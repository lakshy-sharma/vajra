// internal/jobs/processscanner.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"vajra/internal/db/queries"
	"vajra/internal/ebpf"
	"vajra/internal/scanner"
	"vajra/shared/models"
)

// ProcessScanner consumes ProcessEvents from the eBPF dispatcher,
// scans the executed binary via the YARA pool, and persists
// results via ProcessQueries.
//
// Pipeline per event:
//
//	ProcessEvent
//	  → ProcessFilter.IsTrusted()      — skip known-safe processes
//	  → RecentScanTracker              — TTL dedup by exe path
//	  → resolve exe path               — /proc/PID/exe symlink
//	  → scanner.Pool.Enqueue()         — blocking submit to YARA
//	  → result → ClassifyYARASeverity
//	  → ProcessQueries.Insert()
//
// Note: we scan the exe path, not a filename from the event.
// The event Filename is what was passed to execve — the kernel
// may have resolved it differently. /proc/PID/exe is always
// the canonical resolved path of the running binary.
type ProcessScanner struct {
	logger  *zerolog.Logger
	pool    *scanner.Pool
	queries *queries.ProcessQueries
	filter  *scanner.ProcessFilter
	tracker *scanner.RecentScanTracker
}

// NewProcessScanner constructs a ProcessScanner.
func NewProcessScanner(
	logger *zerolog.Logger,
	pool *scanner.Pool,
	pq *queries.ProcessQueries,
	filter *scanner.ProcessFilter,
) *ProcessScanner {
	return &ProcessScanner{
		logger:  logger,
		pool:    pool,
		queries: pq,
		filter:  filter,
		// 10 minute TTL for processes — a binary executing again
		// within 10 minutes is almost certainly the same bytes.
		tracker: scanner.NewRecentScanTracker(10 * time.Minute),
	}
}

// Run consumes from procCh until ctx is cancelled.
// Intended to be launched as a goroutine via service.go.
// wg.Done() is called on return.
func (ps *ProcessScanner) Run(
	ctx context.Context,
	wg *sync.WaitGroup,
	procCh <-chan ebpf.ProcessEvent,
) {
	defer wg.Done()

	ps.logger.Info().Msg("process scanner started")

	for {
		select {
		case <-ctx.Done():
			ps.logger.Info().Msg("process scanner stopped")
			return

		case event, ok := <-procCh:
			if !ok {
				return
			}
			ps.handle(ctx, event)
		}
	}
}

// handle processes a single ProcessEvent through the pipeline.
func (ps *ProcessScanner) handle(ctx context.Context, event ebpf.ProcessEvent) {
	comm := ebpf.CStringToGo(event.Comm[:])

	// ── Stage 1: process filter ───────────────────────────────
	// Trusted processes (e.g. package managers, known system
	// daemons) are skipped entirely. This is configured via
	// ExclusionRules.ExcludeProcesses in config.yaml.
	if ps.filter.IsTrusted(comm) {
		ps.logger.Debug().
			Str("comm", comm).
			Uint32("pid", event.PID).
			Msg("process scanner: trusted process skipped")
		return
	}

	// ── Stage 2: resolve canonical exe path ───────────────────
	// We prefer /proc/PID/exe over event.Filename because:
	// 1. execve filename may be relative or unresolved.
	// 2. The binary is guaranteed to still be mapped at this
	//    point since we're on the enter probe.
	// If the proc symlink fails we fall back to event.Filename.
	exePath := ps.resolveExePath(event.PID, event.Filename[:])
	if exePath == "" {
		ps.logger.Debug().
			Uint32("pid", event.PID).
			Str("comm", comm).
			Msg("process scanner: could not resolve exe path, skipping")
		return
	}

	// ── Stage 3: recent scan dedup ────────────────────────────
	// Key on exe path — same binary executing repeatedly should
	// not trigger repeated scans within the TTL window.
	if ps.tracker.WasRecentlyScanned(exePath, "") {
		ps.logger.Debug().
			Str("exe", exePath).
			Msg("process scanner: recently scanned, skipping")
		return
	}
	ps.tracker.MarkScanned(exePath, "")

	// ── Stage 4: submit to YARA pool (blocking) ───────────────
	resultCh := make(chan scanner.ScanResult, 1)

	if !ps.pool.Enqueue(ctx, exePath, resultCh) {
		return
	}

	// ── Stage 5: collect result and persist ───────────────────
	select {
	case <-ctx.Done():
		return
	case result := <-resultCh:
		ps.persist(result, event, comm, exePath)
	}
}

// resolveExePath returns the canonical path of the executed binary.
// Resolution order:
//  1. /proc/PID/exe symlink — always preferred, always the real path
//  2. event.Filename fallback — only if absolute and stat-able
//
// Returns empty string when neither source yields a scannable path.
// All non-error conditions (process already gone, AppImage mounts,
// failed PATH candidates) are logged at debug, not error.
func (ps *ProcessScanner) resolveExePath(pid uint32, filenameBuf []byte) string {
	procLink := fmt.Sprintf("/proc/%d/exe", pid)

	resolved, err := os.Readlink(procLink)
	if err == nil && resolved != "" {
		// Verify we can actually stat it — AppImage FUSE mounts
		// resolve the symlink but are inaccessible to root.
		if _, statErr := os.Stat(resolved); statErr == nil {
			return resolved
		} else {
			ps.logger.Debug().
				Err(statErr).
				Str("exe", resolved).
				Uint32("pid", pid).
				Msg("process scanner: exe path inaccessible (AppImage or user-namespace mount), skipping")
			return ""
		}
	}

	// /proc/PID/exe failed — process likely already exited.
	// Fall back to event.Filename only if it is an absolute
	// path that exists right now. Relative paths and PATH
	// candidates that failed (shell resolution attempts) are
	// dropped here rather than producing spurious scan errors.
	name := ebpf.CStringToGo(filenameBuf)

	if name == "" {
		ps.logger.Debug().
			Uint32("pid", pid).
			Msg("process scanner: no exe path available, skipping")
		return ""
	}

	if !filepath.IsAbs(name) {
		ps.logger.Debug().
			Str("filename", name).
			Uint32("pid", pid).
			Msg("process scanner: relative path from execve, skipping")
		return ""
	}

	if _, statErr := os.Stat(name); statErr != nil {
		// This is a failed PATH candidate from shell resolution —
		// the execve never succeeded so there is nothing to scan.
		ps.logger.Debug().
			Str("filename", name).
			Uint32("pid", pid).
			Msg("process scanner: execve candidate does not exist, skipping")
		return ""
	}

	return name
}

// persist writes a scan result to the database.
func (ps *ProcessScanner) persist(
	result scanner.ScanResult,
	event ebpf.ProcessEvent,
	comm string,
	exePath string,
) {
	if result.Error != nil {
		ps.logger.Debug().
			Err(result.Error).
			Str("exe", exePath).
			Uint32("pid", event.PID).
			Msg("process scanner: scan skipped")
		return
	}

	severity := scanner.ClassifyYARASeverity(result.Matches)

	// Collect full process metadata for the DB record.
	cmdLine := ebpf.CStringToGo(event.Args[:])
	cwd := ebpf.CStringToGo(event.CWD[:])

	// For clean results we still record the process execution
	// so the process table gives a complete audit trail.
	// Only compute the full hash for non-clean results.
	fileHash := ""
	if severity != models.SeverityClean {
		if h, err := scanner.FullSHA256(exePath); err == nil {
			fileHash = h
		}
	}

	record := &models.ProcessScanResult{
		ScanTime:    time.Now().Unix(),
		PID:         event.PID,
		PPID:        event.PPID,
		UID:         event.UID,
		GID:         event.GID,
		EUID:        event.EUID,
		EGID:        event.EGID,
		ProcessName: comm,
		ExePath:     exePath,
		CmdLine:     cmdLine,
		CWD:         cwd,
		YaraMatches: result.Matches,
		Severity:    severity,
		Status:      models.StatusNew,
		EventType:   event.Type,
		Notes:       fileHash,
	}

	if err := ps.queries.Insert(record); err != nil {
		ps.logger.Error().
			Err(err).
			Str("exe", exePath).
			Uint32("pid", event.PID).
			Msg("process scanner: DB insert failed")
		return
	}

	if severity != models.SeverityClean {
		ps.logger.Warn().
			Str("exe", exePath).
			Str("comm", comm).
			Uint32("pid", event.PID).
			Uint32("ppid", event.PPID).
			Uint32("uid", event.UID).
			Str("severity", string(severity)).
			Int("yara_matches", len(result.Matches)).
			Dur("scan_duration", result.Duration).
			Msg("PROCESS SCAN DETECTION")
	} else {
		ps.logger.Debug().
			Str("exe", exePath).
			Str("comm", comm).
			Uint32("pid", event.PID).
			Dur("scan_duration", result.Duration).
			Msg("process scanner: clean")
	}
}
