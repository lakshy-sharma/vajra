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
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/analyzer"
	"vajra/internal/db/queries"
	"vajra/internal/ebpf"
	"vajra/internal/scanner"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

type ProcessScanner struct {
	logger          *zerolog.Logger
	contentPipeline *analyzer.Pipeline
	runtimePipeline *analyzer.Pipeline
	queries         *queries.ProcessQueries
	filter          *scanner.ProcessFilter
	tracker         *scanner.RecentScanTracker
	dedup           *scanner.DedupTracker
	sysInfo         utilities.SystemInfo
}

func NewProcessScanner(
	logger *zerolog.Logger,
	contentPipeline *analyzer.Pipeline,
	runtimePipeline *analyzer.Pipeline,
	pq *queries.ProcessQueries,
	filter *scanner.ProcessFilter,
	dedupWindow time.Duration,
	sysInfo utilities.SystemInfo,
) *ProcessScanner {
	return &ProcessScanner{
		logger:          logger,
		contentPipeline: contentPipeline,
		runtimePipeline: runtimePipeline,
		queries:         pq,
		filter:          filter,
		tracker:         scanner.NewRecentScanTracker(10 * time.Minute),
		dedup:           scanner.NewDedupTracker(dedupWindow),
		sysInfo:         sysInfo,
	}
}

func (ps *ProcessScanner) Run(ctx context.Context, wg *sync.WaitGroup, procCh <-chan ebpf.ProcessEvent) {
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

func (ps *ProcessScanner) handle(ctx context.Context, event ebpf.ProcessEvent) {
	comm := ebpf.CStringToGo(event.Comm[:])

	// ── Stage 1: resolve exe path ─────────────────────────────
	exePath := ps.resolveExePath(event.PID, event.Filename[:])
	if exePath == "" {
		ps.logger.Debug().Uint32("pid", event.PID).Str("comm", comm).Msg("process scanner: could not resolve exe path, skipping")
		return
	}

	// ── Stage 2: recent scan dedup ────────────────────────────
	if ps.tracker.WasRecentlyScanned(exePath, "") {
		ps.logger.Debug().Str("exe", exePath).Msg("process scanner: recently scanned, skipping")
		return
	}
	ps.tracker.MarkScanned(exePath, "")

	// ── Stage 3: attach PID to context ────────────────────────
	pCtx := analyzer.CtxWithPID(ctx, event.PID)

	// ── Stage 4: runtime pipeline ─────────────────────────────
	runtimeResult, err := ps.runtimePipeline.RunUncached(pCtx, exePath)
	if err != nil {
		ps.logger.Error().Err(err).Str("exe", exePath).Msg("process scanner: runtime pipeline error")
	}

	// ── Stage 5: content pipeline ─────────────────────────────
	contentResult := analyzer.AnalysisResult{Severity: models.SeverityClean}
	if !ps.filter.IsTrusted(comm) {
		fileHash, err := scanner.FullSHA256(exePath)
		if err != nil {
			ps.logger.Debug().Err(err).Str("exe", exePath).Msg("process scanner: could not hash exe, skipping content pipeline")
		} else {
			contentResult, err = ps.contentPipeline.Run(pCtx, exePath, fileHash)
			if err != nil {
				ps.logger.Error().Err(err).Str("exe", exePath).Msg("process scanner: content pipeline error")
			}
		}
	} else {
		ps.logger.Debug().Str("comm", comm).Uint32("pid", event.PID).Msg("process scanner: trusted process, skipping content pipeline")
	}

	// ── Stage 6: merge ────────────────────────────────────────
	merged := analyzer.MergeResults(contentResult, runtimeResult)
	if merged.Skip {
		ps.logger.Debug().Str("exe", exePath).Msg("process scanner: clean cached result, skipping insert")
		return
	}

	// ── Stage 7: persist ──────────────────────────────────────
	ps.persist(merged, event, comm, exePath)
}

func (ps *ProcessScanner) persist(
	merged analyzer.AnalysisResult,
	event ebpf.ProcessEvent,
	comm string,
	exePath string,
) {
	if merged.Severity == models.SeverityClean {
		ps.logger.Debug().Str("exe", exePath).Str("comm", comm).Uint32("pid", event.PID).Msg("process scanner: clean")
		return
	}

	rule := scanner.RuleFromNotes(merged.Notes, merged.YaraMatches)
	key := scanner.BuildKey(rule, exePath, merged.Severity)
	shouldInsert, entry := ps.dedup.CheckAndRecord(key)

	if !shouldInsert {
		if entry.RecordID != 0 {
			if err := ps.queries.IncrementDedupCount(entry.RecordID); err != nil {
				ps.logger.Error().Err(err).Int64("record_id", entry.RecordID).Msg("process scanner: dedup increment failed")
			}
		}
		ps.logger.Debug().Str("exe", exePath).Str("rule", rule).Uint64("count", entry.Count).Msg("process scanner: duplicate detection suppressed")
		return
	}

	// Full cmdline from /proc — eBPF only captures argv[1].
	cmdLine := readCmdline(event.PID)
	if cmdLine == "" {
		cmdLine = ebpf.CStringToGo(event.Args[:])
	}

	// CWD from /proc — eBPF only gives last path component.
	cwd := readCWD(event.PID)
	if cwd == "" {
		cwd = ebpf.CStringToGo(event.CWD[:])
	}

	fileHash := ""
	if h, err := scanner.FullSHA256(exePath); err == nil {
		fileHash = h
	}

	record := &models.ProcessScanResult{
		ScanTime:    ps.sysInfo.EBPFTimestampToUnix(event.Timestamp),
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
		FileHash:    fileHash,
		YaraMatches: merged.YaraMatches,
		Severity:    merged.Severity,
		Status:      models.StatusNew,
		EventType:   event.Type,
		DedupCount:  1,
		Notes:       merged.Notes,
		MachineID:   ps.sysInfo.MachineID,
	}

	if err := ps.queries.Insert(record); err != nil {
		ps.logger.Error().Err(err).Str("exe", exePath).Uint32("pid", event.PID).Msg("process scanner: DB insert failed")
		return
	}

	ps.dedup.RecordInsert(key, record.ID)

	ps.logger.Warn().
		Str("exe", exePath).
		Str("comm", comm).
		Uint32("pid", event.PID).
		Str("cmdline", cmdLine).
		Str("severity", string(merged.Severity)).
		Int("yara_matches", len(merged.YaraMatches)).
		Str("notes", merged.Notes).
		Msg("PROCESS SCAN DETECTION")
}

func (ps *ProcessScanner) resolveExePath(pid uint32, filenameBuf []byte) string {
	procLink := fmt.Sprintf("/proc/%d/exe", pid)
	resolved, err := os.Readlink(procLink)
	if err == nil && resolved != "" {
		if _, statErr := os.Stat(resolved); statErr == nil {
			return resolved
		}
		ps.logger.Debug().Str("exe", resolved).Uint32("pid", pid).Msg("process scanner: exe path inaccessible, skipping")
		return ""
	}
	name := ebpf.CStringToGo(filenameBuf)
	if name == "" || !filepath.IsAbs(name) {
		return ""
	}
	if _, statErr := os.Stat(name); statErr != nil {
		return ""
	}
	return name
}

// readCmdline reads the full command line from /proc/PID/cmdline.
// The file is null-delimited; we replace nulls with spaces.
// Returns empty string if the process has already exited.
func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	// Trim trailing null then replace all nulls with spaces.
	data = []byte(strings.TrimRight(string(data), "\x00"))
	return strings.ReplaceAll(string(data), "\x00", " ")
}

// readCWD resolves /proc/PID/cwd to the full working directory path.
// Returns empty string if the process has already exited.
func readCWD(pid uint32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}
