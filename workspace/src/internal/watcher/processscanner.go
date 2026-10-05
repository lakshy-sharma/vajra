// internal/watcher/processscanner.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package watcher

import (
	"bytes"
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
	"vajra/internal/findings"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// ProcessScanner watches eBPF process events, writes every execve to
// the process tree unconditionally, then runs content and runtime
// pipelines on non-trusted processes. Writes through FindingWriter.
type ProcessScanner struct {
	logger          *zerolog.Logger
	contentPipeline *analyzer.Pipeline
	runtimePipeline *analyzer.Pipeline
	writer          *findings.FindingWriter
	treeQ           *queries.ProcessTreeQueries
	filter          *utilities.ProcessFilter
	tracker         *utilities.RecentScanTracker
	sysInfo         utilities.SystemInfo
}

func NewProcessScanner(
	logger *zerolog.Logger,
	contentPipeline *analyzer.Pipeline,
	runtimePipeline *analyzer.Pipeline,
	writer *findings.FindingWriter,
	treeQ *queries.ProcessTreeQueries,
	filter *utilities.ProcessFilter,
	sysInfo utilities.SystemInfo,
) *ProcessScanner {
	return &ProcessScanner{
		logger:          logger,
		contentPipeline: contentPipeline,
		runtimePipeline: runtimePipeline,
		writer:          writer,
		treeQ:           treeQ,
		filter:          filter,
		tracker:         utilities.NewRecentScanTracker(10 * time.Minute),
		sysInfo:         sysInfo,
	}
}

func (ps *ProcessScanner) Name() string { return "process_scanner" }

func (ps *ProcessScanner) Run(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.ProcessEvent) {
	defer wg.Done()
	ps.logger.Info().Msg("process scanner started")
	for {
		select {
		case <-ctx.Done():
			ps.logger.Info().Msg("process scanner stopped")
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			ps.handle(ctx, event)
		}
	}
}

func (ps *ProcessScanner) handle(ctx context.Context, event ebpf.ProcessEvent) {
	comm := ebpf.CStringToGo(event.Comm[:])

	// Process tree write is unconditional — every execve, before any
	// filtering. Holes in the tree break server-side CTE traversal.
	cmdLine := readCmdline(event.PID)
	if cmdLine == "" {
		cmdLine = ebpf.CStringToGo(event.Args[:])
	}

	if err := ps.treeQ.Insert(&models.ProcessTreeEntry{
		MachineID: ps.sysInfo.MachineID,
		PID:       event.PID,
		PPID:      event.PPID,
		Comm:      comm,
		ExePath:   ebpf.CStringToGo(event.Filename[:]),
		CmdLine:   cmdLine,
		EventTime: ps.sysInfo.EBPFTimestampToUnix(event.Timestamp),
	}); err != nil {
		// Non-fatal — analysis continues even if tree write fails.
		ps.logger.Error().Err(err).Uint32("pid", event.PID).Msg("process scanner: tree insert failed")
	}

	exePath := resolveExePath(event.PID, event.Filename[:])
	if exePath == "" {
		return
	}

	if ps.tracker.WasRecentlyScanned(exePath, "") {
		return
	}
	ps.tracker.MarkScanned(exePath, "")

	pCtx := analyzer.CtxWithPID(ctx, event.PID)

	runtimeResult, err := ps.runtimePipeline.RunUncached(pCtx, exePath)
	if err != nil {
		ps.logger.Error().Err(err).Str("exe", exePath).Msg("process scanner: runtime pipeline error")
	}

	contentResult := analyzer.Result{Severity: models.SeverityClean}
	if !ps.filter.IsTrusted(comm) {
		fileHash, err := utilities.FullSHA256(exePath)
		if err != nil {
			ps.logger.Debug().Err(err).Str("exe", exePath).Msg("process scanner: hash failed, skipping content pipeline")
		} else {
			contentResult, err = ps.contentPipeline.Run(pCtx, exePath, fileHash)
			if err != nil {
				ps.logger.Error().Err(err).Str("exe", exePath).Msg("process scanner: content pipeline error")
			}
		}
	}

	merged := analyzer.MergeResults(contentResult, runtimeResult)
	if merged.Skip || merged.Severity == models.SeverityClean {
		return
	}

	cwd := readCWD(event.PID)
	if cwd == "" {
		cwd = ebpf.CStringToGo(event.CWD[:])
	}

	fileHash := ""
	if h, err := utilities.FullSHA256(exePath); err == nil {
		fileHash = h
	}

	ruleID := utilities.RuleFromMatch(merged.Notes, merged.YaraMatches)
	f := findings.Finding{
		Source:      findings.SourceProcessScanner,
		Severity:    merged.Severity,
		Status:      models.StatusNew,
		DetectedAt:  ps.sysInfo.EBPFTimestampToUnix(event.Timestamp),
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
		TargetPath:  exePath,
		RuleID:      ruleID,
		Notes:       merged.Notes,
		FileHash:    fileHash,
		YaraMatches: merged.YaraMatches,
	}

	if _, err := ps.writer.Write(ctx, f); err != nil {
		ps.logger.Error().Err(err).Str("exe", exePath).Msg("process scanner: write failed")
		return
	}

	ps.logger.Warn().
		Str("exe", exePath).
		Str("comm", comm).
		Uint32("pid", event.PID).
		Str("severity", string(merged.Severity)).
		Str("rule", ruleID).
		Msg("PROCESS DETECTION")
}

// resolveExePath reads /proc/PID/exe, falling back to the eBPF filename.
func resolveExePath(pid uint32, filenameBuf []byte) string {
	resolved, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil && resolved != "" {
		if _, err := os.Stat(resolved); err == nil {
			return resolved
		}
		return ""
	}
	name := ebpf.CStringToGo(filenameBuf)
	if name == "" || !filepath.IsAbs(name) {
		return ""
	}
	if _, err := os.Stat(name); err != nil {
		return ""
	}
	return name
}

// readCmdline reads /proc/PID/cmdline. The file is null-delimited —
// bytes.Split is correct here, not string manipulation.
func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	parts := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			result = append(result, string(p))
		}
	}
	return strings.Join(result, " ")
}

// readCWD resolves /proc/PID/cwd to the full working directory.
func readCWD(pid uint32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}
