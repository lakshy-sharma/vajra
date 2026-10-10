// internal/watcher/processscanner.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	tracker *utilities.RecentScanTracker,
	sysInfo utilities.SystemInfo,
) *ProcessScanner {
	return &ProcessScanner{
		logger:          logger,
		contentPipeline: contentPipeline,
		runtimePipeline: runtimePipeline,
		writer:          writer,
		treeQ:           treeQ,
		filter:          filter,
		tracker:         tracker,
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
	now := time.Now().Unix()

	// Process tree write is unconditional — every execve, before any filtering.
	// Holes in the tree break server-side CTE ancestry traversal.
	cmdLine := utilities.ReadCmdline(event.PID)
	if cmdLine == "" {
		cmdLine = ebpf.CStringToGo(event.Args[:])
	}

	if err := ps.treeQ.Insert(ctx, &models.ProcessTreeEntry{
		MachineID: ps.sysInfo.MachineID,
		PID:       event.PID,
		PPID:      event.PPID,
		Comm:      comm,
		ExePath:   ebpf.CStringToGo(event.Filename[:]),
		CmdLine:   cmdLine,
		EventTime: ps.sysInfo.EBPFTimestampToUnix(event.Timestamp),
	}, now); err != nil {
		// Non-fatal — analysis continues even if tree write fails.
		ps.logger.Error().Err(err).Uint32("pid", event.PID).Msg("process scanner: tree insert failed")
	}

	exePath := resolveExePath(event.PID, event.Filename[:])
	if exePath == "" {
		return
	}

	// W11: use content hash as tracker key so the tracker correctly identifies
	// the same binary even if it moves or is replaced between scans.
	quickHash, _ := utilities.QuickHash(exePath)
	if ps.tracker.WasRecentlyScanned(exePath, quickHash) {
		return
	}

	pCtx := analyzer.CtxWithPID(ctx, event.PID)

	runtimeResult, err := ps.runtimePipeline.RunUncached(pCtx, exePath)
	if err != nil {
		ps.logger.Error().Err(err).Str("exe", exePath).Msg("process scanner: runtime pipeline error")
	}

	// W10: compute SHA256 once — reused for both the pipeline and the finding.
	var fileHash string
	contentResult := analyzer.Result{Severity: models.SeverityClean}
	if !ps.filter.IsTrusted(comm) {
		fileHash, err = utilities.FullSHA256(exePath)
		if err != nil {
			ps.logger.Debug().Err(err).Str("exe", exePath).Msg("process scanner: hash failed, skipping content pipeline")
		} else {
			contentResult, err = ps.contentPipeline.Run(analyzer.CtxWithSHA256(pCtx, fileHash), exePath, fileHash)
			if err != nil {
				ps.logger.Error().Err(err).Str("exe", exePath).Msg("process scanner: content pipeline error")
			}
		}
	}

	// Mark before return so ProcessScanner and FileScanner don't re-scan
	// the same binary even when the result is CLEAN.
	ps.tracker.MarkScanned(exePath, fileHash)

	merged := analyzer.MergeResults(contentResult, runtimeResult)
	if merged.Skip || merged.Severity == models.SeverityClean {
		return
	}

	cwd := readCWD(event.PID)
	if cwd == "" {
		cwd = ebpf.CStringToGo(event.CWD[:])
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

func readCWD(pid uint32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}
