// internal/detect/procwalk.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/analyzer"
	"vajra/internal/findings"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// ProcWalkSummary holds counts reported back to callers.
type ProcWalkSummary struct {
	PIDs       int
	Scanned    int
	Skipped    int
	Detections int
	Elapsed    time.Duration
}

// RunProcWalk walks /proc once, submitting each live executable through the
// content pipeline. Designed to be called:
//   - At agent startup (service.go) to catch pre-existing processes.
//   - As part of a full CLI scan (fullscan.go / cmd/scan.go).
//
// The tracker is shared with ProcessScanner so binaries already seen by
// the eBPF watcher since agent start are not re-scanned. Pass nil to skip
// tracker checks entirely (e.g. standalone CLI invocation).
func RunProcWalk(
	ctx context.Context,
	pipeline *analyzer.Pipeline,
	writer *findings.FindingWriter,
	filter *utilities.ProcessFilter,
	tracker *utilities.RecentScanTracker,
	sysInfo utilities.SystemInfo,
	logger *zerolog.Logger,
) (ProcWalkSummary, error) {
	start := time.Now()
	logger.Info().Msg("procwalk: started")

	pids, err := listPIDs()
	if err != nil {
		return ProcWalkSummary{}, fmt.Errorf("procwalk: list pids: %w", err)
	}

	var summary ProcWalkSummary
	summary.PIDs = len(pids)

	for _, pid := range pids {
		if ctx.Err() != nil {
			break
		}
		hit, skipped, err := scanPID(ctx, pid, pipeline, writer, filter, tracker, sysInfo, logger)
		if err != nil {
			logger.Debug().Err(err).Uint32("pid", pid).Msg("procwalk: pid scan error")
			summary.Skipped++
			continue
		}
		if skipped {
			summary.Skipped++
			continue
		}
		summary.Scanned++
		if hit {
			summary.Detections++
		}
	}

	summary.Elapsed = time.Since(start)
	logger.Info().
		Int("pids_found", summary.PIDs).
		Int("scanned", summary.Scanned).
		Int("skipped", summary.Skipped).
		Int("detections", summary.Detections).
		Str("elapsed", summary.Elapsed.Round(time.Millisecond).String()).
		Msg("procwalk: complete")

	return summary, nil
}

func scanPID(
	ctx context.Context,
	pid uint32,
	pipeline *analyzer.Pipeline,
	writer *findings.FindingWriter,
	filter *utilities.ProcessFilter,
	tracker *utilities.RecentScanTracker,
	sysInfo utilities.SystemInfo,
	logger *zerolog.Logger,
) (hit bool, skipped bool, err error) {
	exePath, err := resolveExeForPID(pid)
	if err != nil || exePath == "" {
		return false, true, nil
	}

	comm := commForPID(pid)

	if filter != nil && filter.IsTrusted(comm) {
		return false, true, nil
	}

	if tracker != nil && tracker.WasRecentlyScanned(exePath, "") {
		return false, true, nil
	}

	fileHash, err := utilities.FullSHA256(exePath)
	if err != nil {
		return false, true, nil
	}

	if tracker != nil && tracker.WasRecentlyScanned(exePath, fileHash) {
		return false, true, nil
	}

	pCtx := analyzer.CtxWithPID(ctx, pid)
	result, err := pipeline.Run(pCtx, exePath, fileHash)
	if err != nil {
		return false, false, fmt.Errorf("pipeline: %w", err)
	}

	if tracker != nil {
		tracker.MarkScanned(exePath, fileHash)
	}

	if result.Skip || result.Severity == models.SeverityClean {
		return false, false, nil
	}

	// W12: read /proc/PID/status once for all fields — was called separately
	// for PPID, UID, and GID, opening the file three times.
	status := utilities.ReadProcStatus(pid)
	ruleID := utilities.RuleFromMatch(result.Notes, result.YaraMatches)

	f := findings.Finding{
		Source:      findings.SourceProcessScanner,
		Severity:    result.Severity,
		Status:      models.StatusNew,
		DetectedAt:  time.Now().Unix(),
		PID:         pid,
		PPID:        status.PPID,
		UID:         status.UID,
		GID:         status.GID,
		EUID:        status.EUID,
		EGID:        status.EGID,
		ProcessName: comm,
		ExePath:     exePath,
		CmdLine:     utilities.ReadCmdline(pid), // W13: shared implementation
		CWD:         cwdForPID(pid),
		TargetPath:  exePath,
		RuleID:      ruleID,
		Notes:       result.Notes,
		FileHash:    fileHash,
		YaraMatches: result.YaraMatches,
	}

	id, err := writer.Write(ctx, f)
	if err != nil {
		return false, false, fmt.Errorf("write: %w", err)
	}

	if id > 0 {
		logger.Warn().
			Str("exe", exePath).
			Str("comm", comm).
			Uint32("pid", pid).
			Str("severity", string(result.Severity)).
			Str("rule", ruleID).
			Msg("PROCWALK DETECTION")
		return true, false, nil
	}

	return false, false, nil
}

// ── /proc helpers ─────────────────────────────────────────────

func listPIDs() ([]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("listPIDs: readdir /proc: %w", err)
	}
	pids := make([]uint32, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(n))
	}
	return pids, nil
}

// resolveExeForPID reads /proc/PID/exe. Strips " (deleted)" which the kernel
// appends when the on-disk binary has been replaced — the inode is still
// readable through the fd.
func resolveExeForPID(pid uint32) (string, error) {
	link := fmt.Sprintf("/proc/%d/exe", pid)
	if _, err := os.Lstat(link); err != nil {
		return "", err
	}
	target, err := os.Readlink(link)
	if err != nil {
		return "", err
	}
	target = strings.TrimSuffix(target, " (deleted)")
	if !filepath.IsAbs(target) {
		return "", fmt.Errorf("non-absolute exe path %q for pid %d", target, pid)
	}
	return target, nil
}

func commForPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(data), "\n")
}

func cwdForPID(pid uint32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}
