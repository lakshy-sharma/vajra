// internal/detect/procwalk.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package detect

import (
	"bytes"
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
//
// This function is synchronous — it blocks until the walk completes or ctx
// is cancelled. service.go runs it in a goroutine.
func RunProcWalk(
	ctx context.Context,
	pipeline *analyzer.Pipeline,
	writer *findings.FindingWriter,
	filter *utilities.ProcessFilter,
	tracker *utilities.RecentScanTracker, // may be nil
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

// scanPID resolves, filters, hashes and pipeline-scans one process.
// Returns (hit, skipped, err).
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
		// Process exited between listPIDs and now — normal, not an error.
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
		// Binary may have been replaced between readlink and hash — skip quietly.
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

	// Always mark scanned — even CLEAN results should not be re-evaluated
	// by ProcessScanner when the same binary execves later in the session.
	if tracker != nil {
		tracker.MarkScanned(exePath, fileHash)
	}

	if result.Skip || result.Severity == models.SeverityClean {
		return false, false, nil
	}

	ruleID := utilities.RuleFromMatch(result.Notes, result.YaraMatches)

	f := findings.Finding{
		Source:      findings.SourceProcessScanner,
		Severity:    result.Severity,
		Status:      models.StatusNew,
		MachineID:   sysInfo.MachineID,
		DetectedAt:  time.Now().Unix(),
		PID:         pid,
		PPID:        ppidForPID(pid),
		UID:         uidForPID(pid),
		GID:         gidForPID(pid),
		ProcessName: comm,
		ExePath:     exePath,
		CmdLine:     cmdlineForPID(pid),
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

	// id == 0 means deduped by FindingWriter — not a new detection.
	return false, false, nil
}

// ── /proc helpers ─────────────────────────────────────────────

// listPIDs returns all numeric PID directories under /proc.
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

// resolveExeForPID reads /proc/PID/exe via the symlink in /proc.
// We stat the symlink itself (Lstat) to confirm the process still exists,
// then Readlink to get the target. Strips the " (deleted)" suffix the kernel
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

// commForPID reads /proc/PID/comm — process name, kernel-truncated to 15 chars.
func commForPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(data), "\n")
}

// cmdlineForPID reads null-delimited /proc/PID/cmdline into a space-separated string.
func cmdlineForPID(pid uint32) string {
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

// cwdForPID resolves /proc/PID/cwd.
func cwdForPID(pid uint32) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}

// ppidForPID reads PPid from /proc/PID/status.
func ppidForPID(pid uint32) uint32 {
	return uint32(readStatusUint(pid, "PPid:"))
}

// uidForPID reads the real UID from /proc/PID/status.
func uidForPID(pid uint32) uint32 {
	return uint32(readStatusUint(pid, "Uid:"))
}

// gidForPID reads the real GID from /proc/PID/status.
func gidForPID(pid uint32) uint32 {
	return uint32(readStatusUint(pid, "Gid:"))
}

// readStatusUint scans /proc/PID/status for a labelled field and returns
// the first numeric token after the label. Returns 0 on any error.
func readStatusUint(pid uint32, field string) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	needle := []byte(field)
	lines := bytes.Split(data, []byte{'\n'})
	for _, line := range lines {
		if !bytes.HasPrefix(line, needle) {
			continue
		}
		// Format: "PPid:\t1234" or "Uid:\t1000\t1000\t1000\t1000"
		fields := bytes.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		n, err := strconv.ParseUint(string(fields[1]), 10, 64)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}
