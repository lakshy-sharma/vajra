// internal/findings/writer.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db/queries"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// Metrics tracks FindingWriter activity for health reporting.
// All fields are updated atomically — safe to read from any goroutine.
type Metrics struct {
	Written  atomic.Int64 // total successful DB writes
	Deduped  atomic.Int64 // suppressed within dedup window
	Errors   atomic.Int64 // DB write failures
	Evidence atomic.Int64 // evidence snapshots captured
	EvidFail atomic.Int64 // evidence captures that failed
}

// FindingWriter is the single insertion point for all detection output.
// Every watcher and scanner produces a Finding — none write to the DB
// directly. This centralises dedup, schema routing, and evidence capture.
type FindingWriter struct {
	logger  *zerolog.Logger
	detQ    *queries.DetectionQueries
	artQ    *queries.ArtifactQueries
	netQ    *queries.DetectionNetworkQueries
	secQ    *queries.SecretQueries
	extQ    *queries.ExtensionQueries
	evidQ   *queries.EvidenceQueries
	dedup   *utilities.DedupTracker
	sysInfo utilities.SystemInfo
	Metrics Metrics
}

func NewFindingWriter(
	logger *zerolog.Logger,
	detQ *queries.DetectionQueries,
	artQ *queries.ArtifactQueries,
	netQ *queries.DetectionNetworkQueries,
	secQ *queries.SecretQueries,
	extQ *queries.ExtensionQueries,
	evidQ *queries.EvidenceQueries,
	dedupWindow time.Duration,
	sysInfo utilities.SystemInfo,
) *FindingWriter {
	return &FindingWriter{
		logger:  logger,
		detQ:    detQ,
		artQ:    artQ,
		netQ:    netQ,
		secQ:    secQ,
		extQ:    extQ,
		evidQ:   evidQ,
		dedup:   utilities.NewDedupTracker(dedupWindow),
		sysInfo: sysInfo,
	}
}

// Write deduplicates, persists, and captures evidence for a finding.
// Returns the detection ID on success, 0 if deduped or on error.
func (fw *FindingWriter) Write(ctx context.Context, f Finding) (int64, error) {
	key := utilities.BuildKey(f.RuleID, f.TargetPath, f.Severity)
	shouldInsert, entry := fw.dedup.CheckAndRecord(key)

	if !shouldInsert {
		fw.Metrics.Deduped.Add(1)
		if entry.RecordID != 0 {
			if err := fw.detQ.IncrementDedupCount(entry.RecordID); err != nil {
				fw.logger.Error().Err(err).Int64("id", entry.RecordID).Msg("finding writer: dedup increment failed")
			}
		}
		return 0, nil
	}

	det := &models.Detection{
		MachineID:     fw.sysInfo.MachineID,
		DetectionTime: f.DetectedAt,
		Source:        string(f.Source),
		Severity:      f.Severity,
		Status:        f.Status,
		PID:           f.PID,
		PPID:          f.PPID,
		UID:           f.UID,
		GID:           f.GID,
		EUID:          f.EUID,
		EGID:          f.EGID,
		ProcessName:   f.ProcessName,
		ExePath:       f.ExePath,
		CmdLine:       f.CmdLine,
		CWD:           f.CWD,
		TargetPath:    f.TargetPath,
		RuleID:        f.RuleID,
		Notes:         f.Notes,
		DedupCount:    1,
	}

	if err := fw.detQ.Insert(det); err != nil {
		fw.Metrics.Errors.Add(1)
		return 0, fmt.Errorf("finding writer: insert detection: %w", err)
	}
	fw.dedup.RecordInsert(key, det.ID)
	fw.Metrics.Written.Add(1)

	// Write extension tables — failures are logged but non-fatal.
	// A partial write is better than losing the detection entirely.
	fw.writeArtifacts(det.ID, f)
	fw.writeNetwork(det.ID, f)
	fw.writeSecret(det.ID, f)
	fw.writeExtensions(det.ID, f)

	// Evidence capture runs synchronously while process state is fresh.
	// Only HIGH and CRITICAL warrant the /proc read overhead.
	if f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical {
		fw.captureEvidence(det.ID, f.PID)
	}

	return det.ID, nil
}

func (fw *FindingWriter) writeArtifacts(detectionID int64, f Finding) {
	if f.FileHash == "" && len(f.YaraMatches) == 0 {
		return
	}
	if err := fw.artQ.Insert(&models.DetectionArtifact{
		DetectionID: detectionID,
		FileHash:    f.FileHash,
		FileSize:    f.FileSize,
		YaraMatches: f.YaraMatches,
	}); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: artifact insert failed")
		fw.Metrics.Errors.Add(1)
	}
}

func (fw *FindingWriter) writeNetwork(detectionID int64, f Finding) {
	if f.RemoteAddr == "" {
		return
	}
	if err := fw.netQ.Insert(&models.DetectionNetwork{
		DetectionID: detectionID,
		RemoteAddr:  f.RemoteAddr,
		RemotePort:  f.RemotePort,
		Protocol:    f.Protocol,
		SocketInode: f.SocketInode,
	}); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: network insert failed")
		fw.Metrics.Errors.Add(1)
	}
}

func (fw *FindingWriter) writeSecret(detectionID int64, f Finding) {
	if f.SecretHash == "" {
		return
	}
	if err := fw.secQ.Insert(&models.DetectionSecret{
		DetectionID:  detectionID,
		RuleID:       f.SecretRuleID,
		SecretHash:   f.SecretHash,
		Fingerprint:  f.SecretFingerprint,
		StartLine:    f.SecretStartLine,
		EndLine:      f.SecretEndLine,
		MatchContext: f.SecretContext,
	}); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: secret insert failed")
		fw.Metrics.Errors.Add(1)
	}
}

func (fw *FindingWriter) writeExtensions(detectionID int64, f Finding) {
	if len(f.Extensions) == 0 {
		return
	}
	if err := fw.extQ.InsertAll(detectionID, f.Extensions); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: extensions insert failed")
		fw.Metrics.Errors.Add(1)
	}
}

// captureEvidence reads live process state from /proc immediately.
// Called synchronously — process may exit within milliseconds of detection.
func (fw *FindingWriter) captureEvidence(detectionID int64, pid uint32) {
	if pid == 0 {
		return
	}

	snapshot := &models.EvidenceSnapshot{
		DetectionID: detectionID,
		CapturedAt:  time.Now().Unix(),
	}

	snapshot.OpenFDs = readFDs(pid)
	snapshot.Maps = readFile(fmt.Sprintf("/proc/%d/maps", pid))
	snapshot.Environ = readEnviron(pid)
	snapshot.Status = readFile(fmt.Sprintf("/proc/%d/status", pid))

	if err := fw.evidQ.Insert(snapshot); err != nil {
		fw.logger.Error().Err(err).Uint32("pid", pid).Int64("detection_id", detectionID).Msg("finding writer: evidence insert failed")
		fw.Metrics.EvidFail.Add(1)
		return
	}
	fw.Metrics.Evidence.Add(1)
}

// LogMetrics writes current counters to the audit log.
// Called by the health ticker every 15 minutes.
func (fw *FindingWriter) LogMetrics(logger *zerolog.Logger) {
	logger.Info().
		Int64("written", fw.Metrics.Written.Load()).
		Int64("deduped", fw.Metrics.Deduped.Load()).
		Int64("errors", fw.Metrics.Errors.Load()).
		Int64("evidence_captured", fw.Metrics.Evidence.Load()).
		Int64("evidence_failed", fw.Metrics.EvidFail.Load()).
		Msg("finding writer: metrics")
}

// ── /proc readers ─────────────────────────────────────────────

// readFDs returns a JSON object mapping fd number to symlink target.
// Captures open files, sockets, pipes at the moment of detection.
func readFDs(pid uint32) string {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return "{}"
	}
	fds := make(map[string]string, len(entries))
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		fds[e.Name()] = target
	}
	b, _ := json.Marshal(fds)
	return string(b)
}

// readEnviron returns /proc/PID/environ as a JSON key/value object.
func readEnviron(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return "{}"
	}
	env := make(map[string]string)
	for _, entry := range splitNull(data) {
		if len(entry) == 0 {
			continue
		}
		idx := indexOf(entry, '=')
		if idx < 0 {
			continue
		}
		env[entry[:idx]] = entry[idx+1:]
	}
	b, _ := json.Marshal(env)
	return string(b)
}

// readFile reads a /proc file and returns its content as a string.
// Returns empty string if the process has already exited.
func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// splitNull splits null-delimited bytes without allocating a regex.
func splitNull(data []byte) []string {
	var result []string
	start := 0
	for i, b := range data {
		if b == 0 {
			result = append(result, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		result = append(result, string(data[start:]))
	}
	return result
}

// indexOf finds the first occurrence of b in s.
func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
