// internal/findings/writer.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package findings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db/queries"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// metricsCounters tracks FindingWriter activity for health reporting.
// Unexported so callers cannot mutate counters directly — use Snapshot().
// All fields are updated atomically — safe to read from any goroutine.
type metricsCounters struct {
	written  atomic.Int64
	deduped  atomic.Int64
	errors   atomic.Int64
	evidence atomic.Int64
	evidFail atomic.Int64
}

// MetricsSnapshot is a point-in-time copy of FindingWriter counters.
// Returned by Snapshot() for health reporting and tests.
type MetricsSnapshot struct {
	Written  int64
	Deduped  int64
	Errors   int64
	Evidence int64
	EvidFail int64
}

// FindingWriter is the single insertion point for all detection output.
// Every watcher and scanner produces a Finding — none write to the DB
// directly. Centralises dedup, schema routing, and evidence capture.
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
	metrics metricsCounters
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

// Snapshot returns a point-in-time copy of the writer's activity counters.
func (fw *FindingWriter) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Written:  fw.metrics.written.Load(),
		Deduped:  fw.metrics.deduped.Load(),
		Errors:   fw.metrics.errors.Load(),
		Evidence: fw.metrics.evidence.Load(),
		EvidFail: fw.metrics.evidFail.Load(),
	}
}

// Write deduplicates, persists, and captures evidence for a finding.
// Returns the detection ID on success, 0 if deduped or on error.
//
// TODO(F5): wrap the detection + sub-table inserts in a single BeginTx
// once the query struct interfaces are finalised. Currently a crash between
// sub-table writes leaves partial rows — the detection row exists but its
// artifact or network detail may not.
func (fw *FindingWriter) Write(ctx context.Context, f Finding) (int64, error) {
	key := utilities.BuildKey(f.RuleID, f.TargetPath, f.Severity)
	shouldInsert, entry := fw.dedup.CheckAndRecord(key)

	now := time.Now().Unix()

	if !shouldInsert {
		fw.metrics.deduped.Add(1)
		if entry.RecordID != 0 {
			if err := fw.detQ.IncrementDedupCount(ctx, entry.RecordID, now); err != nil {
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

	if err := fw.detQ.Insert(ctx, det, now); err != nil {
		fw.metrics.errors.Add(1)
		return 0, fmt.Errorf("finding writer: insert detection: %w", err)
	}
	fw.dedup.RecordInsert(key, det.ID)
	fw.metrics.written.Add(1)

	// Sub-table writes are non-fatal — a partial write beats losing the
	// detection entirely. Errors are logged and counted.
	fw.writeArtifacts(ctx, det.ID, f)
	fw.writeNetwork(ctx, det.ID, f)
	fw.writeSecret(ctx, det.ID, f)
	fw.writeExtensions(ctx, det.ID, f)

	// Evidence capture runs synchronously while process state is fresh.
	// Only HIGH and CRITICAL warrant the /proc read overhead.
	if f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical {
		fw.captureEvidence(ctx, det.ID, f.PID, now)
	}

	return det.ID, nil
}

func (fw *FindingWriter) writeArtifacts(ctx context.Context, detectionID int64, f Finding) {
	if f.FileHash == "" && len(f.YaraMatches) == 0 {
		return
	}
	if err := fw.artQ.Insert(ctx, &models.DetectionArtifact{
		DetectionID: detectionID,
		FileHash:    f.FileHash,
		FileSize:    f.FileSize,
		YaraMatches: f.YaraMatches,
	}); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: artifact insert failed")
		fw.metrics.errors.Add(1)
	}
}

func (fw *FindingWriter) writeNetwork(ctx context.Context, detectionID int64, f Finding) {
	if f.RemoteAddr == "" {
		return
	}
	if err := fw.netQ.Insert(ctx, &models.DetectionNetwork{
		DetectionID: detectionID,
		RemoteAddr:  f.RemoteAddr,
		RemotePort:  f.RemotePort,
		Protocol:    f.Protocol,
		SocketInode: f.SocketInode,
		OldFd:       f.OldFd,
		NewFd:       f.NewFd,
	}); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: network insert failed")
		fw.metrics.errors.Add(1)
	}
}

func (fw *FindingWriter) writeSecret(ctx context.Context, detectionID int64, f Finding) {
	if f.SecretHash == "" {
		return
	}
	if err := fw.secQ.Insert(ctx, &models.DetectionSecret{
		DetectionID:  detectionID,
		RuleID:       f.SecretRuleID,
		SecretHash:   f.SecretHash,
		Fingerprint:  f.SecretFingerprint,
		StartLine:    f.SecretStartLine,
		EndLine:      f.SecretEndLine,
		MatchContext: f.SecretContext,
	}); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: secret insert failed")
		fw.metrics.errors.Add(1)
	}
}

func (fw *FindingWriter) writeExtensions(ctx context.Context, detectionID int64, f Finding) {
	if len(f.Extensions) == 0 {
		return
	}
	if err := fw.extQ.InsertAll(ctx, detectionID, f.Extensions); err != nil {
		fw.logger.Error().Err(err).Int64("detection_id", detectionID).Msg("finding writer: extensions insert failed")
		fw.metrics.errors.Add(1)
	}
}

// captureEvidence reads live process state from /proc at detection time.
// Called synchronously — the process may exit within milliseconds.
func (fw *FindingWriter) captureEvidence(ctx context.Context, detectionID int64, pid uint32, now int64) {
	if pid == 0 {
		return
	}

	snapshot := &models.EvidenceSnapshot{
		DetectionID: detectionID,
		CapturedAt:  now,
		OpenFDs:     readFDs(pid),
		Maps:        readMaps(pid),
		Environ:     readEnviron(pid),
		Status:      readProcText(fmt.Sprintf("/proc/%d/status", pid)),
	}

	if err := fw.evidQ.Insert(ctx, snapshot); err != nil {
		fw.logger.Error().Err(err).Uint32("pid", pid).Int64("detection_id", detectionID).Msg("finding writer: evidence insert failed")
		fw.metrics.evidFail.Add(1)
		return
	}
	fw.metrics.evidence.Add(1)
}

// LogMetrics writes current counters to the structured log.
// Called by the health ticker every 15 minutes.
func (fw *FindingWriter) LogMetrics(logger *zerolog.Logger) {
	s := fw.Snapshot()
	logger.Info().
		Int64("written", s.Written).
		Int64("deduped", s.Deduped).
		Int64("errors", s.Errors).
		Int64("evidence_captured", s.Evidence).
		Int64("evidence_failed", s.EvidFail).
		Msg("finding writer: metrics")
}

// ── /proc readers ─────────────────────────────────────────────────────────────

// readFDs returns a JSON object mapping fd number → symlink target.
// Captures open files, sockets, and pipes at the moment of detection.
func readFDs(pid uint32) json.RawMessage {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return json.RawMessage("{}")
	}
	fds := make(map[string]string, len(entries))
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		fds[e.Name()] = target
	}
	b, err := json.Marshal(fds)
	if err != nil {
		// map[string]string cannot produce a Marshal error in practice, but
		// the rule is to never drop errors silently.
		return json.RawMessage("{}")
	}
	return b
}

// readEnviron returns /proc/PID/environ as a JSON key/value object.
func readEnviron(pid uint32) json.RawMessage {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return json.RawMessage("{}")
	}
	env := make(map[string]string)
	for _, entry := range bytes.Split(data, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		s := string(entry)
		idx := strings.IndexByte(s, '=')
		if idx < 0 {
			continue
		}
		env[s[:idx]] = s[idx+1:]
	}
	b, err := json.Marshal(env)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// readMaps returns /proc/PID/maps encoded as a JSON string.
// The maps file is plain text, not structured data; we preserve the raw
// content rather than parsing it so forensic completeness is not lost.
func readMaps(pid uint32) json.RawMessage {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return json.RawMessage(`""`)
	}
	b, err := json.Marshal(string(data))
	if err != nil {
		return json.RawMessage(`""`)
	}
	return b
}

// readProcText reads a /proc file as a plain string.
// Returns empty string if the process has already exited.
func readProcText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
