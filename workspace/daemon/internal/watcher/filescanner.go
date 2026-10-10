// internal/watcher/filescanner.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/analyzer"
	"vajra/internal/ebpf"
	"vajra/internal/findings"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// FileScanner watches eBPF file events and submits eligible files
// through the analyzer pipeline. Writes through FindingWriter.
type FileScanner struct {
	logger       *zerolog.Logger
	pipeline     *analyzer.Pipeline
	writer       *findings.FindingWriter
	filter       *utilities.ExclusionFilter
	tracker      *utilities.RecentScanTracker
	sysInfo      utilities.SystemInfo
	maxFileSize  int64
	interpreters map[string]bool // basenames from AlertPolicy.Interpreters
}

func NewFileScanner(
	logger *zerolog.Logger,
	pipeline *analyzer.Pipeline,
	writer *findings.FindingWriter,
	filter *utilities.ExclusionFilter,
	sysInfo utilities.SystemInfo,
	maxFileSizeBytes int64,
	interpreters []string,
) *FileScanner {
	interpMap := make(map[string]bool, len(interpreters))
	for _, interp := range interpreters {
		interpMap[filepath.Base(interp)] = true
	}
	return &FileScanner{
		logger:       logger,
		pipeline:     pipeline,
		writer:       writer,
		filter:       filter,
		tracker:      utilities.NewRecentScanTracker(5 * time.Minute),
		sysInfo:      sysInfo,
		maxFileSize:  maxFileSizeBytes,
		interpreters: interpMap,
	}
}

func (fs *FileScanner) Name() string { return "file_scanner" }

func (fs *FileScanner) Run(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.FileEvent) {
	defer wg.Done()
	fs.logger.Info().Msg("file scanner started")
	for {
		select {
		case <-ctx.Done():
			fs.logger.Info().Msg("file scanner stopped")
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			fs.handle(ctx, event)
		}
	}
}

func (fs *FileScanner) handle(ctx context.Context, event ebpf.FileEvent) {
	filePath := ebpf.CStringToGo(event.Filename[:])
	if filePath == "" {
		return
	}
	comm := ebpf.CStringToGo(event.Comm[:])

	if !fs.filter.ShouldScan(filePath) {
		return
	}

	// W9: open once, stat the open fd — prevents TOCTOU between stat and magic check.
	f, err := os.Open(filePath)
	if err != nil {
		return
	}

	eligible, reason := isEligibleFile(f, comm, fs.maxFileSize, fs.interpreters)
	f.Close()
	if !eligible {
		fs.logger.Debug().Str("file", filePath).Str("reason", reason).Msg("file scanner: ineligible")
		return
	}

	quickHash, _ := utilities.QuickHash(filePath)
	if fs.tracker.WasRecentlyScanned(filePath, quickHash) {
		return
	}
	fs.tracker.MarkScanned(filePath, quickHash)

	fileHash, err := utilities.FullSHA256(filePath)
	if err != nil {
		fs.logger.Debug().Err(err).Str("file", filePath).Msg("file scanner: hash failed")
		return
	}

	result, err := fs.pipeline.Run(analyzer.CtxWithSHA256(ctx, fileHash), filePath, fileHash)
	if err != nil {
		fs.logger.Error().Err(err).Str("file", filePath).Msg("file scanner: pipeline error")
		return
	}
	if result.Skip || result.Severity == models.SeverityClean {
		return
	}

	var fileSize int64
	if info, err := os.Stat(filePath); err == nil {
		fileSize = info.Size()
	}

	ruleID := utilities.RuleFromMatch(result.Notes, result.YaraMatches)
	finding := findings.Finding{
		Source:      findings.SourceFileScanner,
		Severity:    result.Severity,
		Status:      models.StatusNew,
		DetectedAt:  fs.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: comm,
		TargetPath:  filePath,
		RuleID:      ruleID,
		Notes:       result.Notes,
		FileHash:    fileHash,
		FileSize:    fileSize,
		YaraMatches: result.YaraMatches,
	}

	if _, err := fs.writer.Write(ctx, finding); err != nil {
		fs.logger.Error().Err(err).Str("file", filePath).Msg("file scanner: write failed")
		return
	}

	fs.logger.Warn().
		Str("file", filePath).
		Str("severity", string(result.Severity)).
		Uint32("pid", event.PID).
		Str("comm", comm).
		Str("rule", ruleID).
		Msg("FILE DETECTION")
}

// isEligibleFile checks whether a file warrants scanning.
// W9: takes an already-open *os.File so stat and magic check share one fd.
// W7: maxSize comes from ScanSettings.MaxFileSizeBytes, not a hardcoded constant.
// W8: uses utilities.HasExecutableMagic instead of a local duplicate.
func isEligibleFile(f *os.File, triggerComm string, maxSize int64, interpreters map[string]bool) (bool, string) {
	info, err := f.Stat()
	if err != nil {
		return false, "stat_failed"
	}
	if info.IsDir() {
		return false, "is_directory"
	}
	if info.Size() < 10 {
		return false, "too_small"
	}
	if maxSize > 0 && info.Size() > maxSize {
		return false, "too_large"
	}
	if info.Mode()&0o111 != 0 {
		return true, ""
	}
	if utilities.HasExecutableMagic(f) {
		return true, ""
	}
	// A file opened by a known interpreter is worth scanning even without
	// an executable bit — scripts are loaded, not executed directly.
	if triggerComm != "" && interpreters[triggerComm] {
		return true, ""
	}
	return false, "not_executable"
}
