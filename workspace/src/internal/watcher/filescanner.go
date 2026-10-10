// internal/watcher/filescanner.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package watcher

import (
	"context"
	"os"
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
	logger   *zerolog.Logger
	pipeline *analyzer.Pipeline
	writer   *findings.FindingWriter
	filter   *utilities.ExclusionFilter
	tracker  *utilities.RecentScanTracker
	sysInfo  utilities.SystemInfo
}

func NewFileScanner(
	logger *zerolog.Logger,
	pipeline *analyzer.Pipeline,
	writer *findings.FindingWriter,
	filter *utilities.ExclusionFilter,
	sysInfo utilities.SystemInfo,
) *FileScanner {
	return &FileScanner{
		logger:   logger,
		pipeline: pipeline,
		writer:   writer,
		filter:   filter,
		tracker:  utilities.NewRecentScanTracker(5 * time.Minute),
		sysInfo:  sysInfo,
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

	eligible, reason := isEligibleFile(filePath, comm)
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

	fileSize := int64(0)
	if info, err := os.Stat(filePath); err == nil {
		fileSize = info.Size()
	}

	ruleID := utilities.RuleFromMatch(result.Notes, result.YaraMatches)
	f := findings.Finding{
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

	if _, err := fs.writer.Write(ctx, f); err != nil {
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

// isEligibleFile returns true if any one of three conditions passes.
// Size bounds always apply regardless of condition.
func isEligibleFile(filePath string, triggerComm string) (bool, string) {
	info, err := os.Stat(filePath)
	if err != nil {
		return false, "stat_failed"
	}
	if info.IsDir() {
		return false, "is_directory"
	}
	if info.Size() < 10 {
		return false, "too_small"
	}
	if info.Size() > 100*1024*1024 {
		return false, "too_large"
	}
	if info.Mode()&0o111 != 0 {
		return true, ""
	}
	if hasExecutableMagic(filePath) {
		return true, ""
	}
	if triggerComm != "" && utilities.KnownInterpreters[triggerComm] {
		return true, ""
	}
	return false, "not_executable"
}

// hasExecutableMagic checks the first 4 bytes for known executable formats.
// ELF: 7f 45 4c 46 — Shebang: 23 21 — MZ/PE: 4d 5a — Mach-O: ca fe ba be
func hasExecutableMagic(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	magic := make([]byte, 4)
	n, err := f.Read(magic)
	if err != nil || n < 2 {
		return false
	}
	if n >= 4 && magic[0] == 0x7f && magic[1] == 0x45 && magic[2] == 0x4c && magic[3] == 0x46 {
		return true
	}
	if magic[0] == '#' && magic[1] == '!' {
		return true
	}
	if magic[0] == 0x4d && magic[1] == 0x5a {
		return true
	}
	if n >= 4 && magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe {
		return true
	}
	return false
}
