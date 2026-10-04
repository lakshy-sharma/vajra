// internal/jobs/filescanner.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

import (
	"context"
	"os"
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

type FileScanner struct {
	logger   *zerolog.Logger
	pipeline *analyzer.Pipeline
	queries  *queries.FileQueries
	filter   *scanner.ExclusionFilter
	tracker  *scanner.RecentScanTracker
	dedup    *scanner.DedupTracker
	sysInfo  utilities.SystemInfo
}

func NewFileScanner(
	logger *zerolog.Logger,
	pipeline *analyzer.Pipeline,
	fq *queries.FileQueries,
	filter *scanner.ExclusionFilter,
	dedupWindow time.Duration,
	sysInfo utilities.SystemInfo,
) *FileScanner {
	return &FileScanner{
		logger:   logger,
		pipeline: pipeline,
		queries:  fq,
		filter:   filter,
		tracker:  scanner.NewRecentScanTracker(5 * time.Minute),
		dedup:    scanner.NewDedupTracker(dedupWindow),
		sysInfo:  sysInfo,
	}
}

func (fs *FileScanner) Run(ctx context.Context, wg *sync.WaitGroup, fileCh <-chan ebpf.FileEvent) {
	defer wg.Done()
	fs.logger.Info().Msg("file scanner started")

	for {
		select {
		case <-ctx.Done():
			fs.logger.Info().Msg("file scanner stopped")
			return
		case event, ok := <-fileCh:
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
		fs.logger.Debug().Str("file", filePath).Msg("file scanner: excluded by filter")
		return
	}

	eligible, reason := isEligibleFile(filePath)
	if !eligible {
		fs.logger.Debug().Str("file", filePath).Str("reason", reason).Msg("file scanner: ineligible")
		return
	}

	quickHash, err := scanner.QuickHash(filePath)
	if err != nil {
		quickHash = ""
	}
	if fs.tracker.WasRecentlyScanned(filePath, quickHash) {
		fs.logger.Debug().Str("file", filePath).Msg("file scanner: recently scanned, skipping")
		return
	}
	fs.tracker.MarkScanned(filePath, quickHash)

	fileHash, err := scanner.FullSHA256(filePath)
	if err != nil {
		fs.logger.Debug().Err(err).Str("file", filePath).Msg("file scanner: could not hash file, skipping")
		return
	}

	result, err := fs.pipeline.Run(ctx, filePath, fileHash)
	if err != nil {
		fs.logger.Error().Err(err).Str("file", filePath).Msg("file scanner: pipeline error")
		return
	}

	if result.Skip {
		fs.logger.Debug().Str("file", filePath).Msg("file scanner: clean result from cache, skipping insert")
		return
	}

	fs.persist(result, event, comm, filePath, fileHash)
}

func (fs *FileScanner) persist(
	result analyzer.AnalysisResult,
	event ebpf.FileEvent,
	comm string,
	filePath string,
	fileHash string,
) {
	if result.Severity == models.SeverityClean {
		fs.logger.Debug().Str("file", filePath).Msg("file scanner: clean")
		return
	}

	rule := scanner.RuleFromNotes(result.Notes, result.YaraMatches)
	key := scanner.BuildKey(rule, filePath, result.Severity)
	shouldInsert, entry := fs.dedup.CheckAndRecord(key)

	if !shouldInsert {
		if entry.RecordID != 0 {
			if err := fs.queries.IncrementDedupCount(entry.RecordID); err != nil {
				fs.logger.Error().Err(err).Int64("record_id", entry.RecordID).Msg("file scanner: dedup increment failed")
			}
		}
		fs.logger.Debug().Str("file", filePath).Str("rule", rule).Uint64("count", entry.Count).Msg("file scanner: duplicate detection suppressed")
		return
	}

	fileSize := int64(0)
	if info, err := os.Stat(filePath); err == nil {
		fileSize = info.Size()
	}

	record := &models.FileScanResult{
		MachineID:   fs.sysInfo.MachineID,
		ScanTime:    fs.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		FilePath:    filePath,
		FileSize:    fileSize,
		FileHash:    fileHash,
		YaraMatches: result.YaraMatches,
		Severity:    result.Severity,
		Status:      models.StatusNew,
		EventType:   event.Type,
		TriggerPID:  event.PID,
		TriggerUID:  event.UID,
		TriggerComm: comm,
		DedupCount:  1,
		Notes:       result.Notes,
	}

	if err := fs.queries.Insert(record); err != nil {
		fs.logger.Error().Err(err).Str("file", filePath).Msg("file scanner: DB insert failed")
		return
	}

	fs.dedup.RecordInsert(key, record.ID)

	fs.logger.Warn().
		Str("file", filePath).
		Str("severity", string(result.Severity)).
		Uint32("pid", event.PID).
		Str("comm", comm).
		Int("yara_matches", len(result.YaraMatches)).
		Str("notes", result.Notes).
		Msg("FILE SCAN DETECTION")
}

func isEligibleFile(filePath string) (bool, string) {
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
	if !hasExecutableMagic(filePath) {
		return false, "not_executable_magic"
	}
	return true, ""
}

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
	if n >= 4 && magic[3] == 0x0d {
		return true
	}
	return false
}
