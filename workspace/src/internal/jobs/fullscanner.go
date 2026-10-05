// internal/jobs/fullscanner.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"
	"vajra/internal/analyzer"
	"vajra/internal/db/queries"
	"vajra/internal/scanner"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// ScanSummary holds the final counts reported to the caller.
type ScanSummary struct {
	FilesScanned int64
	HitsFound    int64
	Candidates   int64 // stat-only pre-walk count, used for progress bar total
	Interrupted  bool
}

// RunFullScan performs a blocking filesystem walk over targetDir,
// submitting each eligible file through the analyzer pipeline.
// Results are written to DB. A progress bar with ETA is rendered to stdout.
func RunFullScan(
	ctx context.Context,
	targetDir string,
	pipeline *analyzer.Pipeline,
	filter *scanner.ExclusionFilter,
	dedup *scanner.DedupTracker,
	fq *queries.FileQueries,
	sysInfo utilities.SystemInfo,
	logger *zerolog.Logger,
) (ScanSummary, error) {
	logger.Info().Str("target", targetDir).Msg("full scan: counting eligible files")

	countBar := progressbar.NewOptions(
		-1,
		progressbar.OptionSetDescription("counting"),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowElapsedTimeOnFinish(),
	)

	countStart := time.Now()
	total, err := countEligible(ctx, targetDir, filter, countBar)
	if err != nil {
		// Only reaches here on context cancellation during count pass.
		// Proceed with total=0 — progress bar renders as indeterminate.
		logger.Info().
			Str("target", targetDir).
			Msg("full scan: count interrupted, proceeding without total estimate")
	}
	_ = countBar.Finish()
	fmt.Println()

	logger.Info().
		Int64("eligible", total).
		Str("target", targetDir).
		Str("count_duration", time.Since(countStart).Round(time.Millisecond).String()).
		Msg("full scan: starting")

	bar := progressbar.NewOptions64(
		total,
		progressbar.OptionSetDescription("scanning"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("files"),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetPredictTime(true),
	)

	// Intentionally not shared with the daemon's RecentScanTracker —
	// a manual scan always re-evaluates files regardless of daemon state.
	tracker := scanner.NewRecentScanTracker(5 * time.Minute)

	var summary ScanSummary
	summary.Candidates = total

	walkErr := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Debug().Err(err).Str("path", path).Msg("full scan: walk error, skipping")
			return nil
		}

		select {
		case <-ctx.Done():
			summary.Interrupted = true
			return fmt.Errorf("full scan: cancelled")
		default:
		}

		if d.IsDir() {
			if !filter.ShouldScan(path) {
				return filepath.SkipDir
			}
			return nil
		}

		if !filter.ShouldScan(path) {
			return nil
		}

		// Full scan has no triggering process — pass empty comm.
		// Eligibility is execute bit OR magic bytes only.
		eligible, _ := isEligibleFile(path, "")
		if !eligible {
			return nil
		}

		_ = bar.Add(1)
		summary.FilesScanned++

		hit, scanErr := scanFile(ctx, path, pipeline, tracker, dedup, fq, sysInfo, logger)
		if scanErr != nil {
			logger.Debug().Err(scanErr).Str("path", path).Msg("full scan: file error")
			return nil
		}
		if hit {
			summary.HitsFound++
		}

		return nil
	})

	_ = bar.Finish()
	fmt.Println()

	if walkErr != nil && !summary.Interrupted {
		return summary, walkErr
	}

	return summary, nil
}

// scanFile runs one file through the full pipeline and persists non-clean results.
func scanFile(
	ctx context.Context,
	filePath string,
	pipeline *analyzer.Pipeline,
	tracker *scanner.RecentScanTracker,
	dedup *scanner.DedupTracker,
	fq *queries.FileQueries,
	sysInfo utilities.SystemInfo,
	logger *zerolog.Logger,
) (bool, error) {
	quickHash, err := scanner.QuickHash(filePath)
	if err != nil {
		quickHash = ""
	}

	if tracker.WasRecentlyScanned(filePath, quickHash) {
		return false, nil
	}
	tracker.MarkScanned(filePath, quickHash)

	fileHash, err := scanner.FullSHA256(filePath)
	if err != nil {
		return false, fmt.Errorf("sha256: %w", err)
	}

	result, err := pipeline.Run(ctx, filePath, fileHash)
	if err != nil {
		return false, fmt.Errorf("pipeline: %w", err)
	}

	if result.Skip || result.Severity == models.SeverityClean {
		return false, nil
	}

	rule := scanner.RuleFromNotes(result.Notes, result.YaraMatches)
	key := scanner.BuildKey(rule, filePath, result.Severity)
	shouldInsert, entry := dedup.CheckAndRecord(key)

	if !shouldInsert {
		if entry.RecordID != 0 {
			if err := fq.IncrementDedupCount(entry.RecordID); err != nil {
				logger.Error().Err(err).Int64("record_id", entry.RecordID).Msg("full scan: dedup increment failed")
			}
		}
		return false, nil
	}

	fileSize := int64(0)
	if info, err := os.Stat(filePath); err == nil {
		fileSize = info.Size()
	}

	record := &models.FileScanResult{
		MachineID:   sysInfo.MachineID,
		ScanTime:    time.Now().Unix(),
		FilePath:    filePath,
		FileSize:    fileSize,
		FileHash:    fileHash,
		YaraMatches: result.YaraMatches,
		Severity:    result.Severity,
		Status:      models.StatusNew,
		DedupCount:  1,
		Notes:       result.Notes,
	}

	if err := fq.Insert(record); err != nil {
		return false, fmt.Errorf("db insert: %w", err)
	}

	dedup.RecordInsert(key, record.ID)

	logger.Warn().
		Str("file", filePath).
		Str("severity", string(result.Severity)).
		Int("yara_matches", len(result.YaraMatches)).
		Str("notes", result.Notes).
		Msg("FULL SCAN DETECTION")

	return true, nil
}

// countEligible does a stat-only pre-walk to estimate eligible files.
// Magic byte and execute bit checking is skipped — size bounds only.
// This makes counting fast at the cost of a slightly optimistic total.
func countEligible(ctx context.Context, targetDir string, filter *scanner.ExclusionFilter, bar *progressbar.ProgressBar) (int64, error) {
	var count int64

	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("count: cancelled")
		default:
		}

		if d.IsDir() {
			if !filter.ShouldScan(path) {
				return filepath.SkipDir
			}
			_ = bar.Add(1)
			return nil
		}

		if !filter.ShouldScan(path) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.IsDir() || info.Size() < 10 || info.Size() > 100*1024*1024 {
			return nil
		}

		count++
		return nil
	})

	return count, err
}
