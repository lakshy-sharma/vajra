// internal/detect/fullscan.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package detect

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
	"vajra/internal/findings"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// ScanSummary holds final counts reported to the CLI caller.
type ScanSummary struct {
	FilesScanned int64
	HitsFound    int64
	Candidates   int64
	Interrupted  bool
}

// RunFullScan performs a blocking filesystem walk, submitting each
// eligible file through the analyzer pipeline via FindingWriter.
// Progress bar with ETA rendered to stdout.
func RunFullScan(
	ctx context.Context,
	targetDir string,
	pipeline *analyzer.Pipeline,
	filter *utilities.ExclusionFilter,
	writer *findings.FindingWriter,
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
		logger.Info().Str("target", targetDir).Msg("full scan: count interrupted, proceeding without total")
	}
	_ = countBar.Finish()
	fmt.Println()

	logger.Info().
		Int64("eligible", total).
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

	// Not shared with daemon's tracker — manual scan always re-evaluates.
	tracker := utilities.NewRecentScanTracker(5 * time.Minute)

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

		// Full scan has no triggering process — execute bit and magic bytes only.
		eligible, _ := isEligibleForWalk(path)
		if !eligible {
			return nil
		}

		_ = bar.Add(1)
		summary.FilesScanned++

		hit, scanErr := scanFile(ctx, path, pipeline, tracker, writer, sysInfo, logger)
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

func scanFile(
	ctx context.Context,
	filePath string,
	pipeline *analyzer.Pipeline,
	tracker *utilities.RecentScanTracker,
	writer *findings.FindingWriter,
	sysInfo utilities.SystemInfo,
	logger *zerolog.Logger,
) (bool, error) {
	quickHash, _ := utilities.QuickHash(filePath)
	if tracker.WasRecentlyScanned(filePath, quickHash) {
		return false, nil
	}
	tracker.MarkScanned(filePath, quickHash)

	fileHash, err := utilities.FullSHA256(filePath)
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

	fileSize := int64(0)
	if info, err := os.Stat(filePath); err == nil {
		fileSize = info.Size()
	}

	ruleID := utilities.RuleFromMatch(result.Notes, result.YaraMatches)
	f := findings.Finding{
		Source:      findings.SourceFullScan,
		Severity:    result.Severity,
		Status:      models.StatusNew,
		DetectedAt:  time.Now().Unix(),
		TargetPath:  filePath,
		RuleID:      ruleID,
		Notes:       result.Notes,
		FileHash:    fileHash,
		FileSize:    fileSize,
		YaraMatches: result.YaraMatches,
	}

	id, err := writer.Write(ctx, f)
	if err != nil {
		return false, fmt.Errorf("write: %w", err)
	}

	if id > 0 {
		logger.Warn().
			Str("file", filePath).
			Str("severity", string(result.Severity)).
			Str("rule", ruleID).
			Msg("FULL SCAN DETECTION")
		return true, nil
	}
	return false, nil
}

// isEligibleForWalk applies execute bit and magic byte checks.
// No interpreter check — full scan has no triggering process.
func isEligibleForWalk(filePath string) (bool, string) {
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
	if hasExecutableMagicBytes(filePath) {
		return true, ""
	}
	return false, "not_executable"
}

// hasExecutableMagicBytes checks first 4 bytes for known executable formats.
func hasExecutableMagicBytes(filePath string) bool {
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
		return true // ELF
	}
	if magic[0] == '#' && magic[1] == '!' {
		return true // shebang
	}
	if magic[0] == 0x4d && magic[1] == 0x5a {
		return true // MZ/PE
	}
	if n >= 4 && magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe {
		return true // Mach-O fat
	}
	return false
}

// countEligible does a stat-only pre-walk for the progress bar total.
// Magic byte check skipped — fast count, slightly optimistic total.
func countEligible(
	ctx context.Context,
	targetDir string,
	filter *utilities.ExclusionFilter,
	bar *progressbar.ProgressBar,
) (int64, error) {
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
		if !info.IsDir() && info.Size() >= 10 && info.Size() <= 100*1024*1024 {
			count++
		}
		return nil
	})
	return count, err
}
