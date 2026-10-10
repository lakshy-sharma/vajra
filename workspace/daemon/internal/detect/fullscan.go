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
	FilesScanned     int64
	HitsFound        int64
	Candidates       int64
	ProcessesScanned int64
	ProcessHits      int64
	Interrupted      bool
}

// RunFullScan performs a blocking filesystem walk followed by a /proc walk.
// maxFileSizeBytes and interpreters come from config — fullscan does not
// import the config package directly to keep CLI and daemon paths independent.
func RunFullScan(
	ctx context.Context,
	targetDir string,
	pipeline *analyzer.Pipeline,
	filter *utilities.ExclusionFilter,
	processFilter *utilities.ProcessFilter,
	writer *findings.FindingWriter,
	sysInfo utilities.SystemInfo,
	logger *zerolog.Logger,
	maxFileSizeBytes int64,
	interpreters []string,
) (ScanSummary, error) {
	// Build interpreter lookup once — checked per file in the walk.
	interpMap := make(map[string]bool, len(interpreters)*2)
	for _, interp := range interpreters {
		interpMap[interp] = true
		interpMap[filepath.Base(interp)] = true
	}

	logger.Info().Str("target", targetDir).Msg("full scan: counting eligible files")

	countBar := progressbar.NewOptions(
		-1,
		progressbar.OptionSetDescription("counting"),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowElapsedTimeOnFinish(),
	)

	countStart := time.Now()
	// W19: countEligible uses the same size/mode criteria as the scan walk
	// so the progress bar total closely matches files actually processed.
	total, err := countEligible(ctx, targetDir, filter, maxFileSizeBytes, countBar)
	if err != nil {
		logger.Info().Str("target", targetDir).Msg("full scan: count interrupted, proceeding without total")
	}
	_ = countBar.Finish()
	fmt.Println()

	logger.Info().
		Int64("eligible", total).
		Str("count_duration", time.Since(countStart).Round(time.Millisecond).String()).
		Msg("full scan: starting file scan")

	bar := progressbar.NewOptions64(
		total,
		progressbar.OptionSetDescription("scanning files"),
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

		info, err := d.Info()
		if err != nil {
			return nil
		}

		eligible, _ := isEligibleForWalk(path, info, maxFileSizeBytes, interpMap)
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

	if ctx.Err() == nil {
		fmt.Println("Scanning running processes...")
		procSummary, procErr := RunProcWalk(
			ctx,
			pipeline,
			writer,
			processFilter,
			tracker,
			sysInfo,
			logger,
		)
		if procErr != nil && ctx.Err() == nil {
			logger.Error().Err(procErr).Msg("full scan: procwalk error")
		}
		summary.ProcessesScanned = int64(procSummary.Scanned)
		summary.ProcessHits = int64(procSummary.Detections)
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

	var fileSize int64
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

// isEligibleForWalk checks file eligibility using an already-fetched FileInfo
// to avoid a redundant stat inside the walk callback.
// W20: interpreter binary check added.
// W8: uses utilities.HasExecutableMagic instead of a local duplicate.
func isEligibleForWalk(filePath string, info fs.FileInfo, maxSize int64, interpreters map[string]bool) (bool, string) {
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
	// Interpreter binaries may not have the executable bit set in all
	// environments (e.g. container base images) — check the path explicitly.
	if interpreters[filePath] || interpreters[filepath.Base(filePath)] {
		return true, ""
	}
	// Magic byte check requires opening the file — only reached when the
	// executable bit is not set and the path is not a known interpreter.
	f, err := os.Open(filePath)
	if err != nil {
		return false, "open_failed"
	}
	defer f.Close()
	if utilities.HasExecutableMagic(f) {
		return true, ""
	}
	return false, "not_executable"
}

// countEligible pre-counts eligible files for the progress bar.
// Uses executable bit and size only — magic byte inspection would require
// opening every file, making the count pass as expensive as the scan pass.
// The bar total is a close approximation; files passing magic check but
// not the executable bit will be scanned but not pre-counted.
func countEligible(
	ctx context.Context,
	targetDir string,
	filter *utilities.ExclusionFilter,
	maxSize int64,
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
		size := info.Size()
		if size < 10 || (maxSize > 0 && size > maxSize) {
			return nil
		}
		if info.Mode()&0o111 != 0 {
			count++
		}
		return nil
	})
	return count, err
}
