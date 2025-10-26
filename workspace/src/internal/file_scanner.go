/*
Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package internal

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hillu/go-yara/v4"
)

type fileToScan struct {
	path string
	info fs.DirEntry
}

// YaraScanResult holds the matches found for a single file.
type YaraScanResult struct {
	FilePath string          `json:"file_path"`
	Matches  yara.MatchRules `json:"yara_matches"`
	Error    error           `json:"scanning_errors,omitempty"`
}

type FileScanner struct {
	rules             *yara.Rules
	db                *sql.DB
	singleFileTimeout time.Duration
}

type ScanStats struct {
	TotalFiles   int64
	ScannedFiles int64
	MatchedFiles int64
	ErrorFiles   int64
	SkippedFiles int64
	DurationSec  int64
}

// Generates a new yara scanner.
func NewFileScanner(rulesZipPath, extractPath string, db *sql.DB) (*FileScanner, error) {
	// Extract rules from zip file
	if err := unzipRules(rulesZipPath, extractPath); err != nil {
		return nil, err
	}

	// Compile rules
	rules, err := compileRules(extractPath)
	if err != nil {
		return nil, err
	}

	return &FileScanner{
		rules:             rules,
		db:                db,
		singleFileTimeout: time.Duration(GlobalConfig.TimingSettings.SingleFileScanTimeoutSec) * time.Second,
	}, nil
}

// Close function closes the scanner by removing the resources.
func (s *FileScanner) Close() error {
	if s.rules != nil {
		s.rules.Destroy()
	}
	return nil
}

// saveFileScanResults saves a batch of scan results to the database
func (s *FileScanner) saveFileScanResults(results []YaraScanResult) error {
	if len(results) == 0 {
		return nil
	}

	// Set scan time and create a transaction.
	scanTime := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	// Generate prepared statement for insert
	stmt, err := tx.Prepare(`
		INSERT INTO file_scan_results (lastscan_time, filepath, yara_results)
		VALUES (?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for _, r := range results {
		// Serialize results
		yaraJSON, err := json.Marshal(r.Matches)
		if err != nil {
			logger.Error().
				Err(err).
				Str("file", r.FilePath).
				Msg("failed to marshal yara results, skipping")
			continue
		}

		// Execute each result.
		if _, err := stmt.Exec(scanTime, r.FilePath, yaraJSON); err != nil {
			logger.Error().
				Err(err).
				Str("file", r.FilePath).
				Msg("failed to insert scan result")
			continue
		}
	}

	// Commit all executions
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

// resultCollector collects results and batches them for database insertion
func (s *FileScanner) resultCollector(ctx context.Context, resultsChan <-chan YaraScanResult, wg *sync.WaitGroup, stats *ScanStats) {
	defer wg.Done()

	batchSize := GlobalConfig.PerformanceSettings.DBInsertBatchSize
	batch := make([]YaraScanResult, 0, batchSize)

	// Save batch function to save results of a batch
	saveBatch := func() {
		if len(batch) == 0 {
			return
		}

		if err := s.saveFileScanResults(batch); err != nil {
			logger.Error().Err(err).
				Int("batch_size", len(batch)).
				Msg("failed to save scan results batch")
		} else {
			logger.Debug().Int("batch_size", len(batch)).Msg("saved results batch")
		}

		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			saveBatch()
			return

		case result, ok := <-resultsChan:
			if !ok {
				saveBatch()
				return
			}

			// Skip clean results to reduce DB noise
			if len(result.Matches) == 0 && result.Error == nil {
				continue
			}

			batch = append(batch, result)
			if len(batch) >= batchSize {
				saveBatch()
			}

		case <-time.After(5 * time.Second):
			saveBatch()
		}
	}
}

// scanFile scans a single file with YARA rules
func (s *FileScanner) scanFile(ctx context.Context, path string) YaraScanResult {
	ctx, cancel := context.WithTimeout(ctx, s.singleFileTimeout)
	defer cancel()

	var matches yara.MatchRules
	err := s.rules.ScanFile(path, 0, s.singleFileTimeout, &matches)

	return YaraScanResult{
		FilePath: path,
		Matches:  matches,
		Error:    err,
	}
}

// updateStats is used for updating filescan stats after a scan is complete.
// It takes a stats object and a yara scan result.
func (s *FileScanner) updateStats(stats *ScanStats, result *YaraScanResult) {
	atomic.AddInt64(&stats.ScannedFiles, 1)

	if result.Error != nil {
		atomic.AddInt64(&stats.ErrorFiles, 1)
		return
	}

	if len(result.Matches) > 0 {
		atomic.AddInt64(&stats.MatchedFiles, 1)
		logger.Debug().
			Str("file", result.FilePath).
			Int("matches", len(result.Matches)).
			Msg("YARA matches found")
	}
}

// scanWorker captures files from fileChan and scans them one by one.
func (s *FileScanner) scanWorker(ctx context.Context, fileChan <-chan fileToScan, resultsChan chan<- YaraScanResult, wg *sync.WaitGroup, stats *ScanStats) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			logger.Debug().Msg("worker: context cancelled")
			return

		case file, ok := <-fileChan:
			if !ok {
				logger.Debug().Msg("worker: file channel closed")
				return
			}

			// Scan the file
			result := s.scanFile(ctx, file.path)
			s.updateStats(stats, &result)

			// Try to send result unless context is done
			select {
			case resultsChan <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// This function walks the directory tree and sends files into scanner channel
func (s *FileScanner) walkDirectory(ctx context.Context, dir string, fileChan chan<- fileToScan, stats *ScanStats) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		// Exit if context was cancelled
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Handle access errors and continue walking
		if err != nil {
			logger.Error().Err(err).Str("path", path).Msg("error accessing path")
			atomic.AddInt64(&stats.ErrorFiles, 1)
			return nil
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Count total files
		atomic.AddInt64(&stats.TotalFiles, 1)

		// Send file to scan workers
		select {
		case fileChan <- fileToScan{path: path, info: d}:
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	})
}

// ScanDirectory scans all files in a directory using YARA rules with concurrency.
func (s *FileScanner) scanDirectory(ctx context.Context, dir string) error {
	logger.Info().Str("directory", dir).Msg("starting directory scan")

	// Setup variables and channels
	startTime := time.Now()
	stats := &ScanStats{}
	fileChan := make(chan fileToScan, GlobalConfig.PerformanceSettings.FileScanBufferSize)
	resultsChan := make(chan YaraScanResult, GlobalConfig.PerformanceSettings.FileScanBufferSize)

	// Create wait groups to synchronize closing saver and processors.
	var scanWG sync.WaitGroup
	var saveWG sync.WaitGroup

	// Start result collector before we start our scanners.
	saveWG.Add(1)
	go s.resultCollector(ctx, resultsChan, &saveWG, stats)

	numWorkers := getMaxWorkers()
	logger.Info().Int("workers", numWorkers).Msg("starting scan workers")
	for range numWorkers {
		scanWG.Add(1)
		go s.scanWorker(ctx, fileChan, resultsChan, &scanWG, stats)
	}

	// Start walking the target directory and send files for scanning.
	walkErr := s.walkDirectory(ctx, dir, fileChan, stats)

	// Closure code
	//==============

	// Close scanners
	close(fileChan)
	scanWG.Wait()

	// Close result savers
	close(resultsChan)
	saveWG.Wait()

	// Generate scan statistics
	stats.DurationSec = int64(time.Since(startTime).Seconds())
	logger.Info().
		Int64("total_files", stats.TotalFiles).
		Int64("scanned", stats.ScannedFiles).
		Int64("matched", stats.MatchedFiles).
		Int64("errors", stats.ErrorFiles).
		Int64("skipped", stats.SkippedFiles).
		Int64("duration_sec", stats.DurationSec).
		Msg("directory scan completed")

	if walkErr != nil {
		return fmt.Errorf("error walking directory: %w", walkErr)
	}
	return nil
}

// startFileScan is an entrypoint function which generates a new yara scanner and performs a full scan before closing the scan.
func startFileScan() {
	// Create scanner
	scanner, err := NewFileScanner(GlobalConfig.ScanSettings.RulesFilepath, filepath.Join(GlobalConfig.GenericSettings.WorkDirectory, "rules"), DB)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create new file scanner object")
	}
	defer scanner.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(GlobalConfig.TimingSettings.CompleteFileScanTimeoutMin)*time.Minute)
	defer cancel()

	// Scan directory
	if err := scanner.scanDirectory(ctx, GlobalConfig.ScanSettings.TargetDirectory); err != nil {
		logger.Error().Err(err).Msg("scan failed")
	}
}
