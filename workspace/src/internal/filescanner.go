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
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hillu/go-yara/v4"
)

const (
	scanTimeoutMinutes     = 30
	bufferSize             = 100
	dbBatchSize            = 1000
	yaraScanTimeoutSeconds = 60
	defaultWorkers         = 2
	maxWorkers             = 4
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
	rules   *yara.Rules
	db      *sql.DB
	timeout time.Duration
}

type ScanStats struct {
	TotalFiles   int64
	ScannedFiles int64
	MatchedFiles int64
	ErrorFiles   int64
	SkippedFiles int64
	DurationSec  int64
}

// Extracts all rules into designated directory.
func unzipRules(zipPath string, extractionPath string) error {
	logger.Info().Str("zip", zipPath).Str("dest", extractionPath).Msg("starting rule extraction")

	var openedFiles int

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", zipPath, err)
	}
	defer r.Close()

	// Ensure the destination directory exists
	if err := os.MkdirAll(extractionPath, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	for _, f := range r.File {
		// Construct the full path for the extracted file
		fpath := filepath.Join(extractionPath, f.Name)

		// Security check: Prevent Path Traversal (crucial for untrusted zip files)
		relPath, err := filepath.Rel(extractionPath, fpath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			logger.Warn().Str("filename", f.Name).Msg("skipping file due to path traversal risk")
			continue
		}

		// Handle directories
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, f.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", fpath, err)
			}
			continue
		}

		// Handle files
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return fmt.Errorf("failed to create file path dir: %w", err)
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", fpath, err)
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		_, err = io.Copy(outFile, rc)
		// Close handles immediately after use
		rc.Close()
		outFile.Close()
		openedFiles++
		if err != nil {
			return fmt.Errorf("failed to copy content for %s: %w", fpath, err)
		}
	}
	logger.Info().Int("rule_files", openedFiles).Msg("rule extraction complete.")
	return nil
}

// Compiles all yara rules specified inside a target directory.
func compileRules(rulesDir string) (*yara.Rules, error) {
	var rulesAdded int
	var rulesSkipped int

	// Start a new compiler.
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not create YARA compiler: %w", err)
	}
	defer compiler.Destroy()

	// Parse all files and
	if err = filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Only process files ending in .yar or .yara
		if strings.HasSuffix(d.Name(), ".yar") || strings.HasSuffix(d.Name(), ".yara") {
			logger.Debug().Str("rule_file", path).Msg("adding rule to compiler")

			// Read the rule content.
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				logger.Error().Err(readErr).Str("rule_file", path).Msg("could not read rule file content")
				rulesSkipped++
				return nil
			}

			// Create a temp compiler for syntax checking
			checkCompiler, checkErr := yara.NewCompiler()
			if checkErr != nil {
				return fmt.Errorf("could not create temporary YARA compiler for checking: %w", checkErr)
			}
			defer checkCompiler.Destroy()
			ruleContent := string(content)

			// Attempt to compile the rule into temp compiler
			if addErr := checkCompiler.AddString(ruleContent, path); addErr != nil {
				logger.Error().Err(addErr).Str("rule_file", path).Msg("syntax error in rule file. skipping")
				rulesSkipped++
				// Do NOT touch the main compiler. Continue walking.
				return nil
			}

			// If temp compiler passed then add rule to main compiler.
			if finalAddErr := compiler.AddString(ruleContent, path); finalAddErr != nil {
				return fmt.Errorf("unexpected error adding pre-checked rule to main compiler %s: %w", path, finalAddErr)
			}

			rulesAdded++
			logger.Debug().Str("rule_file", path).Msg("rule added to compiler")
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Get compiled rules from compiler.
	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("could not get compiled rules after adding files: %w", err)
	}

	logger.Info().Int("rule_added", rulesAdded).Int("rules_skipped", rulesSkipped).Msg("compiled rules")
	return rules, nil
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
		rules:   rules,
		db:      db,
		timeout: yaraScanTimeoutSeconds * time.Second,
	}, nil
}

// Closes the scanner by removing the resources.
func (s *FileScanner) Close() error {
	if s.rules != nil {
		s.rules.Destroy()
	}
	return nil
}

// This function walks the directory tree and send file into scanner channel
func (s *FileScanner) walkDirectory(ctx context.Context, dir string, fileChan chan<- fileToScan, stats *ScanStats) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Handle access errors
		if err != nil {
			logger.Error().Err(err).Str("path", path).Msg("error accessing path")
			atomic.AddInt64(&stats.ErrorFiles, 1)
			// Continue walking despite errors
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
			// Successfully sent
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	})
}

// scanWorker processes files from the channel and scans them
func (s *FileScanner) scanWorker(ctx context.Context, fileChan <-chan fileToScan, resultsChan chan<- YaraScanResult, wg *sync.WaitGroup, stats *ScanStats) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			logger.Debug().Msg("scan worker stopping due to context cancellation")
			return
		case file, ok := <-fileChan:
			if !ok {
				// Channel closed, worker should exit
				return
			}

			// Scan the file
			result := s.scanFile(ctx, file.path)

			// Update stats
			atomic.AddInt64(&stats.ScannedFiles, 1)
			if result.Error != nil {
				atomic.AddInt64(&stats.ErrorFiles, 1)
			}
			if len(result.Matches) > 0 {
				atomic.AddInt64(&stats.MatchedFiles, 1)
				logger.Debug().
					Str("file", result.FilePath).
					Int("matches", len(result.Matches)).
					Msg("YARA matches found")
			}

			// Send result to collector
			select {
			case resultsChan <- result:
				// Successfully sent
			case <-ctx.Done():
				return
			}
		}
	}
}

// scanFile scans a single file with YARA rules
func (s *FileScanner) scanFile(ctx context.Context, path string) YaraScanResult {
	// Create a channel to receive scan completion
	done := make(chan YaraScanResult, 1)

	go func() {
		var matches yara.MatchRules
		err := s.rules.ScanFile(path, 0, time.Duration(s.timeout.Seconds()), &matches)

		done <- YaraScanResult{
			FilePath: path,
			Matches:  matches,
			Error:    err,
		}
	}()

	// Wait for scan to complete or context cancellation
	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		return YaraScanResult{
			FilePath: path,
			Error:    fmt.Errorf("scan cancelled: %w", ctx.Err()),
		}
	}
}

// resultCollector collects results and batches them for database insertion
func (s *FileScanner) resultCollector(ctx context.Context, resultsChan <-chan YaraScanResult, wg *sync.WaitGroup, stats *ScanStats) {
	defer wg.Done()

	batch := make([]YaraScanResult, 0, dbBatchSize)

	// Flush function to save accumulated results
	flush := func() {
		if len(batch) == 0 {
			return
		}

		if err := s.saveScanResults(batch); err != nil {
			logger.Error().Err(err).Int("batch_size", len(batch)).Msg("failed to save scan results batch")
		} else {
			logger.Debug().Int("batch_size", len(batch)).Msg("saved results batch")
		}

		// Clear batch
		batch = batch[:0]
	}

	// Timer for periodic flushes (every 5 seconds)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case result, ok := <-resultsChan:
			if !ok {
				// Channel closed, flush remaining results and exit
				flush()
				return
			}

			// Check if any detections were found before appending to batch.
			if len(result.Matches) > 0 || result.Error != nil {
				batch = append(batch, result)

				if len(batch) >= dbBatchSize {
					flush()
				}
			}
		case <-ticker.C:
			// Periodic flush to avoid holding results too long
			flush()
		}
	}
}

// saveScanResults saves a batch of scan results to the database
func (s *FileScanner) saveScanResults(results []YaraScanResult) error {
	if len(results) == 0 {
		return nil
	}

	// Get current timestamp
	scanTime := time.Now().Unix()

	// Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Build bulk insert query
	valueStrings := make([]string, 0, len(results))
	valueArgs := make([]interface{}, 0, len(results)*3)

	for _, result := range results {
		// Marshal YARA matches to JSON
		yaraResultsJSON, err := json.Marshal(result.Matches)
		if err != nil {
			logger.Error().Err(err).Str("filepath", result.FilePath).Msg("failed to marshal yara results, skipping")
			continue
		}

		valueStrings = append(valueStrings, "(?, ?, ?)")
		valueArgs = append(valueArgs, scanTime, result.FilePath, yaraResultsJSON)
	}

	if len(valueStrings) == 0 {
		return nil
	}

	// Execute bulk insert
	query := fmt.Sprintf(
		"INSERT INTO scan_results (lastscan_time, filepath, yara_results) VALUES %s",
		strings.Join(valueStrings, ","),
	)

	if _, err := tx.Exec(query, valueArgs...); err != nil {
		return fmt.Errorf("failed to execute bulk insert: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ScanDirectory scans all files in a directory using YARA rules with concurrency.
func (s *FileScanner) ScanDirectory(ctx context.Context, dir string) error {
	logger.Info().Str("directory", dir).Msg("starting directory scan")

	// Setup variables and channels
	startTime := time.Now()
	stats := &ScanStats{}
	fileChan := make(chan fileToScan, bufferSize)
	resultsChan := make(chan YaraScanResult, bufferSize)

	// WaitGroups for synchronization
	var scanWG sync.WaitGroup
	var saveWG sync.WaitGroup

	// Start result collector before we start our scanners.
	saveWG.Add(1)
	go s.resultCollector(ctx, resultsChan, &saveWG, stats)

	// Determine required workers and start scanners.
	numWorkers := defaultWorkers
	if maxWorkers := runtime.NumCPU() / 2; maxWorkers > 0 && numWorkers > maxWorkers {
		numWorkers = maxWorkers
	}
	if numWorkers > maxWorkers {
		numWorkers = maxWorkers
	}
	logger.Info().Int("workers", numWorkers).Msg("starting scan workers")
	for i := 0; i < numWorkers; i++ {
		scanWG.Add(1)
		go s.scanWorker(ctx, fileChan, resultsChan, &scanWG, stats)
	}

	// Walk the compleyte directory and send files for scanning into scanners.
	walkErr := s.walkDirectory(ctx, dir, fileChan, stats)

	// When files are completed simply close the file channel to signal other workers to stop.
	// Wait for the workers to finish.
	close(fileChan)
	scanWG.Wait()

	// When scanners are completed then close our result collector.
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

		// Return walk error if it occurred
	if walkErr != nil {
		return fmt.Errorf("error walking directory: %w", walkErr)
	}
	return nil
}

// Startscan is a entrypoint function which generates a new yara scanner and performs a full scan before closing the scan.
func startScan() {
	// Create scanner
	scanner, err := NewFileScanner(GlobalConfig.ScanSettings.RulesFilepath, filepath.Join(GlobalConfig.GenericSettings.WorkDirectory, "rules"), DB)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create new scanner object")
	}
	defer scanner.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeoutMinutes*time.Minute)
	defer cancel()

	// Scan directory
	if err := scanner.ScanDirectory(ctx, GlobalConfig.ScanSettings.TargetDirectory); err != nil {
		logger.Error().Err(err).Msg("scan failed")
	}
}
