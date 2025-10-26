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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf process_monitor.c

package internal

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hillu/go-yara/v4"
	"github.com/shirou/gopsutil/v3/process"
)

const (
	processScanTimeoutSeconds = 30
	processBufferSize         = 50
	processBatchSize          = 100
	yaraProcessTimeoutSeconds = 10
	defaultProcessWorkers     = 4
	maxProcessWorkers         = 8
)

// ProcessScanResult holds the matches found for a single process.
type ProcessScanResult struct {
	PID     int32           `json:"pid"`
	Name    string          `json:"process_name"`
	Cmdline string          `json:"cmdline,omitempty"`
	Matches yara.MatchRules `json:"yara_matches"`
	Error   error           `json:"scanning_errors,omitempty"`
}

type ProcessScanner struct {
	rules       *yara.Rules
	db          *sql.DB
	timeout     time.Duration
	scannedPIDs map[int32]time.Time
	mu          sync.RWMutex
}

type ProcessScanStats struct {
	TotalProcesses   int64
	ScannedProcesses int64
	MatchedProcesses int64
	ErrorProcesses   int64
	SkippedProcesses int64
	DurationSec      int64
}

// NewProcessScanner creates a new process scanner with YARA rules.
func NewProcessScanner(rulesZipPath, extractPath string, db *sql.DB) (*ProcessScanner, error) {
	// Extract rules from zip file
	if err := unzipRules(rulesZipPath, extractPath); err != nil {
		return nil, err
	}

	// Compile rules
	rules, err := compileRules(extractPath)
	if err != nil {
		return nil, err
	}

	return &ProcessScanner{
		rules:       rules,
		db:          db,
		timeout:     yaraProcessTimeoutSeconds * time.Second,
		scannedPIDs: make(map[int32]time.Time),
	}, nil
}

// Close releases scanner resources.
func (ps *ProcessScanner) Close() error {
	if ps.rules != nil {
		ps.rules.Destroy()
	}
	return nil
}

// isRecentlyScanned checks if a process was scanned within the last 30 seconds.
func (ps *ProcessScanner) isRecentlyScanned(pid int32) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if scanTime, exists := ps.scannedPIDs[pid]; exists {
		return time.Since(scanTime) < 30*time.Second
	}
	return false
}

// markScanned records that a process has been scanned.
func (ps *ProcessScanner) markScanned(pid int32) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.scannedPIDs[pid] = time.Now()
}

// cleanupOldEntries removes scan records older than 5 minutes.
func (ps *ProcessScanner) cleanupOldEntries() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for pid, scanTime := range ps.scannedPIDs {
		if scanTime.Before(cutoff) {
			delete(ps.scannedPIDs, pid)
		}
	}
}

// shouldSkipProcess determines if a process should be skipped.
func shouldSkipProcess(proc *process.Process) (bool, string) {
	// Skip kernel threads (PID 0, 1, 2, kthreadd children)
	pid := proc.Pid
	if pid <= 2 {
		return true, "kernel thread"
	}

	// Get process name
	name, err := proc.Name()
	if err != nil {
		return true, "cannot get process name"
	}

	// Skip kernel threads (usually in brackets)
	if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
		return true, "kernel thread"
	}

	return false, ""
}

// scanProcess scans a single process with YARA rules.
func (ps *ProcessScanner) scanProcess(ctx context.Context, pid int32) ProcessScanResult {
	result := ProcessScanResult{PID: pid}

	// Create process handle
	proc, err := process.NewProcess(pid)
	if err != nil {
		result.Error = fmt.Errorf("failed to access process: %w", err)
		return result
	}

	// Get process information
	result.Name, _ = proc.Name()
	result.Cmdline, _ = proc.Cmdline()

	// Check if we should skip this process
	if skip, reason := shouldSkipProcess(proc); skip {
		result.Error = fmt.Errorf("skipped: %s", reason)
		return result
	}

	// Scan process memory with timeout
	done := make(chan ProcessScanResult, 1)

	go func() {
		var matches yara.MatchRules
		err := ps.rules.ScanProc(int(pid), 0, ps.timeout, &matches)

		done <- ProcessScanResult{
			PID:     pid,
			Name:    result.Name,
			Cmdline: result.Cmdline,
			Matches: matches,
			Error:   err,
		}
	}()

	// Wait for scan completion or context cancellation
	select {
	case scanResult := <-done:
		return scanResult
	case <-ctx.Done():
		result.Error = fmt.Errorf("scan cancelled: %w", ctx.Err())
		return result
	}
}

// getAllProcesses retrieves all running process PIDs.
func (ps *ProcessScanner) getAllProcesses() ([]int32, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("failed to get process list: %w", err)
	}
	return pids, nil
}

// getNewProcesses returns PIDs that haven't been scanned recently.
func (ps *ProcessScanner) getNewProcesses() ([]int32, error) {
	allPIDs, err := ps.getAllProcesses()
	if err != nil {
		return nil, err
	}

	newPIDs := make([]int32, 0)
	for _, pid := range allPIDs {
		if !ps.isRecentlyScanned(pid) {
			newPIDs = append(newPIDs, pid)
		}
	}

	return newPIDs, nil
}

// processScanWorker scans processes from the channel.
func (ps *ProcessScanner) processScanWorker(ctx context.Context, pidChan <-chan int32, resultsChan chan<- ProcessScanResult, wg *sync.WaitGroup, stats *ProcessScanStats) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			logger.Debug().Msg("process scan worker stopping due to context cancellation")
			return
		case pid, ok := <-pidChan:
			if !ok {
				return
			}

			// Scan the process
			result := ps.scanProcess(ctx, pid)
			ps.markScanned(pid)

			// Update stats
			if result.Error != nil {
				if !strings.Contains(result.Error.Error(), "skipped:") {
					logger.Debug().Err(result.Error).Int32("pid", pid).Msg("process scan error")
				}
			} else {
				if len(result.Matches) > 0 {
					logger.Warn().
						Int32("pid", result.PID).
						Str("name", result.Name).
						Int("matches", len(result.Matches)).
						Msg("YARA matches found in process")
				}
			}

			// Send result to collector
			select {
			case resultsChan <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// processResultCollector collects and batches results for database insertion.
func (ps *ProcessScanner) processResultCollector(ctx context.Context, resultsChan <-chan ProcessScanResult, wg *sync.WaitGroup, stats *ProcessScanStats) {
	defer wg.Done()

	batch := make([]ProcessScanResult, 0, processBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}

		if err := ps.saveProcessScanResults(batch); err != nil {
			logger.Error().Err(err).Int("batch_size", len(batch)).Msg("failed to save process scan results")
		} else {
			logger.Debug().Int("batch_size", len(batch)).Msg("saved process results batch")
		}

		batch = batch[:0]
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case result, ok := <-resultsChan:
			if !ok {
				flush()
				return
			}

			// Only save results with matches or critical errors
			if len(result.Matches) > 0 {
				batch = append(batch, result)
				if len(batch) >= processBatchSize {
					flush()
				}
			}
		case <-ticker.C:
			flush()
		}
	}
}

// saveProcessScanResults saves batch results to database.
func (ps *ProcessScanner) saveProcessScanResults(results []ProcessScanResult) error {
	if len(results) == 0 {
		return nil
	}

	scanTime := time.Now().Unix()

	tx, err := ps.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	valueStrings := make([]string, 0, len(results))
	valueArgs := make([]interface{}, 0, len(results)*5)

	for _, result := range results {
		yaraResultsJSON, err := json.Marshal(result.Matches)
		if err != nil {
			logger.Error().Err(err).Int32("pid", result.PID).Msg("failed to marshal yara results")
			continue
		}

		valueStrings = append(valueStrings, "(?, ?, ?, ?, ?)")
		valueArgs = append(valueArgs, scanTime, result.PID, result.Name, result.Cmdline, yaraResultsJSON)
	}

	if len(valueStrings) == 0 {
		return nil
	}

	query := fmt.Sprintf(
		"INSERT INTO process_scan_results (lastscan_time, pid, process_name, cmdline, yara_results) VALUES %s",
		strings.Join(valueStrings, ","),
	)

	if _, err := tx.Exec(query, valueArgs...); err != nil {
		return fmt.Errorf("failed to execute bulk insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// scanAllProcesses performs a one-time scan of all running processes.
func (ps *ProcessScanner) scanAllProcesses(ctx context.Context) error {
	logger.Info().Msg("starting process scan")

	startTime := time.Now()
	stats := &ProcessScanStats{}

	// Get all processes
	pids, err := ps.getAllProcesses()
	if err != nil {
		return err
	}
	stats.TotalProcesses = int64(len(pids))

	// Setup channels
	pidChan := make(chan int32, processBufferSize)
	resultsChan := make(chan ProcessScanResult, processBufferSize)

	var scanWG sync.WaitGroup
	var saveWG sync.WaitGroup

	// Start result collector
	saveWG.Add(1)
	go ps.processResultCollector(ctx, resultsChan, &saveWG, stats)

	// Start scan workers
	numWorkers := defaultProcessWorkers
	if maxWorkers := runtime.NumCPU() / 2; maxWorkers > 0 && numWorkers > maxWorkers {
		numWorkers = maxWorkers
	}
	if numWorkers > maxProcessWorkers {
		numWorkers = maxProcessWorkers
	}

	logger.Info().Int("workers", numWorkers).Msg("starting process scan workers")
	for i := 0; i < numWorkers; i++ {
		scanWG.Add(1)
		go ps.processScanWorker(ctx, pidChan, resultsChan, &scanWG, stats)
	}

	// Send PIDs to workers
	for _, pid := range pids {
		select {
		case pidChan <- pid:
		case <-ctx.Done():
			break
		}
	}

	// Cleanup
	close(pidChan)
	scanWG.Wait()
	close(resultsChan)
	saveWG.Wait()

	stats.DurationSec = int64(time.Since(startTime).Seconds())
	logger.Info().
		Int64("total_processes", stats.TotalProcesses).
		Int64("duration_sec", stats.DurationSec).
		Msg("process scan completed")

	return nil
}

// startProcessScan is the entry point for one-time process scanning.
func startProcessScan() {
	scanner, err := NewProcessScanner(
		GlobalConfig.ScanSettings.RulesFilepath,
		filepath.Join(GlobalConfig.GenericSettings.WorkDirectory, "rules"),
		DB,
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create process scanner")
	}
	defer scanner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), processScanTimeoutSeconds*time.Minute)
	defer cancel()

	if err := scanner.scanAllProcesses(ctx); err != nil {
		logger.Error().Err(err).Msg("process scan failed")
	}
}
