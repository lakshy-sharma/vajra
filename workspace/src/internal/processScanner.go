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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hillu/go-yara/v4"
	"github.com/shirou/gopsutil/v3/process"
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
	rules             *yara.Rules
	db                *sql.DB
	singleProcTimeout time.Duration
	scannedPIDs       map[int32]time.Time
	mu                sync.RWMutex
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
		rules:             rules,
		db:                db,
		singleProcTimeout: time.Duration(GlobalConfig.TimingSettings.SingleProcessScanTimeoutSec) * time.Second,
		scannedPIDs:       make(map[int32]time.Time),
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

// saveProcessScanResults saves batch results to database.
func (ps *ProcessScanner) saveProcessScanResults(results []ProcessScanResult) error {
	if len(results) == 0 {
		return nil
	}

	scanTime := time.Now().Unix()
	tx, err := ps.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO process_scan_results (lastscan_time, pid, process_name, cmdline, yara_results)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for _, r := range results {
		yaraJSON, err := json.Marshal(r.Matches)
		if err != nil {
			logger.Error().
				Err(err).
				Int32("pid", r.PID).
				Msg("failed to marshal yara results, skipping")
			continue
		}

		if _, err := stmt.Exec(scanTime, r.PID, r.Name, r.Cmdline, yaraJSON); err != nil {
			logger.Error().
				Err(err).
				Int32("pid", r.PID).
				Msg("failed to insert scan result")
			continue
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

// resultCollector collects and batches results for database insertion.
func (ps *ProcessScanner) resultCollector(ctx context.Context, resultsChan <-chan ProcessScanResult, wg *sync.WaitGroup, stats *ProcessScanStats) {
	defer wg.Done()

	batchSize := GlobalConfig.PerformanceSettings.DBInsertBatchSize
	batch := make([]ProcessScanResult, 0, batchSize)

	saveBatch := func() {
		if len(batch) == 0 {
			return
		}

		if err := ps.saveProcessScanResults(batch); err != nil {
			logger.Error().Err(err).
				Int("batch_size", len(batch)).
				Msg("failed to save process scan results")
		} else {
			logger.Debug().Int("batch_size", len(batch)).Msg("saved process results batch")
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

			// Only save results with matches (reduce DB noise)
			if len(result.Matches) == 0 {
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

// scanProcess scans a single process with YARA rules.
func (ps *ProcessScanner) scanProcess(ctx context.Context, pid int32) ProcessScanResult {
	ctx, cancel := context.WithTimeout(ctx, ps.singleProcTimeout)
	defer cancel()

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

	// Scan process memory
	var matches yara.MatchRules
	err = ps.rules.ScanProc(int(pid), 0, ps.singleProcTimeout, &matches)

	result.Matches = matches
	result.Error = err

	return result
}

// updateStats updates process scan stats after a scan is complete.
func (ps *ProcessScanner) updateStats(stats *ProcessScanStats, result *ProcessScanResult) {
	atomic.AddInt64(&stats.ScannedProcesses, 1)

	if result.Error != nil {
		if !strings.Contains(result.Error.Error(), "skipped:") {
			atomic.AddInt64(&stats.ErrorProcesses, 1)
		} else {
			atomic.AddInt64(&stats.SkippedProcesses, 1)
		}
		return
	}

	if len(result.Matches) > 0 {
		atomic.AddInt64(&stats.MatchedProcesses, 1)
		logger.Warn().
			Int32("pid", result.PID).
			Str("name", result.Name).
			Int("matches", len(result.Matches)).
			Msg("YARA matches found in process")
	}
}

// scanWorker captures PIDs from pidChan and scans them one by one.
func (ps *ProcessScanner) scanWorker(ctx context.Context, pidChan <-chan int32, resultsChan chan<- ProcessScanResult, wg *sync.WaitGroup, stats *ProcessScanStats) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			logger.Debug().Msg("worker: context cancelled")
			return

		case pid, ok := <-pidChan:
			if !ok {
				logger.Debug().Msg("worker: PID channel closed")
				return
			}

			// Scan the process
			result := ps.scanProcess(ctx, pid)
			ps.markScanned(pid)
			ps.updateStats(stats, &result)

			// Try to send result unless context is done
			select {
			case resultsChan <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// getAllProcesses retrieves all running process PIDs.
func (ps *ProcessScanner) getAllProcesses(ctx context.Context, pidChan chan<- int32, stats *ProcessScanStats) error {
	pids, err := process.Pids()
	if err != nil {
		return fmt.Errorf("failed to get process list: %w", err)
	}

	stats.TotalProcesses = int64(len(pids))

	for _, pid := range pids {
		select {
		case pidChan <- pid:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// scanAllProcesses performs a one-time scan of all running processes.
func (ps *ProcessScanner) scanAllProcesses(ctx context.Context) error {
	logger.Info().Msg("scanning all processes")

	startTime := time.Now()
	stats := &ProcessScanStats{}
	pidChan := make(chan int32, GlobalConfig.PerformanceSettings.ProcessScanBufferSize)
	resultsChan := make(chan ProcessScanResult, GlobalConfig.PerformanceSettings.ProcessScanBufferSize)

	var scanWG sync.WaitGroup
	var saveWG sync.WaitGroup

	// Start result collector
	saveWG.Add(1)
	go ps.resultCollector(ctx, resultsChan, &saveWG, stats)

	// Start scan workers
	numWorkers := getMaxWorkers()
	logger.Info().Int("workers", numWorkers).Msg("starting process scan workers")
	for range numWorkers {
		scanWG.Add(1)
		go ps.scanWorker(ctx, pidChan, resultsChan, &scanWG, stats)
	}

	// Get all processes and send to workers
	enumErr := ps.getAllProcesses(ctx, pidChan, stats)

	// Closure code
	//==============

	// Close scanners
	close(pidChan)
	scanWG.Wait()

	// Close result savers
	close(resultsChan)
	saveWG.Wait()

	stats.DurationSec = int64(time.Since(startTime).Seconds())
	logger.Info().
		Int64("total_processes", stats.TotalProcesses).
		Int64("scanned", stats.ScannedProcesses).
		Int64("matched", stats.MatchedProcesses).
		Int64("errors", stats.ErrorProcesses).
		Int64("skipped", stats.SkippedProcesses).
		Int64("duration_sec", stats.DurationSec).
		Msg("process scan completed")

	if enumErr != nil {
		return fmt.Errorf("error enumerating processes: %w", enumErr)
	}
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(GlobalConfig.TimingSettings.CompleteProcessScanTimeoutMin)*time.Minute)
	defer cancel()

	if err := scanner.scanAllProcesses(ctx); err != nil {
		logger.Error().Err(err).Msg("process scan failed")
	}
}
