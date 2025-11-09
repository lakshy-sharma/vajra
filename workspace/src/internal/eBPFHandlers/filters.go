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
package eBPFHandlers

import (
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"vajra/internal/utilities"
)

// Path and extension based filtering.
// =====================================

// Exclusion Filter contains filters supplied by users for performing filtering of events not to be scanned.
type ExclusionFilter struct {
	excludePaths      []string
	excludeExtensions []string
	excludePatterns   []string
	mu                sync.RWMutex
}

// NewPathFilter creates a new path filter with default exclusions
func NewExclusionFilter(config *utilities.Config) *ExclusionFilter {
	return &ExclusionFilter{
		excludePaths:      config.ScanSettings.ExclusionRules.ExcludePaths,
		excludeExtensions: config.ScanSettings.ExclusionRules.ExcludeExtensions,
		excludePatterns:   config.ScanSettings.ExclusionRules.ExcludePatterns,
	}
}

// ShouldScan determines if a file path should be scanned
func (ef *ExclusionFilter) ShouldScan(filePath string) bool {
	ef.mu.RLock()
	defer ef.mu.RUnlock()

	// Check if path contains any excluded directories
	for _, excludePath := range ef.excludePaths {
		if strings.Contains(filePath, excludePath) {
			return false
		}
	}

	// Check file extension
	ext := filepath.Ext(filePath)
	for _, excludeExt := range ef.excludeExtensions {
		if ext == excludeExt {
			return false
		}
	}

	// Check patterns (for language servers, etc.)
	for _, pattern := range ef.excludePatterns {
		if strings.Contains(filePath, pattern) {
			return false
		}
	}

	return true
}

// AddExcludePath adds a path to the exclusion list
func (ef *ExclusionFilter) AddExcludePath(path string) {
	ef.mu.Lock()
	defer ef.mu.Unlock()
	ef.excludePaths = append(ef.excludePaths, path)
}

// Recent Scan Filtering logic. (Dont rescan files)
// ===================================

// RecentScanTracker prevents duplicate scans of the same file
type RecentScanTracker struct {
	scans map[string]time.Time
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewRecentScanTracker creates a new scan tracker
func NewRecentScanTracker(ttl time.Duration) *RecentScanTracker {
	rst := &RecentScanTracker{
		scans: make(map[string]time.Time),
		ttl:   ttl,
	}

	// Start cleanup goroutine
	go rst.cleanup()

	return rst
}

// WasRecentlyScanned checks if a file was recently scanned
func (rst *RecentScanTracker) WasRecentlyScanned(filePath string, fileHash string) bool {
	rst.mu.RLock()
	defer rst.mu.RUnlock()

	// Use hash if available, otherwise use path
	key := fileHash
	if key == "" {
		key = filePath
	}

	if lastScan, exists := rst.scans[key]; exists {
		return time.Since(lastScan) < rst.ttl
	}

	return false
}

// MarkScanned marks a file as scanned
func (rst *RecentScanTracker) MarkScanned(filePath string, fileHash string) {
	rst.mu.Lock()
	defer rst.mu.Unlock()

	key := fileHash
	if key == "" {
		key = filePath
	}

	rst.scans[key] = time.Now()
}

// cleanup removes old entries periodically
func (rst *RecentScanTracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rst.mu.Lock()
		now := time.Now()
		for key, lastScan := range rst.scans {
			if now.Sub(lastScan) > rst.ttl {
				delete(rst.scans, key)
			}
		}
		rst.mu.Unlock()
	}
}

// Process filtering (Dont scan trusted processes)
// ============================
// ProcessFilter filters events by process name
type ProcessFilter struct {
	trustedProcesses []string
	mu               sync.RWMutex
}

// NewProcessFilter creates a new process filter
func NewProcessFilter(config *utilities.Config) *ProcessFilter {
	return &ProcessFilter{
		trustedProcesses: config.ScanSettings.ExclusionRules.ExcludeProcesses,
	}
}

// IsTrusted checks if a process is trusted
func (pf *ProcessFilter) IsTrusted(processName string) bool {
	pf.mu.RLock()
	defer pf.mu.RUnlock()
	return slices.Contains(pf.trustedProcesses, processName)
}

// ShouldReduceMonitoring determines if monitoring should be reduced for this process
func (pf *ProcessFilter) ShouldReduceMonitoring(processName string) bool {
	// Trusted processes get reduced monitoring (only scan executables)
	return pf.IsTrusted(processName)
}
