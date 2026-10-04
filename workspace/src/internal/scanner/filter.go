// internal/scanner/filter.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"vajra/internal/utilities"
)

// ============================================================
// ExclusionFilter — path, extension, pattern filtering
// ============================================================

type ExclusionFilter struct {
	mu         sync.RWMutex
	paths      []string
	extensions []string
	patterns   []string
}

func NewExclusionFilter(cfg *utilities.Config) *ExclusionFilter {
	return &ExclusionFilter{
		paths:      cfg.ScanSettings.ExclusionRules.ExcludePaths,
		extensions: cfg.ScanSettings.ExclusionRules.ExcludeExtensions,
		patterns:   cfg.ScanSettings.ExclusionRules.ExcludePatterns,
	}
}

// ShouldScan returns true if the path passes all exclusion rules.
func (f *ExclusionFilter) ShouldScan(filePath string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, p := range f.paths {
		if strings.Contains(filePath, p) {
			return false
		}
	}

	ext := filepath.Ext(filePath)
	for _, e := range f.extensions {
		if ext == e {
			return false
		}
	}

	for _, pattern := range f.patterns {
		if strings.Contains(filePath, pattern) {
			return false
		}
	}

	return true
}

func (f *ExclusionFilter) AddPath(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, path)
}

// ============================================================
// ProcessFilter — trusted process list
// ============================================================

type ProcessFilter struct {
	mu      sync.RWMutex
	trusted []string
}

func NewProcessFilter(cfg *utilities.Config) *ProcessFilter {
	return &ProcessFilter{
		trusted: cfg.ScanSettings.ExclusionRules.ExcludeProcesses,
	}
}

// IsTrusted returns true when the process is on the exclusion list.
func (f *ProcessFilter) IsTrusted(processName string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return slices.Contains(f.trusted, processName)
}

// ReduceMonitoring is an alias kept for call-site readability:
// trusted processes only get scanned for executable files.
func (f *ProcessFilter) ReduceMonitoring(processName string) bool {
	return f.IsTrusted(processName)
}

// ============================================================
// RecentScanTracker — deduplication TTL cache
// ============================================================

type RecentScanTracker struct {
	mu    sync.RWMutex
	scans map[string]time.Time
	ttl   time.Duration
}

func NewRecentScanTracker(ttl time.Duration) *RecentScanTracker {
	rst := &RecentScanTracker{
		scans: make(map[string]time.Time),
		ttl:   ttl,
	}
	go rst.cleanup()
	return rst
}

// WasRecentlyScanned returns true if this file/hash was seen
// within the TTL window. Prefers hash as key; falls back to path.
func (rst *RecentScanTracker) WasRecentlyScanned(filePath, fileHash string) bool {
	rst.mu.RLock()
	defer rst.mu.RUnlock()

	key := fileHash
	if key == "" {
		key = filePath
	}

	if t, ok := rst.scans[key]; ok {
		return time.Since(t) < rst.ttl
	}

	return false
}

// MarkScanned records the current time for this file/hash.
func (rst *RecentScanTracker) MarkScanned(filePath, fileHash string) {
	rst.mu.Lock()
	defer rst.mu.Unlock()

	key := fileHash
	if key == "" {
		key = filePath
	}

	rst.scans[key] = time.Now()
}

func (rst *RecentScanTracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rst.mu.Lock()
		now := time.Now()
		for k, t := range rst.scans {
			if now.Sub(t) > rst.ttl {
				delete(rst.scans, k)
			}
		}
		rst.mu.Unlock()
	}
}
