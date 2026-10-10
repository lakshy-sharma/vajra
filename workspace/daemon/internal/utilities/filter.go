// internal/utilities/filter.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	sharedconfig "vajra/shared/config"
)

// ExclusionFilter decides whether a file path should be scanned.
// Thread-safe — paths can be added at runtime.
type ExclusionFilter struct {
	mu         sync.RWMutex
	paths      []string
	extensions []string
	patterns   []string
}

func NewExclusionFilter(cfg *sharedconfig.Config) *ExclusionFilter {
	return &ExclusionFilter{
		paths:      cfg.ScanSettings.ExclusionRules.ExcludePaths,
		extensions: cfg.ScanSettings.ExclusionRules.ExcludeExtensions,
		patterns:   cfg.ScanSettings.ExclusionRules.ExcludePatterns,
	}
}

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

// ProcessFilter gates which processes receive the full content pipeline.
// Trusted processes still run the runtime pipeline — a trusted name
// exhibiting suspicious behaviour is more alarming, not less.
type ProcessFilter struct {
	mu      sync.RWMutex
	trusted []string
}

func NewProcessFilter(cfg *sharedconfig.Config) *ProcessFilter {
	return &ProcessFilter{trusted: cfg.ScanSettings.ExclusionRules.ExcludeProcesses}
}

func (f *ProcessFilter) IsTrusted(processName string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return slices.Contains(f.trusted, processName)
}

// RecentScanTracker is a TTL cache that prevents rescanning files
// that were seen within the window. Keyed on hash when available,
// path otherwise — catches in-place binary replacement via QuickHash.
type RecentScanTracker struct {
	mu    sync.RWMutex
	scans map[string]time.Time
	ttl   time.Duration
}

func NewRecentScanTracker(ttl time.Duration) *RecentScanTracker {
	rst := &RecentScanTracker{scans: make(map[string]time.Time), ttl: ttl}
	go rst.cleanup()
	return rst
}

func (rst *RecentScanTracker) WasRecentlyScanned(filePath, fileHash string) bool {
	rst.mu.RLock()
	defer rst.mu.RUnlock()
	key := fileHash
	if key == "" {
		key = filePath
	}
	t, ok := rst.scans[key]
	return ok && time.Since(t) < rst.ttl
}

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
