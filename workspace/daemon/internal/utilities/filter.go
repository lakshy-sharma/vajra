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
	// Extensions and patterns have no config backing yet; they exist for
	// runtime additions via AddExtension / AddPattern (future extension points).
	return &ExclusionFilter{
		paths: cfg.ScanSettings.ExcludedPaths,
	}
}

func (f *ExclusionFilter) ShouldScan(filePath string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, p := range f.paths {
		// HasPathPrefix guards against /foo/bar matching /foo/barz —
		// strings.Contains would allow that false positive.
		if HasPathPrefix(filePath, p) {
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

// HasPathPrefix reports whether filePath is equal to prefix or is a file
// directly inside it. A plain strings.HasPrefix would match /foo/bar against
// the prefix /foo/b, which is wrong — the check must land on a path separator.
func HasPathPrefix(filePath, prefix string) bool {
	// Normalise so callers need not worry about trailing slashes in config.
	prefix = strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(filePath, prefix) {
		return false
	}
	rest := filePath[len(prefix):]
	return rest == "" || rest[0] == '/'
}

// ProcessFilter gates which processes receive the full content pipeline.
// Trusted processes still run the runtime pipeline — a trusted name
// exhibiting suspicious behaviour is more alarming, not less.
type ProcessFilter struct {
	mu      sync.RWMutex
	trusted []string
}

func NewProcessFilter(cfg *sharedconfig.Config) *ProcessFilter {
	return &ProcessFilter{trusted: cfg.ScanSettings.ExcludedProcesses}
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
	done  chan struct{}
}

func NewRecentScanTracker(ttl time.Duration) *RecentScanTracker {
	rst := &RecentScanTracker{
		scans: make(map[string]time.Time),
		ttl:   ttl,
		done:  make(chan struct{}),
	}
	go rst.cleanup()
	return rst
}

// Stop terminates the background cleanup goroutine.
// Must be called when the tracker is no longer needed to avoid a goroutine leak.
func (rst *RecentScanTracker) Stop() {
	close(rst.done)
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
	// Run at the same cadence as the TTL window — entries expire after one
	// cycle at most, and we avoid running more aggressively than needed.
	ticker := time.NewTicker(rst.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-rst.done:
			return
		case <-ticker.C:
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
}
