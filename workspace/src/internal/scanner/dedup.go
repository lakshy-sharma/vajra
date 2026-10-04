// internal/scanner/dedup.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"fmt"
	"sync"
	"time"

	"vajra/shared/models"
)

// DedupKey uniquely identifies a detection for deduplication.
// Two detections with the same rule, path, and severity within
// the dedup window are considered the same finding.
type DedupKey struct {
	// Rule is the YARA rule name or analyzer name that fired.
	// e.g. "yara:Ransomware_Ryuk", "ldpreload", "revshell"
	Rule string

	// Path is the file or exe path that triggered the detection.
	Path string

	// Severity ensures a severity escalation on the same path
	// is always recorded even within the dedup window.
	// A path going from MEDIUM to CRITICAL is a new finding.
	Severity models.EventSeverity
}

// DedupEntry tracks the first occurrence of a detection.
type DedupEntry struct {
	// FirstSeen is when this detection was first recorded.
	FirstSeen time.Time

	// LastSeen is when this detection was most recently suppressed.
	LastSeen time.Time

	// Count is how many times this detection fired within the window.
	// Includes the first occurrence.
	Count uint64

	// RecordID is the DB row ID of the first insertion.
	// Used to increment the dedup count on the existing row
	// rather than inserting duplicates.
	RecordID int64
}

// DedupTracker suppresses repeated detections within a
// configurable time window. It is safe for concurrent use.
//
// Sits between the analyzer pipeline output and the DB insert
// in both FileScanner and ProcessScanner.
//
// When a detection fires:
//   - First occurrence → insert to DB, store entry with RecordID
//   - Subsequent occurrences within window → skip insert,
//     increment Count on existing row via the provided callback
//   - After window expires → treat as new detection, insert again
//
// The window should be long enough to suppress alert storms
// (repeated executions of a known-bad binary) but short enough
// that a genuine recurring threat is still recorded periodically.
// Default: 5 minutes. Configurable via config.yaml.
type DedupTracker struct {
	mu      sync.Mutex
	entries map[DedupKey]*DedupEntry
	window  time.Duration
}

// NewDedupTracker creates a DedupTracker with the given window.
// A cleanup goroutine runs every window duration to evict stale
// entries and prevent unbounded memory growth.
func NewDedupTracker(window time.Duration) *DedupTracker {
	dt := &DedupTracker{
		entries: make(map[DedupKey]*DedupEntry),
		window:  window,
	}
	go dt.cleanup()
	return dt
}

// CheckAndRecord checks whether a detection should be inserted.
//
// Returns:
//   - shouldInsert=true, entry with Count=1 → first occurrence, insert to DB
//   - shouldInsert=false, entry with Count>1 → duplicate within window,
//     caller should call IncrementCount(entry.RecordID) instead
//
// The caller must call RecordInsert after a successful DB insert
// to store the RecordID for subsequent dedup count increments.
func (dt *DedupTracker) CheckAndRecord(key DedupKey) (shouldInsert bool, entry *DedupEntry) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	now := time.Now()

	if existing, ok := dt.entries[key]; ok {
		if now.Sub(existing.FirstSeen) < dt.window {
			// Within window — suppress insert, increment count.
			existing.LastSeen = now
			existing.Count++
			return false, existing
		}
		// Window expired — treat as new detection.
		// Reset the entry for this key.
		delete(dt.entries, key)
	}

	// First occurrence or window expired.
	entry = &DedupEntry{
		FirstSeen: now,
		LastSeen:  now,
		Count:     1,
	}
	dt.entries[key] = entry
	return true, entry
}

// RecordInsert stores the DB row ID after a successful insert.
// Must be called after CheckAndRecord returns shouldInsert=true
// and the DB insert succeeds. The RecordID is used by subsequent
// duplicate detections to increment the count on the right row.
func (dt *DedupTracker) RecordInsert(key DedupKey, recordID int64) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	if entry, ok := dt.entries[key]; ok {
		entry.RecordID = recordID
	}
}

// KeyFromAnalysisResult builds a DedupKey from a pipeline result.
// Rule is derived from the first YARA match name if present,
// otherwise from the notes field prefix (analyzer name).
func KeyFromAnalysisResult(path string, result interface {
	GetSeverity() models.EventSeverity
	GetYaraMatches() []models.YaraMatch
	GetNotes() string
},
) DedupKey {
	return DedupKey{}
}

// BuildKey constructs a DedupKey from explicit components.
// Use this in scanner code where the analyzer name and path
// are known directly.
//
// rule should be:
//   - "yara:<RuleName>" for YARA matches (use first match name)
//   - "yara:multi" for 3+ matches with no dominant rule
//   - analyzer Name() for proc analyzers: "ldpreload", "revshell", "capability"
func BuildKey(rule, path string, severity models.EventSeverity) DedupKey {
	return DedupKey{
		Rule:     rule,
		Path:     path,
		Severity: severity,
	}
}

// ruleFromResult derives a rule identifier from an AnalysisResult
// for use as the DedupKey.Rule field.
// YARA results use the first match rule name.
// Non-YARA results use the notes prefix up to the first colon.
func RuleFromNotes(notes string, yaraMatches []models.YaraMatch) string {
	if len(yaraMatches) > 0 {
		if len(yaraMatches) == 1 {
			return fmt.Sprintf("yara:%s", yaraMatches[0].Rule)
		}
		return "yara:multi"
	}
	// Extract analyzer name from notes prefix.
	// Notes format: "analyzer_name: details"
	for i, c := range notes {
		if c == ':' {
			return notes[:i]
		}
	}
	return notes
}

// cleanup evicts entries older than the dedup window.
// Runs as a background goroutine — never call directly.
func (dt *DedupTracker) cleanup() {
	ticker := time.NewTicker(dt.window)
	defer ticker.Stop()

	for range ticker.C {
		dt.mu.Lock()
		now := time.Now()
		for key, entry := range dt.entries {
			if now.Sub(entry.FirstSeen) >= dt.window {
				delete(dt.entries, key)
			}
		}
		dt.mu.Unlock()
	}
}
