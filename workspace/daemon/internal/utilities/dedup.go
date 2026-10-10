// internal/utilities/dedup.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"sync"
	"time"

	"vajra/shared/models"
)

// DedupKey identifies a detection uniquely for suppression purposes.
// Severity is part of the key so an escalation on the same path
// always produces a new record even within the window.
type DedupKey struct {
	Rule     string
	Path     string
	Severity models.EventSeverity
}

// DedupEntry tracks the first occurrence of a detection.
type DedupEntry struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Count     uint64
	RecordID  int64 // DB row ID for dedup count increment
}

// DedupTracker suppresses repeated detections within a configurable
// window. Safe for concurrent use.
type DedupTracker struct {
	mu      sync.Mutex
	entries map[DedupKey]*DedupEntry
	window  time.Duration
}

func NewDedupTracker(window time.Duration) *DedupTracker {
	dt := &DedupTracker{
		entries: make(map[DedupKey]*DedupEntry),
		window:  window,
	}
	go dt.cleanup()
	return dt
}

// CheckAndRecord returns whether this detection should be inserted.
// First occurrence within window: insert. Subsequent: increment count.
// Caller must call RecordInsert after a successful DB insert.
func (dt *DedupTracker) CheckAndRecord(key DedupKey) (shouldInsert bool, entry *DedupEntry) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	now := time.Now()
	if existing, ok := dt.entries[key]; ok {
		if now.Sub(existing.FirstSeen) < dt.window {
			existing.LastSeen = now
			existing.Count++
			return false, existing
		}
		delete(dt.entries, key)
	}

	entry = &DedupEntry{FirstSeen: now, LastSeen: now, Count: 1}
	dt.entries[key] = entry
	return true, entry
}

// RecordInsert stores the DB row ID after a successful insert.
func (dt *DedupTracker) RecordInsert(key DedupKey, recordID int64) {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if entry, ok := dt.entries[key]; ok {
		entry.RecordID = recordID
	}
}

// BuildKey constructs a DedupKey from explicit components.
func BuildKey(rule, path string, severity models.EventSeverity) DedupKey {
	return DedupKey{Rule: rule, Path: path, Severity: severity}
}

// RuleFromMatch derives a dedup rule key from YARA matches or notes.
func RuleFromMatch(notes string, matches []models.YaraMatch) string {
	if len(matches) == 1 {
		return "yara:" + matches[0].Rule
	}
	if len(matches) > 1 {
		return "yara:multi"
	}
	for i, c := range notes {
		if c == ':' {
			return notes[:i]
		}
	}
	return notes
}

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
