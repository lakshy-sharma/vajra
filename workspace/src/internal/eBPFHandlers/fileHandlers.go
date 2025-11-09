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
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"vajra/internal/eBPFListeners"
	"vajra/internal/utilities"

	"github.com/hillu/go-yara/v4"
)

// handleMaliciousFile takes action when malicious file is detected
func (eh *EventHandler) handleMaliciousFile(result ScanResult) {
	eh.logger.Error().
		Str("file", result.FilePath).
		Uint32("pid", result.PID).
		Str("comm", result.Comm).
		Int("rule_matches", len(result.Matches)).
		Str("risk_level", result.RiskLevel).
		Msg("MALICIOUS FILE DETECTED")

	// Log matched rules
	for _, match := range result.Matches {
		eh.logger.Error().
			Str("rule", match.Rule).
			Str("namespace", match.Namespace).
			Interface("tags", match.Tags).
			Msg("YARA rule matched")
	}

	// Take configured actions
	// - Quarantine file
	// - Kill process
	// - Alert administrator
	// - Block network connections
	// Implement based on your security policy
}

// calculateFileHash calculates SHA256 hash of a file
func calculateFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// shouldScanFile determines if a file should be scanned based on path/extension
func (eh *EventHandler) shouldScanFile(filename string) bool {
	if filename == "" {
		return false
	}

	// Skip system directories that are typically safe
	skipPrefixes := []string{
		"/proc/",
		"/sys/",
		"/dev/",
	}

	for _, prefix := range skipPrefixes {
		if len(filename) >= len(prefix) && filename[:len(prefix)] == prefix {
			return false
		}
	}

	// Scan executables and scripts
	ext := filepath.Ext(filename)
	scanExtensions := []string{
		"", ".exe", ".elf", ".so", ".ko", // Executables and libraries
		".sh", ".py", ".pl", ".rb", ".js", // Scripts
		".jar", ".class", // Java
	}

	for _, scanExt := range scanExtensions {
		if ext == scanExt {
			return true
		}
	}

	// Scan files in sensitive directories
	sensitiveDirs := []string{
		"/tmp/",
		"/var/tmp/",
		"/home/",
		"/root/",
	}

	for _, dir := range sensitiveDirs {
		if len(filename) >= len(dir) && filename[:len(dir)] == dir {
			return true
		}
	}

	return false
}

// handleFileEvent handles file creation/open events
func (eh *EventHandler) handleFileEvent(event EventContext) {
	fileEvent := event.EventData.(eBPFListeners.FileEvent)
	filename := utilities.ConvertCStringToGo(fileEvent.Filename[:])
	comm := utilities.ConvertCStringToGo(fileEvent.Comm[:])

	// Only scan files in sensitive locations or with suspicious extensions
	if eh.shouldScanFile(filename) {
		eh.logger.Info().
			Uint32("pid", fileEvent.PID).
			Str("file", filename).
			Str("comm", comm).
			Msg("scanning file event")

		eh.scanFile(filename, event.EventType, fileEvent.PID, fileEvent.UID, comm)
	}
}

// scanFile performs YARA scanning on a file
func (eh *EventHandler) scanFile(filePath string, eventType, pid, uid uint32, comm string) {
	// Rate limiting
	<-eh.rateLimiter.C

	// Check cache to avoid duplicate scans
	cacheKey := fmt.Sprintf("%s:%d", filePath, pid)
	if _, exists := eh.scanCache.LoadOrStore(cacheKey, time.Now()); exists {
		return
	}

	// Clean up cache entry after some time
	time.AfterFunc(5*time.Minute, func() {
		eh.scanCache.Delete(cacheKey)
	})

	// Check if file exists and is readable
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		eh.logger.Debug().Err(err).Str("file", filePath).Msg("cannot access file for scanning")
		return
	}

	// Skip very large files to avoid performance issues
	if fileInfo.Size() > 100*1024*1024 { // 100MB
		eh.logger.Debug().Str("file", filePath).Int64("size", fileInfo.Size()).Msg("skipping large file")
		return
	}

	startTime := time.Now()

	// Perform YARA scan
	var matches yara.MatchRules
	err = eh.yaraRules.ScanFile(filePath, 0, 30*time.Second, &matches)

	scanDuration := time.Since(startTime)

	if err != nil {
		eh.logger.Error().
			Err(err).
			Str("file", filePath).
			Msg("YARA scan failed")
		return
	}

	// Process scan results
	result := ScanResult{
		FilePath:    filePath,
		EventType:   eventType,
		PID:         pid,
		UID:         uid,
		Comm:        comm,
		Matches:     matches,
		ScanTime:    time.Now(),
		IsMalicious: len(matches) > 0,
		RiskLevel:   eh.calculateRiskLevel(matches),
	}

	if result.IsMalicious {
		eh.handleMaliciousFile(result)
	}

	// Log scan result
	eh.logger.Info().
		Str("file", filePath).
		Uint32("pid", pid).
		Str("comm", comm).
		Int("matches", len(matches)).
		Dur("scan_duration", scanDuration).
		Bool("malicious", result.IsMalicious).
		Str("risk_level", result.RiskLevel).
		Msg("file scanned")

	// Store result in database if configured
	if eh.dbHandler != nil {
		eh.storeScanResult(result)
	}
}
