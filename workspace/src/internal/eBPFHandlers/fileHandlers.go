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
	"encoding/hex"
	"fmt"
	"io"
	"os"
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

// isExecutableFile checks if a file is likely an executable based on permissions and magic bytes
func isExecutableFile(filePath string, fileInfo os.FileInfo) bool {
	// Check if executable bit is set
	if fileInfo.Mode()&0111 != 0 {
		// Verify with magic bytes to confirm it's actually executable
		return hasExecutableMagic(filePath)
	}

	return false
}

// hasExecutableMagic checks file magic bytes to determine if it's executable
func hasExecutableMagic(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read first 4 bytes (magic number)
	magic := make([]byte, 4)
	n, err := file.Read(magic)
	if err != nil || n < 4 {
		return false
	}

	// ELF (Linux/Unix executables): 0x7f 'E' 'L' 'F'
	if magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return true
	}

	// PE (Windows executables): 'M' 'Z'
	if magic[0] == 'M' && magic[1] == 'Z' {
		return true
	}

	// Mach-O (macOS executables): Various formats
	// 32-bit: 0xfeedface, 0xcefaedfe
	// 64-bit: 0xfeedfacf, 0xcffaedfe
	if (magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && (magic[3] == 0xce || magic[3] == 0xcf)) ||
		(magic[0] == 0xce && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) ||
		(magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) {
		return true
	}

	// Shebang scripts: #!
	if magic[0] == '#' && magic[1] == '!' {
		return true
	}

	return false
}

// quickFileHash generates a quick hash of a file for deduplication
func quickFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	// Only hash first 8KB for speed
	buffer := make([]byte, 8192)
	n, _ := file.Read(buffer)
	if n > 0 {
		hash.Write(buffer[:n])
	}

	return hex.EncodeToString(hash.Sum(nil))
}

// calculateFileHash calculates full SHA256 hash
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// shouldScanFile determines if a file should be scanned based on multiple criteria
func (eh *EventHandler) shouldScanFile(filePath string, processName string, eventType uint32) (bool, string) {
	// Check if path should be excluded
	if !eh.exclusionFilter.ShouldScan(filePath) {
		return false, "path_excluded"
	}

	// Check if file exists and is accessible
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false, "file_not_accessible"
	}

	// Skip directories
	if fileInfo.IsDir() {
		return false, "is_directory"
	}

	// Skip very small files (likely temp/cache)
	if fileInfo.Size() < 10 {
		return false, "too_small"
	}

	// Skip very large files (> 100MB) for performance
	if fileInfo.Size() > 100*1024*1024 {
		return false, "too_large"
	}

	// For trusted processes, only scan files with executable permissions and magic bytes
	if eh.processFilter.ShouldReduceMonitoring(processName) {
		if !isExecutableFile(filePath, fileInfo) {
			return false, "trusted_process_non_executable"
		}
	}

	// For all other files, check if they're executable before scanning
	// This prevents scanning random data files, text files, etc.
	if !isExecutableFile(filePath, fileInfo) {
		// Only scan non-executables if they're in suspicious locations or from untrusted processes
		if eh.processFilter.IsTrusted(processName) {
			return false, "non_executable_trusted_source"
		}
	}

	// Check if recently scanned
	fileHash := quickFileHash(filePath)
	if eh.recentScans.WasRecentlyScanned(filePath, fileHash) {
		return false, "recently_scanned"
	}

	return true, ""
}

// handleFileEvent processes file open/create events with intelligent filtering
func (eh *EventHandler) handleFileEvent(event EventContext) {
	fileEvent, ok := event.EventData.(eBPFListeners.FileEvent)
	if !ok {
		return
	}

	filePath := utilities.ConvertCStringToGo(fileEvent.Filename[:])
	processName := utilities.ConvertCStringToGo(fileEvent.Comm[:])

	// Apply intelligent filtering
	shouldScan, reason := eh.shouldScanFile(filePath, processName, event.EventType)
	if !shouldScan {
		eh.logger.Debug().
			Str("file", filePath).
			Str("process_name", processName).
			Str("rejection_reason", reason).
			Msg("file scan skipped")
		return
	}

	eh.logger.Info().
		Str("file", filePath).
		Str("process_name", processName).
		Uint32("pid", fileEvent.PID).
		Msg("scanning file event")

	// Rate limiting
	<-eh.rateLimiter.C

	// Perform YARA scan
	eh.scanFile(filePath, event.EventType, fileEvent.PID, fileEvent.UID, processName)
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
