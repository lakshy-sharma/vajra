/*
Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.
You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
)

const (
	// Debounce window to avoid scanning files being edited
	debounceWindow = 3 * time.Second

	// Maximum file size (100 MB)
	maxRealtimeFileSize = 100 * 1024 * 1024

	// Scan queue buffer size
	scanQueueSize = 100

	// Number of concurrent scan workers for file watcher
	watcherScanWorkers = 2
)

// FileEvent represents a debounced filesystem event
type FileEvent struct {
	Path      string
	Operation fsnotify.Op
	Timestamp time.Time
}

// FileWatcher manages real-time filesystem monitoring and scanning
type FileWatcher struct {
	watcher *fsnotify.Watcher
	scanner *FileScanner
	logger  *zerolog.Logger

	// Debouncing mechanism
	pendingEvents map[string]*FileEvent
	eventMutex    sync.Mutex
	eventTimer    *time.Timer

	// Scan queue and workers
	scanQueue chan FileEvent
	workerWG  sync.WaitGroup

	// File hash cache to avoid rescanning unchanged files
	hashCache  map[string]string
	cacheMutex sync.RWMutex

	// Skip list for file extensions and directories
	skipExtensions map[string]bool
	skipDirs       map[string]bool

	ctx    context.Context
	cancel context.CancelFunc
}

// NewFileWatcher creates a new file watcher with integrated scanner
func NewFileWatcher(scanner *FileScanner, logger *zerolog.Logger) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	fw := &FileWatcher{
		watcher:        watcher,
		scanner:        scanner,
		logger:         logger,
		pendingEvents:  make(map[string]*FileEvent),
		scanQueue:      make(chan FileEvent, scanQueueSize),
		hashCache:      make(map[string]string),
		skipExtensions: initSkipExtensions(),
		skipDirs:       initSkipDirectories(),
		ctx:            ctx,
		cancel:         cancel,
	}

	return fw, nil
}

// initSkipExtensions returns file extensions that should not be scanned
func initSkipExtensions() map[string]bool {
	return map[string]bool{
		// Media files
		".mp4": true, ".avi": true, ".mkv": true, ".mov": true, ".wmv": true,
		".mp3": true, ".wav": true, ".flac": true, ".aac": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".svg": true, ".ico": true, ".webp": true,

		// Archives (scan separately with specialized tools)
		".iso": true, ".img": true, ".vmdk": true, ".vdi": true,

		// Database files (typically large, low risk)
		".db": true, ".sqlite": true, ".mdb": true,

		// Log files (handle separately with log analysis)
		".log": true,

		// Temporary files
		".tmp": true, ".temp": true, ".swp": true, ".bak": true,
	}
}

// initSkipDirectories returns directories that should be excluded
func initSkipDirectories() map[string]bool {
	return map[string]bool{
		".git":         true,
		".svn":         true,
		"node_modules": true,
		".cache":       true,
		"__pycache__":  true,
		".venv":        true,
		"venv":         true,
	}
}

// shouldSkipFile determines if a file should be skipped based on various criteria
func (fw *FileWatcher) shouldSkipFile(path string) (bool, string) {
	// Check if file still exists (might have been deleted)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, "file no longer exists"
		}
		return true, "cannot stat file"
	}

	// Skip directories
	if info.IsDir() {
		return true, "is directory"
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(path))
	if fw.skipExtensions[ext] {
		return true, "extension in skip list"
	}

	// Check if in skip directory
	dir := filepath.Dir(path)
	for skipDir := range fw.skipDirs {
		if strings.Contains(dir, skipDir) {
			return true, "in skip directory"
		}
	}

	// Check file size
	if info.Size() > maxRealtimeFileSize {
		fw.logger.Warn().
			Str("file", path).
			Int64("size", info.Size()).
			Msg("file too large for real-time scanning, scheduling for batch scan")
		return true, "exceeds size limit"
	}

	// Check if file is still being written (size is 0 or very recent modification)
	if info.Size() == 0 {
		return true, "empty file"
	}

	// Skip if modified in last 500ms (likely still being written)
	if time.Since(info.ModTime()) < 500*time.Millisecond {
		return true, "file still being written"
	}

	return false, ""
}

// calculateFileHash computes SHA256 hash of a file
func calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
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

// hasFileChanged checks if file hash has changed since last scan
func (fw *FileWatcher) hasFileChanged(path string) (bool, error) {
	newHash, err := calculateFileHash(path)
	if err != nil {
		return true, err // Assume changed if we can't compute hash
	}

	fw.cacheMutex.RLock()
	oldHash, exists := fw.hashCache[path]
	fw.cacheMutex.RUnlock()

	if !exists || oldHash != newHash {
		// Update cache
		fw.cacheMutex.Lock()
		fw.hashCache[path] = newHash
		fw.cacheMutex.Unlock()
		return true, nil
	}

	return false, nil
}

// processEvent handles a debounced filesystem event
func (fw *FileWatcher) processEvent(event FileEvent) {
	// Check if we should skip this file
	if skip, reason := fw.shouldSkipFile(event.Path); skip {
		fw.logger.Debug().
			Str("file", event.Path).
			Str("reason", reason).
			Msg("skipping file scan")
		return
	}

	// Check if file has actually changed (hash-based)
	changed, err := fw.hasFileChanged(event.Path)
	if err != nil {
		fw.logger.Debug().Err(err).Str("file", event.Path).Msg("error checking file hash")
	} else if !changed {
		fw.logger.Debug().Str("file", event.Path).Msg("file unchanged (hash match), skipping scan")
		return
	}

	// Scan the file
	fw.logger.Info().
		Str("file", event.Path).
		Str("operation", event.Operation.String()).
		Msg("scanning file")

	result := fw.scanner.scanFile(fw.ctx, event.Path)

	// Handle scan results
	if result.Error != nil {
		fw.logger.Error().
			Err(result.Error).
			Str("file", event.Path).
			Msg("scan failed")
		return
	}

	if len(result.Matches) > 0 {
		// THREAT DETECTED!
		fw.logger.Warn().
			Str("file", event.Path).
			Int("matches", len(result.Matches)).
			Msg("THREAT DETECTED - YARA matches found")

		// Log each match
		for _, match := range result.Matches {
			fw.logger.Warn().
				Str("file", event.Path).
				Str("rule", match.Rule).
				Str("namespace", match.Namespace).
				Msg("YARA rule matched")
		}

		// Save to database
		if err := fw.scanner.saveFileScanResults([]YaraScanResult{result}); err != nil {
			fw.logger.Error().Err(err).Msg("failed to save scan result")
		}

		// TODO: Trigger alert/quarantine here
		// fw.handleThreat(result)

	} else {
		fw.logger.Debug().
			Str("file", event.Path).
			Msg("file clean - no threats detected")
	}
}

// scanWorker processes files from the scan queue
func (fw *FileWatcher) scanWorker() {
	defer fw.workerWG.Done()

	for {
		select {
		case <-fw.ctx.Done():
			return
		case event, ok := <-fw.scanQueue:
			if !ok {
				return
			}
			fw.processEvent(event)
		}
	}
}

// debounceTimer triggers processing of pending events after debounce window
func (fw *FileWatcher) debounceTimer() {
	fw.eventMutex.Lock()
	defer fw.eventMutex.Unlock()

	// Process all pending events
	for path, event := range fw.pendingEvents {
		select {
		case fw.scanQueue <- *event:
			fw.logger.Debug().Str("file", path).Msg("queued file for scanning")
		case <-fw.ctx.Done():
			return
		default:
			fw.logger.Warn().Str("file", path).Msg("scan queue full, dropping event")
		}
	}

	// Clear pending events
	fw.pendingEvents = make(map[string]*FileEvent)
}

// handleEvent adds an event to the debounce queue
func (fw *FileWatcher) handleEvent(event fsnotify.Event) {
	fw.eventMutex.Lock()
	defer fw.eventMutex.Unlock()

	// Update or add event to pending map
	fw.pendingEvents[event.Name] = &FileEvent{
		Path:      event.Name,
		Operation: event.Op,
		Timestamp: time.Now(),
	}

	// Reset debounce timer
	if fw.eventTimer != nil {
		fw.eventTimer.Stop()
	}
	fw.eventTimer = time.AfterFunc(debounceWindow, fw.debounceTimer)
}

// addRecursive recursively adds all subdirectories to the watcher
func (fw *FileWatcher) addRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			// Check if directory should be skipped
			dirName := filepath.Base(path)
			if fw.skipDirs[dirName] {
				fw.logger.Debug().Str("dir", path).Msg("skipping directory")
				return filepath.SkipDir
			}

			// Add directory to watcher
			if err := fw.watcher.Add(path); err != nil {
				fw.logger.Error().Err(err).Str("dir", path).Msg("failed to add directory to watcher")
				return nil // Continue despite errors
			}
			fw.logger.Debug().Str("dir", path).Msg("watching directory")
		}
		return nil
	})
}

// Start begins the file watching daemon
func (fw *FileWatcher) Start(targetDir string) error {
	// Add target directory and all subdirectories recursively
	if err := fw.addRecursive(targetDir); err != nil {
		return err
	}

	fw.logger.Info().
		Str("directory", targetDir).
		Int("workers", watcherScanWorkers).
		Msg("file watcher started")

	// Start scan workers
	for i := 0; i < watcherScanWorkers; i++ {
		fw.workerWG.Add(1)
		go fw.scanWorker()
	}

	// Main event loop
	for {
		select {
		case <-fw.ctx.Done():
			fw.logger.Info().Msg("file watcher shutting down")
			return nil

		case event, ok := <-fw.watcher.Events:
			if !ok {
				return nil
			}

			// Log all events at debug level
			fw.logger.Debug().
				Str("file", event.Name).
				Str("op", event.Op.String()).
				Msg("filesystem event received")

			// Process relevant events
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				fw.handleEvent(event)
			} else if event.Has(fsnotify.Rename) {
				// Handle rename as a new file creation
				fw.handleEvent(event)
			} else if event.Has(fsnotify.Chmod) {
				// Chmod on executable files might indicate malicious activity
				if strings.HasSuffix(event.Name, ".exe") ||
					strings.HasSuffix(event.Name, ".sh") ||
					strings.HasSuffix(event.Name, ".bat") {
					fw.logger.Info().
						Str("file", event.Name).
						Msg("executable permission changed, queuing for scan")
					fw.handleEvent(event)
				}
			}
			// REMOVE events are ignored - no need to scan deleted files

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return nil
			}
			fw.logger.Error().Err(err).Msg("filesystem watcher error")
		}
	}
}

// Stop gracefully shuts down the file watcher
func (fw *FileWatcher) Stop() error {
	fw.logger.Info().Msg("stopping file watcher")

	// Cancel context
	fw.cancel()

	// Stop debounce timer
	fw.eventMutex.Lock()
	if fw.eventTimer != nil {
		fw.eventTimer.Stop()
	}
	fw.eventMutex.Unlock()

	// Close scan queue
	close(fw.scanQueue)

	// Wait for workers to finish
	fw.workerWG.Wait()

	// Close watcher
	if err := fw.watcher.Close(); err != nil {
		return err
	}

	fw.logger.Info().Msg("file watcher stopped")
	return nil
}
