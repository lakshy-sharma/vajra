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
	debounceWindow      = 3 * time.Second
	maxRealtimeFileSize = 100 * 1024 * 1024
)

type FileEvent struct {
	Path      string
	Operation fsnotify.Op
	Timestamp time.Time
}

type FileWatcher struct {
	watcher        *fsnotify.Watcher
	scanner        *FileScanner
	logger         *zerolog.Logger
	pendingEvents  map[string]*FileEvent
	eventMutex     sync.Mutex
	eventTimer     *time.Timer
	scanQueue      chan FileEvent
	workerWG       sync.WaitGroup
	hashCache      map[string]string
	cacheMutex     sync.RWMutex
	skipExtensions map[string]bool
	skipDirs       map[string]bool
	ctx            context.Context
	cancel         context.CancelFunc
}

func initSkipExtensions() map[string]bool {
	return map[string]bool{
		".mp4": true, ".avi": true, ".mkv": true, ".mov": true, ".wmv": true,
		".mp3": true, ".wav": true, ".flac": true, ".aac": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".svg": true, ".ico": true, ".webp": true,
		".iso": true, ".img": true, ".vmdk": true, ".vdi": true,
		".db": true, ".sqlite": true, ".mdb": true,
		".log": true,
		".tmp": true, ".temp": true, ".swp": true, ".bak": true,
	}
}

func initSkipDirectories() map[string]bool {
	return map[string]bool{
		".git": true, ".svn": true, "node_modules": true, ".cache": true,
		"__pycache__": true, ".venv": true, "venv": true,
	}
}

func NewFileWatcher(ctx context.Context, cancel context.CancelFunc, scanner *FileScanner, logger *zerolog.Logger) (*FileWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &FileWatcher{
		watcher:        w,
		scanner:        scanner,
		logger:         logger,
		pendingEvents:  make(map[string]*FileEvent),
		scanQueue:      make(chan FileEvent, GlobalConfig.PerformanceSettings.FileScanBufferSize),
		hashCache:      make(map[string]string),
		skipExtensions: initSkipExtensions(),
		skipDirs:       initSkipDirectories(),
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

func (fw *FileWatcher) Start(targetDir string) error {
	if err := fw.addRecursive(targetDir); err != nil {
		return err
	}

	numWorkers := getMaxWorkers()
	fw.logger.Info().Str("directory", targetDir).Int("workers", numWorkers).Msg("file watcher started")

	for i := 0; i < numWorkers; i++ {
		fw.workerWG.Add(1)
		go fw.scanWorker()
	}

	for {
		select {
		case <-fw.ctx.Done():
			fw.logger.Info().Msg("file watcher shutting down")
			return nil

		case event, ok := <-fw.watcher.Events:
			if !ok {
				return nil
			}

			fw.logger.Debug().Str("file", event.Name).Str("op", event.Op.String()).Msg("filesystem event received")

			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Chmod) {
				if event.Has(fsnotify.Chmod) {
					fw.logger.Info().Str("file", event.Name).Msg("executable permission changed, queuing for scan")
				}
				fw.handleEvent(event)
			}

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return nil
			}
			fw.logger.Error().Err(err).Msg("filesystem watcher error")
		}
	}
}

func (fw *FileWatcher) Stop() error {
	fw.logger.Info().Msg("stopping file watcher")
	fw.cancel()

	fw.eventMutex.Lock()
	if fw.eventTimer != nil {
		fw.eventTimer.Stop()
		fw.eventTimer = nil
	}
	fw.eventMutex.Unlock()

	close(fw.scanQueue)
	fw.workerWG.Wait()

	if err := fw.watcher.Close(); err != nil {
		return err
	}

	fw.logger.Info().Msg("file watcher stopped")
	return nil
}

func (fw *FileWatcher) handleEvent(event fsnotify.Event) {
	fw.eventMutex.Lock()
	defer fw.eventMutex.Unlock()

	fw.pendingEvents[event.Name] = &FileEvent{
		Path:      event.Name,
		Operation: event.Op,
		Timestamp: time.Now(),
	}

	if fw.eventTimer != nil {
		fw.eventTimer.Stop()
	}
	fw.eventTimer = time.AfterFunc(debounceWindow, fw.debounceTimer)
}

func (fw *FileWatcher) debounceTimer() {
	fw.eventMutex.Lock()
	defer fw.eventMutex.Unlock()

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

	fw.pendingEvents = make(map[string]*FileEvent)
}

func (fw *FileWatcher) addRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if fw.skipDirs[filepath.Base(path)] {
				fw.logger.Debug().Str("dir", path).Msg("skipping directory")
				return filepath.SkipDir
			}
			if err := fw.watcher.Add(path); err != nil {
				fw.logger.Error().Err(err).Str("dir", path).Msg("failed to add directory")
			} else {
				fw.logger.Debug().Str("dir", path).Msg("watching directory")
			}
		}
		return nil
	})
}

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

func (fw *FileWatcher) processEvent(event FileEvent) {
	if skip, reason := fw.shouldSkipFile(event.Path); skip {
		fw.logger.Debug().Str("file", event.Path).Str("reason", reason).Msg("skipping file scan")
		return
	}

	if changed, err := fw.hasFileChanged(event.Path); err != nil {
		fw.logger.Debug().Err(err).Str("file", event.Path).Msg("error checking file hash")
		return
	} else if !changed {
		fw.logger.Debug().Str("file", event.Path).Msg("file unchanged, skipping scan")
		return
	}

	fw.logger.Info().Str("file", event.Path).Str("operation", event.Operation.String()).Msg("scanning file")
	result := fw.scanner.scanFile(fw.ctx, event.Path)
	if result.Error != nil {
		fw.logger.Error().Err(result.Error).Str("file", event.Path).Msg("scan failed")
		return
	}

	// Unified logging for matches
	if len(result.Matches) > 0 {
		matchInfo := make([]string, len(result.Matches))
		for i, m := range result.Matches {
			matchInfo[i] = m.Namespace + "/" + m.Rule
		}
		fw.logger.Warn().
			Str("file", event.Path).
			Int("matches", len(result.Matches)).
			Strs("rules", matchInfo).
			Msg("THREAT DETECTED")

		if err := fw.scanner.saveFileScanResults([]YaraScanResult{result}); err != nil {
			fw.logger.Error().Err(err).Str("file", event.Path).Msg("failed to save scan result")
		}
	} else {
		fw.logger.Debug().Str("file", event.Path).Msg("file clean")
	}
}

func (fw *FileWatcher) shouldSkipFile(path string) (bool, string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, "file no longer exists"
		}
		return true, "cannot stat file"
	}

	if info.IsDir() {
		return true, "is directory"
	}

	ext := strings.ToLower(filepath.Ext(path))
	if fw.skipExtensions[ext] {
		return true, "extension in skip list"
	}

	for skipDir := range fw.skipDirs {
		if strings.Contains(filepath.Dir(path), skipDir) {
			return true, "in skip directory"
		}
	}

	size := info.Size()
	modTime := info.ModTime()
	if size == 0 {
		return true, "empty file"
	}
	if size > maxRealtimeFileSize {
		fw.logger.Warn().Str("file", path).Int64("size", size).Msg("file too large, scheduling for batch scan")
		return true, "exceeds size limit"
	}
	if time.Since(modTime) < 500*time.Millisecond {
		return true, "file still being written"
	}

	return false, ""
}

func (fw *FileWatcher) hasFileChanged(path string) (bool, error) {
	newHash, err := calculateFileHash(path)
	if err != nil {
		return true, err
	}

	fw.cacheMutex.RLock()
	oldHash, exists := fw.hashCache[path]
	fw.cacheMutex.RUnlock()

	if !exists || oldHash != newHash {
		fw.cacheMutex.Lock()
		fw.hashCache[path] = newHash
		fw.cacheMutex.Unlock()
		return true, nil
	}
	return false, nil
}

func calculateFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
