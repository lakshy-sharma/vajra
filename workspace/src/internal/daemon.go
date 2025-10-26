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
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// runFileWatcher starts the file watcher in a goroutine-safe way.
func runFileWatcher(ctx context.Context, wg *sync.WaitGroup, errChan chan<- error) {
	defer wg.Done()

	// Create scanner
	scanner, err := NewFileScanner(
		GlobalConfig.ScanSettings.RulesFilepath,
		filepath.Join(GlobalConfig.GenericSettings.WorkDirectory, "rules"),
		DB,
	)
	if err != nil {
		errChan <- err
		return
	}
	defer scanner.Close()

	// Create file watcher
	fileWatcher, err := NewFileWatcher(scanner, logger.Logger)
	if err != nil {
		errChan <- err
		return
	}
	defer fileWatcher.Stop()

	logger.Info().Msg("file watcher started")

	// Start watching (blocks until stopped)
	if err := fileWatcher.Start(GlobalConfig.ScanSettings.TargetDirectory); err != nil {
		if ctx.Err() == nil {
			// Only report error if not from graceful shutdown
			errChan <- err
		}
	}
}

// runProcessMonitor starts the process monitor in a goroutine-safe way.
func runProcessMonitor(ctx context.Context, wg *sync.WaitGroup, errChan chan<- error) {
	defer wg.Done()

	// Check platform
	if runtime.GOOS != "linux" {
		logger.Warn().Msg("eBPF process monitoring only supported on Linux")
		return
	}

	// Create scanner
	scanner, err := NewProcessScanner(
		GlobalConfig.ScanSettings.RulesFilepath,
		filepath.Join(GlobalConfig.GenericSettings.WorkDirectory, "rules"),
		DB,
	)
	if err != nil {
		errChan <- err
		return
	}
	defer scanner.Close()

	// Create process monitor
	monitor, err := NewProcessMonitor(scanner, logger.Logger)
	if err != nil {
		errChan <- err
		return
	}
	defer monitor.Stop()

	logger.Info().Msg("process monitor started")

	// Start monitoring (blocks until stopped)
	if err := monitor.Start(); err != nil {
		if ctx.Err() == nil {
			// Only report error if not from graceful shutdown
			errChan <- err
		}
	}
}

// startDaemonMode runs both file and process monitoring with coordinated shutdown.
func startDaemonMode() {
	logger.Info().Msg("starting daemon mode - combined file and process monitoring")

	// Check privileges
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		logger.Warn().Msg("running without root privileges - process monitoring may be limited")
	}

	// Setup context for coordinated shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// WaitGroup to track monitoring goroutines
	var wg sync.WaitGroup

	// Error channel for fatal errors
	errChan := make(chan error, 2)

	// Start file watcher
	wg.Add(1)
	go runFileWatcher(ctx, &wg, errChan)

	// Start process monitor
	wg.Add(1)
	go runProcessMonitor(ctx, &wg, errChan)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info().Msg("daemon mode started, press Ctrl+C to stop")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info().
			Str("signal", sig.String()).
			Msg("received shutdown signal, initiating graceful shutdown")
	case err := <-errChan:
		logger.Error().
			Err(err).
			Msg("critical error occurred, initiating shutdown")
	}

	// Initiate graceful shutdown
	logger.Info().Msg("shutting down daemon...")
	cancel()

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info().Msg("daemon stopped successfully")
	case <-time.After(30 * time.Second):
		logger.Warn().Msg("shutdown timeout reached, forcing exit")
	}
}
