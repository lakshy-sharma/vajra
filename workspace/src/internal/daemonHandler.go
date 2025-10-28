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
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// runFileWatcher starts the file watcher in a goroutine-safe way.
func runFileWatcher(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, errChan chan<- error) {
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
	fileWatcher, err := NewFileWatcher(ctx, cancel, scanner, logger.Logger)
	if err != nil {
		errChan <- err
		return
	}
	defer fileWatcher.Stop()

	logger.Info().Msg("starting filesystem monitor")
	// Start watching (blocks until stopped)
	if err := fileWatcher.Start(GlobalConfig.ScanSettings.TargetDirectory); err != nil {
		if ctx.Err() == nil {
			// Only report error if not from graceful shutdown
			errChan <- err
		}
	}
}

// runProcessMonitor starts the process monitor in a goroutine-safe way.
func runProcessMonitor(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, errChan chan<- error) {
	defer wg.Done()

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
	monitor, err := NewProcessMonitor(ctx, cancel, scanner, logger.Logger)
	if err != nil {
		errChan <- err
		return
	}
	defer monitor.Stop()

	logger.Info().Msg("starting process monitor")
	if err := monitor.Start(); err != nil {
		if ctx.Err() == nil {
			errChan <- err
		}
	}
}

// runAPIServer starts the API server in a goroutine-safe way
func runAPIServer(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, errChan chan<- error) {
	defer wg.Done()

	server := NewAPIServer(ctx, cancel, DB)

	// Start server in goroutine
	go func() {
		address := fmt.Sprintf("%s:%d",
			GlobalConfig.APIServerSettings.Host,
			GlobalConfig.APIServerSettings.Port)
		if err := server.Start(address); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("API server error: %w", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	if err := server.Stop(); err != nil {
		logger.Error().Err(err).Msg("error stopping API server")
	}
}

// startDaemonMode runs both file and process monitoring with coordinated shutdown.
func startDaemonMode() {
	// Startup code
	//===============================
	logger.Info().Msg("starting daemon mode")

	// Check privileges
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		logger.Warn().Msg("running without root privileges. process scanning will be limited to polling mode")
	}

	// Define wait groups and context for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup

	// Error channel for fatal errors
	errChan := make(chan error, 2)

	// Start file watcher
	wg.Add(1)
	go runFileWatcher(ctx, cancel, &wg, errChan)

	// Start process monitor
	wg.Add(1)
	go runProcessMonitor(ctx, cancel, &wg, errChan)

	// Start the api server
	wg.Add(1)
	go runAPIServer(ctx, cancel, &wg, errChan)

	// Closure code
	//============================
	// Wait for shutdown signal or error
	logger.Info().Msg("daemon mode started, press Ctrl+C to stop")
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

	// Remove context and wait for daemons to close
	logger.Info().Msg("shutting down daemons...")
	cancel()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info().Msg("all daemons exited successfully")
	case <-time.After(time.Duration(GlobalConfig.TimingSettings.ShutdownTimeoutSec) * time.Second):
		logger.Warn().Msg("daemons crossed shutdown timeout, forcing exit")
	}
}
