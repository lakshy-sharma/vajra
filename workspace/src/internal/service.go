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
	"sync"
	"syscall"
	"time"
	"vajra/internal/database"
	"vajra/internal/eBPFHandlers"
	"vajra/internal/eBPFListeners"
	"vajra/internal/jobs"
	"vajra/internal/utilities"

	"github.com/rs/zerolog"
)

// startServiceMode runs the EDR in continuous monitoring mode
func startServiceMode(logger *zerolog.Logger, config *utilities.Config, dbHandler *database.DBHandler) {
	logger.Info().Msg("starting service mode")

	// Create the eBPF handler for processing events from eBPF.
	eventHandler, err := eBPFHandlers.NewEventHandler(logger, config, dbHandler)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create eBPF event handler")
	}
	defer eventHandler.Stop()

	// Create and start eBPF event generator to capture eBPF events.
	gen, err := eBPFListeners.NewEventGenerator(eventHandler.EventListener)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create eBPF event generator")
	}
	defer gen.Stop()
	if err := gen.Start(); err != nil {
		logger.Fatal().Err(err).Msg("failed to start event generator")
	}
	logger.Info().Msg("eBPF monitoring started with YARA scanning enabled")

	// Define wait groups and context with a cancel function
	// for performing clean shutdown.
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal channels for stopping code on events.
	errChan := make(chan error, 2)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// TODO
	// Start periodic full system scans

	// Start database cleanup task
	wg.Add(1)
	go jobs.RunDBCleanup(ctx, &wg, logger, dbHandler, config)
	wg.Add(1)
	go jobs.RunAutorunScan(ctx, &wg, logger, dbHandler, config)

	logger.Info().Msg("service mode active, press Ctrl+C to stop")

	// Wait for shutdown signal
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

	// Shutdown sequence
	logger.Info().Msg("shutting down services...")
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info().Msg("all services stopped successfully")
	case <-time.After(time.Duration(config.TimingSettings.ShutdownTimeoutSec) * time.Second):
		logger.Warn().Msg("shutdown timeout exceeded, forcing exit")
	}
}
