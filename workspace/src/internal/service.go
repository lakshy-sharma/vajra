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
	"vajra/internal/utilities"

	"github.com/rs/zerolog"
)

// runDatabaseCleanup periodically cleans old entries from the database
func runDatabaseCleanup(ctx context.Context, wg *sync.WaitGroup,
	logger *zerolog.Logger, dbHandler *database.DBHandler) {

	defer wg.Done()

	ticker := time.NewTicker(24 * time.Hour) // Run daily
	defer ticker.Stop()

	logger.Info().Msg("database cleanup task started")

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("stopping database cleanup task")
			return

		case <-ticker.C:
			logger.Info().Msg("running database cleanup")

			// Delete entries older than 90 days (configurable)
			cutoffTime := time.Now().Add(-90 * 24 * time.Hour).Unix()

			// Clean file scan results
			result, err := dbHandler.DB.Exec(`
				DELETE FROM file_scan_results 
				WHERE scan_time < ? AND status = 'RESOLVED'
			`, cutoffTime)

			if err != nil {
				logger.Error().Err(err).Msg("failed to clean file_scan_results")
			} else {
				rows, _ := result.RowsAffected()
				logger.Info().Int64("deleted_rows", rows).Msg("cleaned file_scan_results")
			}

			// Clean network events
			result, err = dbHandler.DB.Exec(`
				DELETE FROM network_events 
				WHERE event_time < ? AND severity = 'LOW'
			`, cutoffTime)

			if err != nil {
				logger.Error().Err(err).Msg("failed to clean network_events")
			} else {
				rows, _ := result.RowsAffected()
				logger.Info().Int64("deleted_rows", rows).Msg("cleaned network_events")
			}

			// Vacuum database to reclaim space
			if _, err := dbHandler.DB.Exec("VACUUM"); err != nil {
				logger.Error().Err(err).Msg("failed to vacuum database")
			} else {
				logger.Info().Msg("database vacuumed successfully")
			}
		}
	}
}

// startServiceMode runs the EDR in continuous monitoring mode
func startServiceMode(logger *zerolog.Logger, config *utilities.Config, dbHandler *database.DBHandler) {
	logger.Info().Msg("starting service mode")

	// Setup eBPF event handler
	eventHandler, err := eBPFHandlers.NewEventHandler(logger, config, dbHandler)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create event handler")
	}
	defer eventHandler.Stop()

	// Start eBPF event generator
	gen, err := eBPFListeners.NewEventGenerator(eventHandler.EventListener)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create event generator")
	}
	defer gen.Stop()
	if err := gen.Start(); err != nil {
		logger.Fatal().Err(err).Msg("failed to start event generator")
	}
	logger.Info().Msg("eBPF monitoring started with YARA scanning enabled")

	// Define wait groups and context for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// TODO
	// Start periodic full filesystem scan (optional)

	// Start database cleanup task
	wg.Add(1)
	go runDatabaseCleanup(ctx, &wg, logger, dbHandler)

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
