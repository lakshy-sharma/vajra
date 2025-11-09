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
package jobs

import (
	"context"
	"sync"
	"time"
	"vajra/internal/database"
	"vajra/internal/utilities"

	"github.com/rs/zerolog"
)

// runDatabaseCleanup periodically cleans old entries from the database
func RunDBCleanup(ctx context.Context, wg *sync.WaitGroup, logger *zerolog.Logger, dbHandler *database.DBHandler, config *utilities.Config) {
	defer wg.Done()

	ticker := time.NewTicker(time.Duration(config.TimingSettings.DatabaseCleanupTimeHour) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("stopping database cleanup task")
			return

		case <-ticker.C:
			logger.Info().Msg("running database cleanup")

			// Delete entries older than 90 days
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
