// internal/jobs/cleanup.go
package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db/queries"
)

func RunDBCleanup(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	cq *queries.CleanupQueries,
	cleanupIntervalHour int,
	retentionDays int,
) {
	defer wg.Done()

	ticker := time.NewTicker(time.Duration(cleanupIntervalHour) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("db cleanup stopped")
			return
		case <-ticker.C:
			result, err := cq.RunCleanup(retentionDays)
			if err != nil {
				logger.Error().Err(err).Msg("db cleanup failed")
				continue
			}
			logger.Info().
				Int64("file_scan_rows", result.FileScanRowsDeleted).
				Int64("process_scan_rows", result.ProcessScanRowsDeleted).
				Int64("network_rows", result.NetworkRowsDeleted).
				Int64("memory_rows", result.MemoryRowsDeleted).
				Msg("db cleanup complete")
		}
	}
}
