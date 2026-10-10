// internal/job/cleanup.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package job

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db/queries"
)

// Cleanup deletes resolved detections and raw telemetry older than
// the retention window. Runs on a configurable hour interval.
type Cleanup struct {
	logger        *zerolog.Logger
	cleanupQ      *queries.CleanupQueries
	intervalHour  int
	retentionDays int
}

func NewCleanup(
	logger *zerolog.Logger,
	cleanupQ *queries.CleanupQueries,
	intervalHour int,
	retentionDays int,
) *Cleanup {
	return &Cleanup{
		logger:        logger,
		cleanupQ:      cleanupQ,
		intervalHour:  intervalHour,
		retentionDays: retentionDays,
	}
}

func (c *Cleanup) Name() string { return "db_cleanup" }

func (c *Cleanup) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(time.Duration(c.intervalHour) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info().Msg("db cleanup stopped")
			return
		case <-ticker.C:
			result, err := c.cleanupQ.RunCleanup(c.retentionDays)
			if err != nil {
				c.logger.Error().Err(err).Msg("db cleanup failed")
				continue
			}
			c.logger.Info().
				Int64("detections", result.DetectionsDeleted).
				Int64("network", result.NetworkRowsDeleted).
				Int64("memory", result.MemoryRowsDeleted).
				Msg("db cleanup complete")
		}
	}
}
