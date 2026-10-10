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
	c.logger.Info().Msg("db cleanup started")

	// J1: run immediately at startup so stale rows are removed before the
	// first ticker fires (which may be hours away).
	c.runOnce(ctx)

	ticker := time.NewTicker(time.Duration(c.intervalHour) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info().Msg("db cleanup stopped")
			return
		case <-ticker.C:
			c.runOnce(ctx)
		}
	}
}

func (c *Cleanup) runOnce(ctx context.Context) {
	now := time.Now().Unix()
	cutoff := now - int64(c.retentionDays)*86400

	result, err := c.cleanupQ.RunCleanup(ctx, cutoff)
	if err != nil {
		c.logger.Error().Err(err).Msg("db cleanup failed")
		return
	}
	c.logger.Info().
		Int64("detections", result.DetectionsDeleted).
		Int64("network", result.NetworkRowsDeleted).
		Int64("memory", result.MemoryRowsDeleted).
		Int64("security", result.SecurityRowsDeleted).
		Msg("db cleanup complete")
}
