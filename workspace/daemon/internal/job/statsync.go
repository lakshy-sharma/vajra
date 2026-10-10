// internal/job/statsync.go
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

// StatSyncer drives periodic aggregation of raw event counts into the
// event_statistics table. All SQL lives in StatisticsQueries.
type StatSyncer struct {
	logger   *zerolog.Logger
	statsQ   *queries.StatisticsQueries
	interval time.Duration
}

// NewStatSyncer creates a StatSyncer with the aggregation interval from config.
// J11: was hardcoded to time.Hour regardless of StatsSyncIntervalMin.
func NewStatSyncer(logger *zerolog.Logger, statsQ *queries.StatisticsQueries, intervalMin int) *StatSyncer {
	if intervalMin <= 0 {
		intervalMin = 5 // safe floor — zero would spin-loop
	}
	return &StatSyncer{
		logger:   logger,
		statsQ:   statsQ,
		interval: time.Duration(intervalMin) * time.Minute,
	}
}

func (s *StatSyncer) Name() string { return "stat_syncer" }

func (s *StatSyncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	s.logger.Info().Msg("stat syncer started")

	s.runOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("stat syncer stopped")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// RunOnce runs a single aggregation cycle — exposed for future CLI use.
func (s *StatSyncer) RunOnce() { s.runOnce(context.Background()) }

func (s *StatSyncer) runOnce(ctx context.Context) {
	start := time.Now()
	s.logger.Debug().Msg("stat syncer: starting aggregation")

	n, err := s.statsQ.Aggregate(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("stat syncer: aggregation failed")
		return
	}

	s.logger.Info().
		Int64("rows_upserted", n).
		Str("elapsed", time.Since(start).Round(time.Millisecond).String()).
		Msg("stat syncer: aggregation complete")
}
