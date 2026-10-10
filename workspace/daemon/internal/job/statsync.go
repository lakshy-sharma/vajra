// internal/job/statsync.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package job

import (
	"context"
	"sync"
	"time"
	"vajra/internal/db/queries"

	"github.com/rs/zerolog"
)

const statSyncDefaultInterval = time.Hour

// StatSyncer drives periodic aggregation of raw event counts into the
// event_statistics table. All SQL lives in StatisticsQueries.
type StatSyncer struct {
	logger   *zerolog.Logger
	statsQ   *queries.StatisticsQueries
	interval time.Duration
}

func NewStatSyncer(logger *zerolog.Logger, statsQ *queries.StatisticsQueries) *StatSyncer {
	return &StatSyncer{
		logger:   logger,
		statsQ:   statsQ,
		interval: statSyncDefaultInterval,
	}
}

func (s *StatSyncer) Name() string { return "stat_syncer" }

func (s *StatSyncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	s.logger.Info().Msg("stat syncer started")
	s.runOnce()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("stat syncer stopped")
			return
		case <-ticker.C:
			s.runOnce()
		}
	}
}

// RunOnce runs a single aggregation cycle — exposed for future CLI use.
func (s *StatSyncer) RunOnce() { s.runOnce() }

func (s *StatSyncer) runOnce() {
	start := time.Now()
	s.logger.Debug().Msg("stat syncer: starting aggregation")

	n, err := s.statsQ.Aggregate()
	if err != nil {
		s.logger.Error().Err(err).Msg("stat syncer: aggregation failed")
		return
	}

	s.logger.Info().
		Int64("rows_upserted", n).
		Str("elapsed", time.Since(start).Round(time.Millisecond).String()).
		Msg("stat syncer: aggregation complete")
}
