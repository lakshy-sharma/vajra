// internal/jobs/autoruns/autoruns.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package autoruns

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db"
	"vajra/internal/db/queries"
	"vajra/shared/models"
)

// AutorunSource is the platform-agnostic interface every
// persistence-category scanner must implement.
type AutorunSource interface {
	Name() string
	Collect() ([]*models.AutorunEntry, error)
}

// Scanner orchestrates all sources, diffs results against the
// DB state, and persists changes.
type Scanner struct {
	ctx      context.Context
	wg       *sync.WaitGroup
	logger   *zerolog.Logger
	queries  *queries.AutorunQueries
	interval time.Duration
	mu       sync.RWMutex
	state    map[string]*models.AutorunEntry
}

func NewScanner(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	q *queries.AutorunQueries,
	intervalMin int,
) *Scanner {
	if intervalMin <= 0 {
		intervalMin = 30
	}
	return &Scanner{
		ctx:      ctx,
		wg:       wg,
		logger:   logger,
		queries:  q,
		interval: time.Duration(intervalMin) * time.Minute,
		state:    make(map[string]*models.AutorunEntry),
	}
}

func (s *Scanner) LoadState() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.queries.LoadActive()
	if err != nil {
		return err
	}
	for i := range entries {
		e := &entries[i]
		s.state[e.UniqueKey()] = e
	}
	s.logger.Info().Int("loaded", len(entries)).Msg("autorun state loaded from DB")
	return nil
}

func (s *Scanner) Scan() ([]*models.AutorunEntry, error) {
	sources := GetSources()

	var (
		mu  sync.Mutex
		all []*models.AutorunEntry
		wg  sync.WaitGroup
	)

	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			entries, err := src.Collect()
			if err != nil {
				s.logger.Error().Err(err).Str("source", src.Name()).Msg("autorun source error")
				return
			}
			mu.Lock()
			all = append(all, entries...)
			mu.Unlock()
		}()
	}

	wg.Wait()
	s.logger.Info().Int("entries", len(all)).Msg("autorun scan complete")
	return all, nil
}

func (s *Scanner) Diff(fresh []*models.AutorunEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()

	freshMap := make(map[string]*models.AutorunEntry, len(fresh))
	for _, e := range fresh {
		freshMap[e.UniqueKey()] = e
	}

	// Mark removed entries inactive.
	for key, old := range s.state {
		if _, exists := freshMap[key]; !exists {
			if err := s.queries.MarkInactive(old, now); err != nil {
				s.logger.Error().Err(err).Str("key", key).Msg("failed to mark autorun inactive")
				continue
			}
			s.logger.Warn().
				Str("category", string(old.Category)).
				Str("location", old.Location).
				Str("image", old.ImagePath).
				Msg("autorun removed")
			delete(s.state, key)
		}
	}

	// Insert new entries, bump last_seen for existing ones.
	for key, e := range freshMap {
		if _, exists := s.state[key]; !exists {
			nowTime := time.Unix(now, 0).UTC().Format(time.RFC3339)
			e.CreatedAt = nowTime
			e.UpdatedAt = nowTime
			e.FirstSeen = now
			e.LastSeen = now
			e.IsActive = true

			if err := s.queries.Insert(e); err != nil {
				s.logger.Error().Err(err).Str("key", key).Msg("failed to insert autorun")
				continue
			}
			s.logger.Warn().
				Str("category", string(e.Category)).
				Str("location", e.Location).
				Str("image", e.ImagePath).
				Str("sha256", e.SHA256).
				Msg("NEW AUTORUN DETECTED")
			s.state[key] = e
		} else {
			if err := s.queries.UpdateLastSeen(s.state[key], now); err != nil {
				s.logger.Error().Err(err).Str("key", key).Msg("failed to update last_seen")
			}
		}
	}
}

// RunAutorunScan is the goroutine entry point.
// Takes *db.DB to avoid import cycles — constructs its own queries internally.
func RunAutorunScan(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger *zerolog.Logger,
	database *db.DB,
	intervalMin int,
) {
	defer wg.Done()

	q := queries.NewAutorunQueries(database)
	s := NewScanner(ctx, wg, logger, q, intervalMin)

	if err := s.LoadState(); err != nil {
		logger.Error().Err(err).Msg("failed to load initial autorun state")
	}

	runOnce(s, logger)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("autorun scanner stopped")
			return
		case <-ticker.C:
			runOnce(s, logger)
		}
	}
}

func runOnce(s *Scanner, logger *zerolog.Logger) {
	entries, err := s.Scan()
	if err != nil {
		logger.Error().Err(err).Msg("autorun scan failed")
		return
	}
	s.Diff(entries)
}
