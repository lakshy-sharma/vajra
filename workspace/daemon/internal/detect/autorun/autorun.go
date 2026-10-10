// internal/detect/autorun/autorun.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package autorun

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"vajra/internal/db/queries"
	"vajra/internal/findings"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// Source is the interface every persistence-category scanner implements.
type Source interface {
	Name() string
	Collect() ([]*models.AutorunEntry, error)
}

// Scanner orchestrates all persistence sources, diffs against DB state,
// and writes new or removed entries through FindingWriter.
type Scanner struct {
	logger      *zerolog.Logger
	autorunQ    *queries.AutorunQueries
	writer      *findings.FindingWriter
	sysInfo     utilities.SystemInfo
	interval    time.Duration
	concurrency int // W21: caps goroutines per scan pass
	mu          sync.RWMutex
	state       map[string]*models.AutorunEntry
}

func NewScanner(
	logger *zerolog.Logger,
	autorunQ *queries.AutorunQueries,
	writer *findings.FindingWriter,
	sysInfo utilities.SystemInfo,
	intervalMin int,
	concurrency int,
) *Scanner {
	if intervalMin <= 0 {
		intervalMin = 30
	}
	if concurrency <= 0 {
		concurrency = 2
	}
	return &Scanner{
		logger:      logger,
		autorunQ:    autorunQ,
		writer:      writer,
		sysInfo:     sysInfo,
		interval:    time.Duration(intervalMin) * time.Minute,
		concurrency: concurrency,
		state:       make(map[string]*models.AutorunEntry),
	}
}

func (s *Scanner) Name() string { return "autorun_scanner" }

func (s *Scanner) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if err := s.loadState(ctx); err != nil {
		s.logger.Error().Err(err).Msg("autorun: failed to load initial state")
	}

	s.runOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("autorun scanner stopped")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Scanner) runOnce(ctx context.Context) {
	entries, err := s.scan(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("autorun: scan failed")
		return
	}
	s.diff(ctx, entries)
}

func (s *Scanner) loadState(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.autorunQ.LoadActive(ctx)
	if err != nil {
		return err
	}
	for i := range entries {
		e := &entries[i]
		s.state[e.UniqueKey()] = e
	}
	s.logger.Info().Int("loaded", len(entries)).Msg("autorun: state loaded")
	return nil
}

// scan collects entries from all sources with bounded concurrency.
// W21: replaced unbounded goroutine-per-source with errgroup + semaphore.
func (s *Scanner) scan(ctx context.Context) ([]*models.AutorunEntry, error) {
	srcs := GetSources()

	var mu sync.Mutex
	var all []*models.AutorunEntry

	g, _ := errgroup.WithContext(ctx)
	sem := make(chan struct{}, s.concurrency)

	for _, src := range srcs {
		src := src
		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()

			entries, err := src.Collect()
			if err != nil {
				s.logger.Error().Err(err).Str("source", src.Name()).Msg("autorun: source error")
				return nil // non-fatal — one failing source must not abort others
			}
			mu.Lock()
			all = append(all, entries...)
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait()
	s.logger.Info().Int("entries", len(all)).Msg("autorun: scan complete")
	return all, nil
}

func (s *Scanner) diff(ctx context.Context, fresh []*models.AutorunEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()

	freshMap := make(map[string]*models.AutorunEntry, len(fresh))
	for _, e := range fresh {
		freshMap[e.UniqueKey()] = e
	}

	for key, old := range s.state {
		if _, exists := freshMap[key]; !exists {
			if err := s.autorunQ.MarkInactive(ctx, old, now); err != nil {
				s.logger.Error().Err(err).Str("key", key).Msg("autorun: mark inactive failed")
				continue
			}
			s.logger.Warn().
				Str("category", string(old.Category)).
				Str("location", old.Location).
				Str("image", old.ImagePath).
				Msg("autorun: entry removed")
			delete(s.state, key)
		}
	}

	for key, e := range freshMap {
		if _, exists := s.state[key]; !exists {
			e.FirstSeen = now
			e.LastSeen = now
			e.IsActive = true

			if err := s.autorunQ.Insert(ctx, e, now); err != nil {
				s.logger.Error().Err(err).Str("key", key).Msg("autorun: insert failed")
				continue
			}

			f := findings.Finding{
				Source:     findings.SourceAutorunScanner,
				Severity:   models.SeverityMedium,
				Status:     models.StatusNew,
				DetectedAt: now,
				TargetPath: e.ImagePath,
				RuleID:     "new_autorun_" + string(e.Category),
				Notes:      "new autorun: " + e.Location,
				FileHash:   e.SHA256,
				Extensions: map[string]string{
					"autorun_category": string(e.Category),
					"autorun_location": e.Location,
					"image_name":       e.ImageName,
					"arguments":        e.Arguments,
				},
			}
			if _, err := s.writer.Write(ctx, f); err != nil {
				s.logger.Error().Err(err).Str("key", key).Msg("autorun: write finding failed")
			}

			s.logger.Warn().
				Str("category", string(e.Category)).
				Str("location", e.Location).
				Str("image", e.ImagePath).
				Msg("NEW AUTORUN DETECTED")
			s.state[key] = e
		} else {
			if err := s.autorunQ.UpdateLastSeen(ctx, s.state[key], now); err != nil {
				s.logger.Error().Err(err).Str("key", key).Msg("autorun: update last_seen failed")
			}
		}
	}
}
