// internal/analyzer/yara.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package analyzer

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"vajra/internal/scanner/yara"
	"vajra/internal/utilities"
)

// resultChPool amortises channel allocation across scan calls.
// Each channel is buffered by 1 so a pool worker never blocks on send
// even if the caller has already returned due to context cancellation.
var resultChPool = sync.Pool{
	New: func() any { return make(chan yara.ScanResult, 1) },
}

// YARAAnalyzer submits a file to the shared YARA pool and returns
// a classified result. Slowest analyzer in the pipeline — runs last
// so faster analyzers can short-circuit before it.
type YARAAnalyzer struct {
	pool   *yara.Pool
	logger *zerolog.Logger
}

func NewYARAAnalyzer(pool *yara.Pool, logger *zerolog.Logger) *YARAAnalyzer {
	return &YARAAnalyzer{pool: pool, logger: logger}
}

func (y *YARAAnalyzer) Name() string { return "yara" }

func (y *YARAAnalyzer) Analyze(ctx context.Context, path string) (Result, error) {
	resultCh := resultChPool.Get().(chan yara.ScanResult)
	defer func() {
		// Drain before returning to pool — on context cancellation the pool
		// worker may still send after we have stopped waiting, so a stale
		// result must not be seen by the next caller that reuses this channel.
		select {
		case <-resultCh:
		default:
		}
		resultChPool.Put(resultCh)
	}()

	if !y.pool.Enqueue(ctx, path, resultCh) {
		return Result{}, fmt.Errorf("yara: enqueue cancelled: %s", path)
	}

	select {
	case <-ctx.Done():
		return Result{}, fmt.Errorf("yara: context cancelled: %s", path)
	case r := <-resultCh:
		if r.Error != nil {
			return Result{}, fmt.Errorf("yara: scan error on %s: %w", path, r.Error)
		}

		// Convert []yara.Match to []utilities.RuleMatch for engine-agnostic
		// severity classification, then extract model matches for storage.
		ruleMatches := make([]utilities.RuleMatch, len(r.Matches))
		for i, m := range r.Matches {
			ruleMatches[i] = m
		}
		severity := utilities.ClassifySeverity(ruleMatches)
		modelMatches := yara.ToModelMatches(r.Matches)

		y.logger.Debug().
			Str("path", path).
			Str("severity", string(severity)).
			Int("matches", len(r.Matches)).
			Dur("duration", r.Duration).
			Msg("yara: scan complete")

		return Result{
			Severity:    severity,
			YaraMatches: modelMatches,
		}, nil
	}
}
