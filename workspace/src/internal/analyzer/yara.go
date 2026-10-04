// internal/analyzer/yara.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package analyzer

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"vajra/internal/scanner"
)

// YARAAnalyzer submits a file path to the shared YARA pool
// and returns the classified result.
// It is the slowest analyzer in the pipeline and should always
// run last so faster analyzers can short-circuit before it.
type YARAAnalyzer struct {
	pool   *scanner.Pool
	logger *zerolog.Logger
}

// NewYARAAnalyzer constructs a YARAAnalyzer backed by the shared pool.
// The pool is created once in service.go and passed in — YARAAnalyzer
// does not own it and must not call pool.Stop().
func NewYARAAnalyzer(pool *scanner.Pool, logger *zerolog.Logger) *YARAAnalyzer {
	return &YARAAnalyzer{
		pool:   pool,
		logger: logger,
	}
}

// Name implements Analyzer.
func (y *YARAAnalyzer) Name() string {
	return "yara"
}

// Analyze submits path to the YARA pool and blocks until the
// result is available or ctx is cancelled.
// Returns an error if the pool rejected the submission (shutdown)
// or if YARA itself returned an error for this file.
func (y *YARAAnalyzer) Analyze(ctx context.Context, path string) (AnalysisResult, error) {
	resultCh := make(chan scanner.ScanResult, 1)

	if !y.pool.Enqueue(ctx, path, resultCh) {
		// ctx cancelled while waiting for queue space.
		return AnalysisResult{}, fmt.Errorf("yara: pool enqueue cancelled for %s", path)
	}

	select {
	case <-ctx.Done():
		return AnalysisResult{}, fmt.Errorf("yara: context cancelled waiting for result on %s", path)

	case result := <-resultCh:
		if result.Error != nil {
			// YARA errors are usually permission denied or file
			// vanished between eligibility check and scan.
			// Return the error — pipeline will log and continue.
			return AnalysisResult{}, fmt.Errorf("yara: scan error on %s: %w", path, result.Error)
		}

		severity := scanner.ClassifyYARASeverity(result.Matches)

		y.logger.Debug().
			Str("path", path).
			Str("severity", string(severity)).
			Int("matches", len(result.Matches)).
			Dur("duration", result.Duration).
			Msg("yara analyzer: scan complete")

		return AnalysisResult{
			Severity:    severity,
			YaraMatches: result.Matches,
		}, nil
	}
}
