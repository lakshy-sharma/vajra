// internal/analyzer/hash.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package analyzer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/rs/zerolog"
	"vajra/shared/models"
)

// HashAnalyzer checks a file's SHA256 against an in-memory Bloom filter
// built from the MalwareBazaar dataset. Short-circuits the content pipeline
// on CRITICAL, saving the YARA pool for files not already known-bad.
//
// Disabled gracefully when the bloom filter file is absent — the rest of
// the pipeline runs unaffected.
type HashAnalyzer struct {
	filter *bloom.BloomFilter
	logger *zerolog.Logger
}

// NewHashAnalyzer loads the Bloom filter from path. Returns a disabled
// analyzer (nil filter) if the file does not exist — not an error.
func NewHashAnalyzer(path string, logger *zerolog.Logger) (*HashAnalyzer, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Warn().Str("path", path).Msg("hash analyzer: bloom filter not found — disabled")
		return &HashAnalyzer{logger: logger}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("hash analyzer: open bloom filter: %w", err)
	}
	defer f.Close()

	filter := &bloom.BloomFilter{}
	if _, err := filter.ReadFrom(bufio.NewReader(f)); err != nil {
		return nil, fmt.Errorf("hash analyzer: read bloom filter: %w", err)
	}

	logger.Info().
		Str("path", path).
		Uint32("capacity", uint32(filter.Cap())).
		Msg("hash analyzer: bloom filter loaded")

	return &HashAnalyzer{filter: filter, logger: logger}, nil
}

func (h *HashAnalyzer) Name() string { return "hash" }

// Analyze checks the lowercase SHA256 passed via context against the filter.
// The SHA256 is expected in context — FileScanner and ProcessScanner both
// compute it before the pipeline runs.
// Returns CRITICAL on a hit, CLEAN otherwise.
// A Bloom filter hit is probabilistic — false positives let YARA run next.
// False negatives are impossible.
func (h *HashAnalyzer) Analyze(ctx context.Context, path string) (Result, error) {
	if h.filter == nil {
		return Result{Severity: models.SeverityClean}, nil
	}

	sha256, ok := SHA256FromCtx(ctx)
	if !ok || sha256 == "" {
		return Result{Severity: models.SeverityClean}, nil
	}

	if !h.filter.TestString(strings.ToLower(sha256)) {
		return Result{Severity: models.SeverityClean}, nil
	}

	h.logger.Warn().
		Str("path", path).
		Str("sha256", sha256).
		Msg("hash analyzer: known-bad hash detected")

	return Result{
		Severity: models.SeverityCritical,
		Notes:    fmt.Sprintf("SHA256 matched MalwareBazaar dataset: %s", sha256),
	}, nil
}

// Enabled reports whether the analyzer has a loaded filter.
func (h *HashAnalyzer) Enabled() bool { return h.filter != nil }
