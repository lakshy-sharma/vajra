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
// Thread safety: the filter field is set once in NewHashAnalyzer and never
// written again — there is no Reload method and the field is unexported.
// Concurrent calls to Analyze are safe because bloom.BloomFilter supports
// concurrent reads. If a reload mechanism is ever added it must replace the
// entire HashAnalyzer (create a new one and swap the pointer at the call
// site) rather than mutating h.filter directly, to preserve this guarantee.
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
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn().Str("path", path).Msg("hash analyzer: bloom filter not found — disabled")
			return &HashAnalyzer{logger: logger}, nil
		}
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

// Analyze checks the SHA256 passed via context against the filter.
// Returns CRITICAL on a hit, CLEAN otherwise.
//
// A Bloom filter hit is probabilistic — false positives are possible and
// will cause YARA to run on a clean file. False negatives are impossible.
//
// The ToLower call here is a known allocation on the hot path (A10).
// The correct fix is to build the filter with lowercase hashes in hashsync,
// so the check becomes a direct TestString with no conversion. Until
// hashsync is updated to lowercase at insert time, the call stays here to
// avoid false negatives on uppercase SHA256 values from the MalwareBazaar CSV.
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
		Notes:    "SHA256 matched MalwareBazaar dataset: " + sha256,
	}, nil
}

// Enabled reports whether the analyzer has a loaded filter.
func (h *HashAnalyzer) Enabled() bool { return h.filter != nil }
