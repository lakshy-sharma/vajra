// internal/job/hashsync.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package job

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/rs/zerolog"
	sharedconfig "vajra/shared/config"
)

const (
	bazaarDefaultURL = "https://bazaar.abuse.ch/export/csv/full/"
	csvName          = "full.csv"
	sha256Col        = 1
)

// hashClient is used exclusively for MalwareBazaar downloads.
// J5: dedicated client with timeout — http.DefaultClient has no timeout.
var hashClient = &http.Client{Timeout: 15 * time.Minute}

// HashSyncer downloads the MalwareBazaar full CSV and builds a Bloom filter
// at BloomFilterPath. The filter is loaded by HashAnalyzer at startup.
// Disabled when APIKey is empty.
type HashSyncer struct {
	logger   *zerolog.Logger
	cfg      sharedconfig.ThreatIntelSettings
	interval time.Duration
}

func NewHashSyncer(logger *zerolog.Logger, cfg sharedconfig.ThreatIntelSettings, intervalHour int) *HashSyncer {
	return &HashSyncer{
		logger:   logger,
		cfg:      cfg,
		interval: time.Duration(intervalHour) * time.Hour,
	}
}

func (h *HashSyncer) Name() string { return "hash_syncer" }

func (h *HashSyncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if h.cfg.APIKey == "" {
		h.logger.Warn().Msg("hash syncer: no API key configured — disabled")
		return
	}

	h.logger.Info().Msg("hash syncer started")
	h.runOnce(ctx)

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.logger.Info().Msg("hash syncer stopped")
			return
		case <-ticker.C:
			h.runOnce(ctx)
		}
	}
}

// RunOnce runs a single sync cycle — used by `vajra hashes update`.
func (h *HashSyncer) RunOnce() error {
	return h.runOnce(context.Background())
}

func (h *HashSyncer) runOnce(ctx context.Context) error {
	start := time.Now()
	h.logger.Info().Msg("hash syncer: starting sync")

	zipPath := filepath.Join(filepath.Dir(h.cfg.BloomFilterPath), "bazaar_full.zip")

	if err := h.download(ctx, zipPath); err != nil {
		h.logger.Error().Err(err).Msg("hash syncer: download failed")
		return err
	}

	count, err := h.buildFilter(zipPath)
	if err != nil {
		h.logger.Error().Err(err).Msg("hash syncer: bloom build failed")
		return err
	}

	// J2: delete the zip after a successful build so the next sync cycle
	// always downloads a fresh export rather than reusing a stale file.
	if removeErr := os.Remove(zipPath); removeErr != nil {
		h.logger.Warn().Err(removeErr).Str("path", zipPath).Msg("hash syncer: could not remove zip after build")
	}

	h.logger.Info().
		Int("hashes", count).
		Str("elapsed", time.Since(start).Round(time.Second).String()).
		Str("output", h.cfg.BloomFilterPath).
		Msg("hash syncer: sync complete")
	return nil
}

// download fetches the full CSV zip from MalwareBazaar.
func (h *HashSyncer) download(ctx context.Context, zipPath string) error {
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		return fmt.Errorf("download: mkdir: %w", err)
	}

	baseURL := h.cfg.MalwareBazaarURL
	if baseURL == "" {
		baseURL = bazaarDefaultURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return fmt.Errorf("download: build request: %w", err)
	}
	// J4: auth key moved from URL query parameter to header — a query
	// parameter is included in access logs and any logged error messages.
	req.Header.Set("Auth-Key", h.cfg.APIKey)

	resp, err := hashClient.Do(req) // J5: dedicated client, not http.DefaultClient
	if err != nil {
		return fmt.Errorf("download: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: unexpected status %d", resp.StatusCode)
	}

	tmp := zipPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("download: create tmp: %w", err)
	}

	written, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("download: write: %w", err)
	}

	if err := os.Rename(tmp, zipPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("download: rename: %w", err)
	}

	h.logger.Info().
		Str("path", zipPath).
		Int64("bytes", written).
		Msg("hash syncer: download complete")
	return nil
}

// buildFilter reads the CSV from the zip, extracts sha256 values, and writes
// the bloom filter. Bloom parameters come from config — not hardcoded constants.
func (h *HashSyncer) buildFilter(zipPath string) (int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, fmt.Errorf("buildFilter: open zip: %w", err)
	}
	defer zr.Close()

	var csvFile *zip.File
	for _, f := range zr.File {
		if f.Name == csvName {
			csvFile = f
			break
		}
	}
	if csvFile == nil {
		return 0, fmt.Errorf("buildFilter: %s not found in zip", csvName)
	}

	rc, err := csvFile.Open()
	if err != nil {
		return 0, fmt.Errorf("buildFilter: open csv: %w", err)
	}
	defer rc.Close()

	// J3: csv.Reader.Comment removes comment lines natively — the previous
	// goroutine+pipe workaround is dead code once Comment is set.
	reader := csv.NewReader(bufio.NewReader(rc))
	reader.Comment = '#'

	filter := bloom.NewWithEstimates(h.cfg.BloomCapacity, h.cfg.BloomFPRate)
	count := 0
	headerSeen := false

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed rows — do not abort the whole build for one bad line.
			continue
		}
		if !headerSeen {
			headerSeen = true
			continue
		}
		if len(row) <= sha256Col {
			continue
		}
		// A10 (hash.go companion): lowercase at insert time so TestString in
		// HashAnalyzer needs no conversion.
		sha256 := strings.ToLower(strings.TrimSpace(row[sha256Col]))
		if len(sha256) != 64 {
			continue
		}
		filter.AddString(sha256)
		count++
	}

	if err := h.writeFilter(filter); err != nil {
		return 0, err
	}
	return count, nil
}

func (h *HashSyncer) writeFilter(filter *bloom.BloomFilter) error {
	if err := os.MkdirAll(filepath.Dir(h.cfg.BloomFilterPath), 0o755); err != nil {
		return fmt.Errorf("writeFilter: mkdir: %w", err)
	}

	tmp := h.cfg.BloomFilterPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("writeFilter: create: %w", err)
	}

	w := bufio.NewWriter(f)
	if _, err := filter.WriteTo(w); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writeFilter: write: %w", err)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writeFilter: flush: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("writeFilter: close: %w", err)
	}

	if err := os.Rename(tmp, h.cfg.BloomFilterPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("writeFilter: rename: %w", err)
	}
	return nil
}
