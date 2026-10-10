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
	bazaarFullURL = "https://bazaar.abuse.ch/export/csv/full/"
	csvName       = "full.csv"
	sha256Col     = 1

	// 5M capacity with 1% FP rate — covers current dataset with room to grow.
	// FP means YARA runs on a file it didn't need to — acceptable overhead.
	bloomCapacity = 5_000_000
	bloomFPRate   = 0.01
)

// HashSyncer downloads the MalwareBazaar full CSV and builds a Bloom filter
// at BloomFilterPath. The filter is loaded by HashAnalyzer at startup.
// If no auth key is configured the job disables itself.
type HashSyncer struct {
	logger   *zerolog.Logger
	cfg      sharedconfig.ThreatIntelSettings
	interval time.Duration
}

func NewHashSyncer(logger *zerolog.Logger, cfg sharedconfig.ThreatIntelSettings) *HashSyncer {
	return &HashSyncer{
		logger:   logger,
		cfg:      cfg,
		interval: time.Duration(cfg.HashSyncIntervalHour) * time.Hour,
	}
}

func (h *HashSyncer) Name() string { return "hash_syncer" }

func (h *HashSyncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if h.cfg.MalwareBazaarAuthKey == "" {
		h.logger.Warn().Msg("hash syncer: no auth key configured — disabled")
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

	h.logger.Info().
		Int("hashes", count).
		Str("elapsed", time.Since(start).Round(time.Second).String()).
		Str("output", h.cfg.BloomFilterPath).
		Msg("hash syncer: sync complete")
	return nil
}

// download fetches the full CSV zip from MalwareBazaar.
// Skips the download if the zip already exists on disk.
func (h *HashSyncer) download(ctx context.Context, zipPath string) error {
	if _, err := os.Stat(zipPath); err == nil {
		h.logger.Info().Str("path", zipPath).Msg("hash syncer: zip exists, skipping download")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		return fmt.Errorf("download: mkdir: %w", err)
	}

	url := fmt.Sprintf("%s?auth_key=%s", bazaarFullURL, h.cfg.MalwareBazaarAuthKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("download: build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: unexpected status %d", resp.StatusCode)
	}

	// Write to a temp file then rename — avoids partial writes.
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

// buildFilter reads the CSV from the zip, extracts sha256_hash, and writes
// the bloom filter to BloomFilterPath.
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

	filter := bloom.NewWithEstimates(bloomCapacity, bloomFPRate)
	count := 0
	reader := csv.NewReader(bufio.NewReader(rc))

	// MalwareBazaar CSV has comment lines starting with #.
	// csv.Reader does not handle comments — we wrap it with a line filter.
	// Reopen with filtered reader.
	rc.Close()
	rc2, err := csvFile.Open()
	if err != nil {
		return 0, fmt.Errorf("buildFilter: reopen csv: %w", err)
	}
	defer rc2.Close()

	scanner := bufio.NewScanner(rc2)
	headerSeen := false
	pr, pw := io.Pipe()
	reader = csv.NewReader(pr)

	// Feed non-comment lines into the pipe in a goroutine.
	go func() {
		defer pw.Close()
		w := bufio.NewWriter(pw)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "#") {
				continue
			}
			w.WriteString(line + "\n")
		}
		w.Flush()
	}()

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed rows — don't abort the whole build.
			continue
		}
		if !headerSeen {
			headerSeen = true
			continue
		}
		if len(row) <= sha256Col {
			continue
		}
		sha256 := strings.TrimSpace(strings.ToLower(row[sha256Col]))
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

// writeFilter serialises the bloom filter to BloomFilterPath atomically.
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
