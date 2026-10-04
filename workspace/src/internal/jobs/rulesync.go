// internal/jobs/rulesync.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/utilities"
)

const (
	yaraForgeAPIURL  = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
	rulesTagFilename = ".rules_version"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

type RuleSyncer struct {
	logger *zerolog.Logger
	cfg    utilities.RulesSettings
}

func NewRuleSyncer(logger *zerolog.Logger, cfg utilities.RulesSettings) *RuleSyncer {
	return &RuleSyncer{logger: logger, cfg: cfg}
}

func (rs *RuleSyncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	rs.logger.Info().
		Int("interval_hours", rs.cfg.RulesSyncIntervalHour).
		Msg("rule syncer started")

	rs.sync()

	ticker := time.NewTicker(time.Duration(rs.cfg.RulesSyncIntervalHour) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			rs.logger.Info().Msg("rule syncer stopped")
			return
		case <-ticker.C:
			rs.sync()
		}
	}
}

func (rs *RuleSyncer) RunOnce() error {
	return rs.sync()
}

func (rs *RuleSyncer) LocalHash() (string, error) {
	return rs.hashFile(rs.cfg.RulesFilepath)
}

func (rs *RuleSyncer) sync() error {
	rs.logger.Info().Msg("rule syncer: checking for updates")

	// ── Check remote release tag ──────────────────────────────
	remoteTag, err := rs.fetchLatestTag()
	if err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: could not fetch remote release tag, skipping")
		return fmt.Errorf("rulesync: fetch tag: %w", err)
	}

	localTag := rs.readLocalTag()

	rs.logger.Debug().
		Str("remote_tag", remoteTag).
		Str("local_tag", localTag).
		Msg("rule syncer: version check")

	if remoteTag == localTag {
		rs.logger.Info().
			Str("tag", localTag).
			Msg("rule syncer: rules are up to date")
		return nil
	}

	rs.logger.Info().
		Str("local_tag", localTag).
		Str("remote_tag", remoteTag).
		Msg("rule syncer: new rules available, downloading")

	// ── Download to staging ───────────────────────────────────
	stagingPath := rs.cfg.RulesFilepath + ".staging"
	if err := rs.download(rs.cfg.RulesRemoteURL, stagingPath); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: download failed")
		os.Remove(stagingPath)
		return fmt.Errorf("rulesync: download: %w", err)
	}

	// ── Verify downloaded file is a valid zip ─────────────────
	if err := rs.verifyZip(stagingPath); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: downloaded file is not a valid zip")
		os.Remove(stagingPath)
		return fmt.Errorf("rulesync: verify zip: %w", err)
	}

	// ── Archive current rules ─────────────────────────────────
	if err := rs.archiveCurrent(); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: archive failed, continuing")
	}

	// ── Atomic replace ────────────────────────────────────────
	if err := os.Rename(stagingPath, rs.cfg.RulesFilepath); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: could not replace rules file")
		os.Remove(stagingPath)
		return fmt.Errorf("rulesync: replace: %w", err)
	}

	// ── Store new tag ─────────────────────────────────────────
	if err := rs.writeLocalTag(remoteTag); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: could not write version tag")
	}

	rs.logger.Info().
		Str("tag", remoteTag).
		Str("path", rs.cfg.RulesFilepath).
		Msg("rule syncer: rules updated successfully")

	// ── Prune old archives ────────────────────────────────────
	if err := rs.pruneArchives(); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: archive pruning failed")
	}

	// ── Restart agent ─────────────────────────────────────────
	rs.logger.Info().Msg("rule syncer: restarting agent to load new rules")
	if err := rs.restartAgent(); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: systemd restart failed — new rules load on next restart")
		return fmt.Errorf("rulesync: restart: %w", err)
	}

	return nil
}

// fetchLatestTag calls the GitHub releases API and returns the
// tag_name of the latest release (e.g. "20260816").
func (rs *RuleSyncer) fetchLatestTag() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, yaraForgeAPIURL, nil)
	if err != nil {
		return "", fmt.Errorf("fetch tag: build request: %w", err)
	}
	// GitHub API requires a User-Agent header.
	req.Header.Set("User-Agent", "vajra-edr")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch tag: http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch tag: unexpected status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("fetch tag: decode json: %w", err)
	}

	if release.TagName == "" {
		return "", fmt.Errorf("fetch tag: empty tag_name in response")
	}

	return release.TagName, nil
}

// tagFilePath returns the path to the local version state file.
// Stored alongside the rules zip so it moves with it.
func (rs *RuleSyncer) tagFilePath() string {
	return filepath.Join(filepath.Dir(rs.cfg.RulesFilepath), rulesTagFilename)
}

// readLocalTag returns the stored release tag, or empty string
// if no tag has been stored yet (first run).
func (rs *RuleSyncer) readLocalTag() string {
	data, err := os.ReadFile(rs.tagFilePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// writeLocalTag stores the release tag after a successful update.
func (rs *RuleSyncer) writeLocalTag(tag string) error {
	return os.WriteFile(rs.tagFilePath(), []byte(tag), 0o644)
}

// verifyZip checks that the downloaded file starts with the ZIP
// magic bytes (PK\x03\x04). A corrupted or incomplete download
// would otherwise silently replace working rules.
func (rs *RuleSyncer) verifyZip(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("verify zip: open: %w", err)
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return fmt.Errorf("verify zip: read magic: %w", err)
	}

	// ZIP magic: PK\x03\x04
	if magic[0] != 0x50 || magic[1] != 0x4b || magic[2] != 0x03 || magic[3] != 0x04 {
		return fmt.Errorf("verify zip: not a valid ZIP file (magic: %x)", magic)
	}

	return nil
}

func (rs *RuleSyncer) download(url, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("download: mkdir: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download: http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: unexpected status %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("download: create: %w", err)
	}
	defer f.Close()

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("download: write: %w", err)
	}

	rs.logger.Info().
		Str("url", url).
		Int64("bytes", written).
		Msg("rule syncer: download complete")

	return nil
}

func (rs *RuleSyncer) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func (rs *RuleSyncer) archiveCurrent() error {
	if _, err := os.Stat(rs.cfg.RulesFilepath); os.IsNotExist(err) {
		return nil
	}

	if err := os.MkdirAll(rs.cfg.RulesArchiveDir, 0o755); err != nil {
		return fmt.Errorf("archive: mkdir: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	archivePath := filepath.Join(rs.cfg.RulesArchiveDir, fmt.Sprintf("rules-%s.zip", timestamp))

	src, err := os.Open(rs.cfg.RulesFilepath)
	if err != nil {
		return fmt.Errorf("archive: open source: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("archive: create dest: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("archive: copy: %w", err)
	}

	rs.logger.Info().Str("archive", archivePath).Msg("rule syncer: current rules archived")
	return nil
}

func (rs *RuleSyncer) pruneArchives() error {
	entries, err := os.ReadDir(rs.cfg.RulesArchiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("prune: read dir: %w", err)
	}

	var archives []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "rules-") && strings.HasSuffix(e.Name(), ".zip") {
			archives = append(archives, filepath.Join(rs.cfg.RulesArchiveDir, e.Name()))
		}
	}

	sort.Strings(archives)

	for i := 0; i < len(archives)-rs.cfg.RulesArchiveCount; i++ {
		if err := os.Remove(archives[i]); err != nil {
			rs.logger.Error().Err(err).Str("path", archives[i]).Msg("rule syncer: could not remove old archive")
			continue
		}
		rs.logger.Info().Str("path", archives[i]).Msg("rule syncer: pruned old archive")
	}

	return nil
}

func (rs *RuleSyncer) restartAgent() error {
	cmd := exec.Command("systemctl", "restart", "vajra")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart: %w — output: %s", err, string(out))
	}
	return nil
}
