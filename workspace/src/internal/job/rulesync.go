// internal/job/rulesync.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package job

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

// RuleSyncer checks YARA Forge for new rule releases and updates
// the local rules archive. Restarts the agent via systemd on update.
type RuleSyncer struct {
	logger *zerolog.Logger
	cfg    utilities.RulesSettings
}

func NewRuleSyncer(logger *zerolog.Logger, cfg utilities.RulesSettings) *RuleSyncer {
	return &RuleSyncer{logger: logger, cfg: cfg}
}

func (rs *RuleSyncer) Name() string { return "rule_syncer" }

func (rs *RuleSyncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	rs.logger.Info().Int("interval_hours", rs.cfg.RulesSyncIntervalHour).Msg("rule syncer started")

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

// RunOnce is the CLI entry point for vajra rules update.
func (rs *RuleSyncer) RunOnce() error {
	return rs.sync()
}

func (rs *RuleSyncer) LocalHash() (string, error) {
	return hashFile(rs.cfg.RulesFilepath)
}

func (rs *RuleSyncer) sync() error {
	rs.logger.Info().Msg("rule syncer: checking for updates")

	remoteTag, err := rs.fetchLatestTag()
	if err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: fetch tag failed, skipping")
		return fmt.Errorf("rulesync: fetch tag: %w", err)
	}

	localTag := rs.readLocalTag()
	if remoteTag == localTag {
		rs.logger.Info().Str("tag", localTag).Msg("rule syncer: rules up to date")
		return nil
	}

	rs.logger.Info().Str("local", localTag).Str("remote", remoteTag).Msg("rule syncer: update available")

	stagingPath := rs.cfg.RulesFilepath + ".staging"
	if err := rs.download(rs.cfg.RulesRemoteURL, stagingPath); err != nil {
		os.Remove(stagingPath)
		return fmt.Errorf("rulesync: download: %w", err)
	}

	if err := rs.verifyZip(stagingPath); err != nil {
		os.Remove(stagingPath)
		return fmt.Errorf("rulesync: verify: %w", err)
	}

	if err := rs.archiveCurrent(); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: archive failed, continuing")
	}

	if err := os.Rename(stagingPath, rs.cfg.RulesFilepath); err != nil {
		os.Remove(stagingPath)
		return fmt.Errorf("rulesync: replace: %w", err)
	}

	if err := rs.writeLocalTag(remoteTag); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: version tag write failed")
	}

	rs.logger.Info().Str("tag", remoteTag).Msg("rule syncer: rules updated")

	if err := rs.pruneArchives(); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: archive pruning failed")
	}

	rs.logger.Info().Msg("rule syncer: restarting agent")
	if err := rs.restartAgent(); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: restart failed — new rules load on next start")
		return fmt.Errorf("rulesync: restart: %w", err)
	}
	return nil
}

func (rs *RuleSyncer) fetchLatestTag() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, yaraForgeAPIURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "vajra-edr")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("empty tag_name in response")
	}
	return release.TagName, nil
}

func (rs *RuleSyncer) tagFilePath() string {
	return filepath.Join(filepath.Dir(rs.cfg.RulesFilepath), rulesTagFilename)
}

func (rs *RuleSyncer) readLocalTag() string {
	data, err := os.ReadFile(rs.tagFilePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (rs *RuleSyncer) writeLocalTag(tag string) error {
	return os.WriteFile(rs.tagFilePath(), []byte(tag), 0o644)
}

func (rs *RuleSyncer) verifyZip(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return err
	}
	// PK\x03\x04
	if magic[0] != 0x50 || magic[1] != 0x4b || magic[2] != 0x03 || magic[3] != 0x04 {
		return fmt.Errorf("not a valid ZIP (magic: %x)", magic)
	}
	return nil
}

func (rs *RuleSyncer) download(url, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	rs.logger.Info().Int64("bytes", written).Msg("rule syncer: download complete")
	return nil
}

func (rs *RuleSyncer) archiveCurrent() error {
	if _, err := os.Stat(rs.cfg.RulesFilepath); os.IsNotExist(err) {
		return nil
	}
	if err := os.MkdirAll(rs.cfg.RulesArchiveDir, 0o755); err != nil {
		return err
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	archivePath := filepath.Join(rs.cfg.RulesArchiveDir, fmt.Sprintf("rules-%s.zip", timestamp))

	src, err := os.Open(rs.cfg.RulesFilepath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	rs.logger.Info().Str("archive", archivePath).Msg("rule syncer: rules archived")
	return nil
}

func (rs *RuleSyncer) pruneArchives() error {
	entries, err := os.ReadDir(rs.cfg.RulesArchiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
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
			rs.logger.Error().Err(err).Str("path", archives[i]).Msg("rule syncer: prune failed")
		}
	}
	return nil
}

func (rs *RuleSyncer) restartAgent() error {
	out, err := exec.Command("systemctl", "restart", "vajra").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w — output: %s", err, string(out))
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
