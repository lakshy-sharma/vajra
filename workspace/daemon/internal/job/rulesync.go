// internal/job/rulesync.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package job

import (
	"archive/zip"
	"context"
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
	sharedconfig "vajra/shared/config"
)

const (
	yaraForgeAPIURL  = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
	rulesTagFilename = ".rules_version"
)

// yaraForgeClient is reused across fetchLatestTag calls.
// J9: was created fresh on every call — unnecessary allocation and no
// connection reuse.
var yaraForgeClient = &http.Client{Timeout: 30 * time.Second}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// RuleSyncer checks YARA Forge for new rule releases and updates
// the local rules archive. Restarts the agent via systemd on update.
type RuleSyncer struct {
	logger *zerolog.Logger
	cfg    sharedconfig.RulesSettings
}

func NewRuleSyncer(logger *zerolog.Logger, cfg sharedconfig.RulesSettings) *RuleSyncer {
	return &RuleSyncer{logger: logger, cfg: cfg}
}

func (rs *RuleSyncer) Name() string { return "rule_syncer" }

func (rs *RuleSyncer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	rs.logger.Info().Int("interval_hours", rs.cfg.RulesSyncIntervalHour).Msg("rule syncer started")

	if err := rs.sync(ctx); err != nil {
		rs.logger.Error().Err(err).Msg("rule syncer: initial sync failed")
	}

	ticker := time.NewTicker(time.Duration(rs.cfg.RulesSyncIntervalHour) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			rs.logger.Info().Msg("rule syncer stopped")
			return
		case <-ticker.C:
			if err := rs.sync(ctx); err != nil {
				rs.logger.Error().Err(err).Msg("rule syncer: sync failed")
			}
		}
	}
}

// RunOnce is the CLI entry point for vajra rules update.
func (rs *RuleSyncer) RunOnce() error {
	return rs.sync(context.Background())
}

// LocalHash returns the SHA256 of the current rules file.
// J8: was a local hashFile function duplicating utilities.FullSHA256.
func (rs *RuleSyncer) LocalHash() (string, error) {
	return utilities.FullSHA256(rs.cfg.RulesFilepath)
}

func (rs *RuleSyncer) sync(ctx context.Context) error {
	rs.logger.Info().Msg("rule syncer: checking for updates")

	remoteTag, err := rs.fetchLatestTag(ctx)
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
	if err := rs.download(ctx, rs.cfg.RulesRemoteURL, stagingPath); err != nil {
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

// fetchLatestTag queries the GitHub API for the latest YARA Forge release tag.
// J9: uses package-level yaraForgeClient instead of creating a new one per call.
func (rs *RuleSyncer) fetchLatestTag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, yaraForgeAPIURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "vajra-edr")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := yaraForgeClient.Do(req)
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

// verifyZip validates the downloaded rules archive by opening its central
// directory. J7: the previous check only verified magic bytes — a truncated
// download would pass the magic check but fail to extract.
func (rs *RuleSyncer) verifyZip(path string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("verifyZip: invalid ZIP: %w", err)
	}
	defer zr.Close()
	// zip.OpenReader validates the central directory; an empty archive is
	// also invalid — a legitimate YARA Forge bundle always has rule files.
	if len(zr.File) == 0 {
		return fmt.Errorf("verifyZip: ZIP contains no files")
	}
	return nil
}

// download fetches a file from url to destPath with context support.
// J6: the previous download had no context parameter, making cancellation impossible.
func (rs *RuleSyncer) download(ctx context.Context, url, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
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
