// internal/detect/secrets.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package detect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	blconfig "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/rs/zerolog"

	"vajra/internal/findings"
	"vajra/internal/utilities"
	sharedconfig "vajra/shared/config"
	"vajra/shared/models"
)

type SecretsScanner struct {
	logger        *zerolog.Logger
	blScanner     *scan.Scanner
	prefilter     sources.PrefilterFunc
	writer        *findings.FindingWriter
	sysInfo       utilities.SystemInfo
	targets       []string
	scanInterval  time.Duration
	targetTimeout time.Duration // W18: per-target time budget
}

func NewSecretsScanner(
	logger *zerolog.Logger,
	writer *findings.FindingWriter,
	sysInfo utilities.SystemInfo,
	cfg *sharedconfig.Config,
) (*SecretsScanner, error) {
	blCfg, err := blconfig.Default()
	if err != nil {
		return nil, fmt.Errorf("secrets scanner: load betterleaks config: %w", err)
	}

	scanOpts := []scan.Option{
		scan.WithMinimumConfidence(confidenceLevel(cfg.SecretsSettings.MinimumConfidence)), // W15
		scan.WithMatchContext(contextLines(cfg.SecretsSettings.MatchContextLines)),
		scan.WithPrecompile(),
	}

	// W16: ignore file path comes from config, not a hardcoded constant.
	if cfg.SecretsSettings.IgnoreFile != "" {
		ignoredHashes, err := loadIgnoreFile(cfg.SecretsSettings.IgnoreFile, logger)
		if err != nil {
			return nil, fmt.Errorf("secrets scanner: load ignore file: %w", err)
		}
		if len(ignoredHashes) > 0 {
			scanOpts = append(scanOpts, scan.WithIgnoredFingerprints(ignoredHashes...))
			logger.Info().Int("count", len(ignoredHashes)).Msg("secrets scanner: loaded ignored fingerprints")
		}
	}

	blScanner, err := scan.New(blCfg, scanOpts...)
	if err != nil {
		return nil, fmt.Errorf("secrets scanner: build betterleaks scanner: %w", err)
	}

	// Exclude own DB directory plus any operator-configured paths.
	excludedPaths := append(cfg.SecretsSettings.ExcludedPaths, cfg.GenericSettings.DBDirectory)
	prefilter := buildPrefilter(excludedPaths)

	targets := expandTargets(logger, cfg.SecretsSettings.ScanTargets, cfg.ScanSettings.TargetDirectory)

	return &SecretsScanner{
		logger:        logger,
		blScanner:     blScanner,
		prefilter:     prefilter,
		writer:        writer,
		sysInfo:       sysInfo,
		targets:       targets,
		scanInterval:  time.Duration(cfg.TimingSettings.SecretsScanIntervalMin) * time.Minute,        // W17
		targetTimeout: time.Duration(cfg.TimingSettings.SingleTargetSecretsTimeoutMin) * time.Minute, // W18
	}, nil
}

func (ss *SecretsScanner) Name() string { return "secrets_scanner" }

func (ss *SecretsScanner) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ss.logger.Info().Strs("targets", ss.targets).Msg("secrets scanner started")

	ss.runOnce(ctx)

	ticker := time.NewTicker(ss.scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			ss.logger.Info().Msg("secrets scanner stopped")
			return
		case <-ticker.C:
			ss.runOnce(ctx)
		}
	}
}

func (ss *SecretsScanner) runOnce(ctx context.Context) {
	start := time.Now()
	ss.logger.Debug().Strs("targets", ss.targets).Msg("secrets scanner: scan started")

	var totalFindings int
	for _, target := range ss.targets {
		if ctx.Err() != nil {
			break
		}
		// W18: each target gets its own deadline so a large directory cannot
		// starve other targets or block the scanner indefinitely.
		targetCtx, cancel := context.WithTimeout(ctx, ss.targetTimeout)
		n, err := ss.scanTarget(targetCtx, target)
		cancel()
		if err != nil && ctx.Err() == nil {
			ss.logger.Error().Err(err).Str("target", target).Msg("secrets scanner: target scan error")
		}
		totalFindings += n
	}

	ss.logger.Info().
		Int("findings", totalFindings).
		Strs("targets", ss.targets).
		Str("elapsed", time.Since(start).Round(time.Millisecond).String()).
		Msg("secrets scanner: scan complete")
}

func (ss *SecretsScanner) scanTarget(ctx context.Context, target string) (int, error) {
	src := &sources.Files{
		Path:           target,
		FollowSymlinks: false,
		Prefilter:      ss.prefilter,
	}

	var written int
	_, err := ss.blScanner.Scan(ctx, src, func(f report.Finding) error {
		if writeErr := ss.handleFinding(ctx, f); writeErr != nil {
			ss.logger.Error().Err(writeErr).
				Str("rule", f.RuleID).
				Str("path", f.Location.Path).
				Msg("secrets scanner: write failed")
		} else {
			written++
		}
		return nil
	})
	return written, err
}

func (ss *SecretsScanner) handleFinding(ctx context.Context, f report.Finding) error {
	filePath := f.Location.Path
	if filePath == "" {
		filePath = f.Attr(sources.AttrPath)
	}

	secretHash := hashSecret(f.Match.Value)
	if secretHash == "" {
		secretHash = f.Match.Fingerprint
	}
	if secretHash == "" {
		return nil
	}

	matchContext := f.Match.Context
	if matchContext == "" {
		matchContext = redactValue(f.Match.Line, f.Match.Value)
	}

	vjFinding := findings.Finding{
		Source:            findings.SourceSecretsScanner,
		Severity:          blConfidenceToSeverity(f.Confidence),
		Status:            models.StatusNew,
		DetectedAt:        time.Now().Unix(),
		TargetPath:        filePath,
		RuleID:            f.RuleID,
		Notes:             f.Description,
		SecretRuleID:      f.RuleID,
		SecretHash:        secretHash,
		SecretFingerprint: f.Match.Fingerprint,
		SecretStartLine:   f.Location.StartLine,
		SecretEndLine:     f.Location.EndLine,
		SecretContext:     matchContext,
	}

	id, err := ss.writer.Write(ctx, vjFinding)
	if err != nil {
		return err
	}

	if id > 0 {
		ss.logger.Warn().
			Str("rule", f.RuleID).
			Str("path", filePath).
			Int("line", f.Location.StartLine).
			Str("confidence", f.Confidence).
			Str("severity", string(vjFinding.Severity)).
			Msg("SECRET DETECTED")
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────

func buildPrefilter(excludedPaths []string) sources.PrefilterFunc {
	return func(attributes map[string]string) bool {
		path := attributes[sources.AttrPath]
		if path == "" {
			return false
		}
		for _, seg := range excludedPaths {
			if strings.Contains(path, seg) {
				return true
			}
		}
		return false
	}
}

// loadIgnoreFile parses a betterleaks fingerprint ignore file.
// Missing file is not an error — first run or ignore file not yet created.
func loadIgnoreFile(path string, logger *zerolog.Logger) ([]fingerprint.Hash, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("loadIgnoreFile: read %s: %w", path, err)
	}

	// bytes.NewReader avoids an extra string allocation vs strings.NewReader(string(data)).
	hashes, diagnostics, err := fingerprint.Load(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("loadIgnoreFile: parse: %w", err)
	}
	for _, d := range diagnostics {
		logger.Warn().
			Int("line", d.Line).
			Str("reason", d.Reason).
			Str("path", path).
			Msg("secrets scanner: ignore file parse warning")
	}
	return hashes, nil
}

func expandTargets(logger *zerolog.Logger, configured []string, fallbackDir string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, pattern := range configured {
		if !containsGlob(pattern) {
			result = appendUnique(result, seen, pattern)
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			logger.Warn().Str("pattern", pattern).Err(err).Msg("secrets scanner: invalid glob pattern, skipping")
			continue
		}
		if len(matches) == 0 {
			logger.Warn().Str("pattern", pattern).Msg("secrets scanner: glob matched no paths, skipping")
			continue
		}
		for _, m := range matches {
			result = appendUnique(result, seen, m)
		}
	}

	if len(result) == 0 {
		logger.Warn().Str("fallback", fallbackDir).Msg("secrets scanner: no valid target directories resolved, falling back to target_directory")
		return []string{fallbackDir}
	}
	return result
}

func containsGlob(s string) bool {
	for _, c := range s {
		if c == '*' || c == '?' || c == '[' {
			return true
		}
	}
	return false
}

func appendUnique(result []string, seen map[string]struct{}, path string) []string {
	if _, ok := seen[path]; ok {
		return result
	}
	seen[path] = struct{}{}
	return append(result, path)
}

func hashSecret(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum)
}

// confidenceLevel maps the config int (0–100) to a betterleaks confidence constant.
// W15: was hardcoded to ConfidenceMedium.
func confidenceLevel(minConf int) string {
	switch {
	case minConf >= 80:
		return scan.ConfidenceHigh
	case minConf >= 50:
		return scan.ConfidenceMedium
	default:
		return scan.ConfidenceLow
	}
}

// contextLines converts an int line count to the "before,after" string
// format expected by betterleaks WithMatchContext.
func contextLines(n int) string {
	if n <= 0 {
		n = 1
	}
	s := strconv.Itoa(n)
	return s + "," + s
}

func blConfidenceToSeverity(confidence string) models.EventSeverity {
	switch confidence {
	case scan.ConfidenceHigh:
		return models.SeverityCritical
	case scan.ConfidenceMedium:
		return models.SeverityHigh
	case scan.ConfidenceLow:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

func redactValue(line, value string) string {
	if value == "" || line == "" {
		return line
	}
	for i := 0; i <= len(line)-len(value); i++ {
		if line[i:i+len(value)] == value {
			return line[:i] + "[REDACTED]" + line[i+len(value):]
		}
	}
	return line
}
