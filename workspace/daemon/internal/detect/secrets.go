// internal/detect/secrets.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package detect

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"vajra/internal/findings"
	"vajra/internal/utilities"
	"vajra/shared/models"

	blconfig "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/rs/zerolog"

	sharedconfig "vajra/shared/config"
)

// IgnoreFileName lives alongside the database and is written by
// `vajra secrets export-ignore`, read here on construction.
const IgnoreFileName = "secrets.ignore"

type SecretsScanner struct {
	logger        *zerolog.Logger
	blScanner     *scan.Scanner
	prefilter     sources.PrefilterFunc
	writer        *findings.FindingWriter
	sysInfo       utilities.SystemInfo
	targets       []string
	scanInterval  time.Duration
	usingDefaults bool
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

	ignoredHashes, err := loadIgnoreFile(
		filepath.Join(cfg.GenericSettings.DBDirectory, IgnoreFileName),
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("secrets scanner: load ignore file: %w", err)
	}

	scanOpts := []scan.Option{
		scan.WithMinimumConfidence(scan.ConfidenceMedium),
		scan.WithMatchContext("1,1"),
		scan.WithPrecompile(),
	}
	if len(ignoredHashes) > 0 {
		scanOpts = append(scanOpts, scan.WithIgnoredFingerprints(ignoredHashes...))
		logger.Info().Int("count", len(ignoredHashes)).
			Msg("secrets scanner: loaded ignored fingerprints")
	}

	blScanner, err := scan.New(blCfg, scanOpts...)
	if err != nil {
		return nil, fmt.Errorf("secrets scanner: build betterleaks scanner: %w", err)
	}

	segments := cfg.ScanSettings.Secrets.AllExcludeSegments(cfg.GenericSettings.DBDirectory)
	pf := buildPrefilter(segments)

	logger.Info().
		Strs("exclude_segments", segments).
		Msg("secrets scanner: prefilter built")

	usingDefaults := cfg.ScanSettings.Secrets.IsDefaultConfig()
	targets := expandTargets(
		logger,
		cfg.ScanSettings.Secrets.TargetDirectories,
		cfg.ScanSettings.TargetDirectory,
	)

	return &SecretsScanner{
		logger:        logger,
		blScanner:     blScanner,
		prefilter:     pf,
		writer:        writer,
		sysInfo:       sysInfo,
		targets:       targets,
		scanInterval:  time.Duration(cfg.TimingSettings.AutorunScanTimeMin) * time.Minute,
		usingDefaults: usingDefaults,
	}, nil
}

func (ss *SecretsScanner) Name() string { return "secrets_scanner" }

func (ss *SecretsScanner) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if ss.usingDefaults {
		ss.logger.Warn().
			Strs("directories", ss.targets).
			Msg("secrets scanner: using DEFAULT target directories — " +
				"edit scan_settings.secrets.target_directories in config.yaml " +
				"before deploying to production")
	}

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
		n, err := ss.scanTarget(ctx, target)
		if err != nil && ctx.Err() == nil {
			ss.logger.Error().Err(err).Str("target", target).
				Msg("secrets scanner: target scan error")
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
		MachineID:         ss.sysInfo.MachineID,
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

// buildPrefilter skips files whose path contains any of the given segments.
func buildPrefilter(segments []string) sources.PrefilterFunc {
	return func(attributes map[string]string) bool {
		path := attributes[sources.AttrPath]
		if path == "" {
			return false
		}
		for _, seg := range segments {
			if strings.Contains(path, seg) {
				return true
			}
		}
		return false
	}
}

// loadIgnoreFile parses a betterleaks fingerprint ignore file.
// Missing file is not an error — first run or not yet exported.
func loadIgnoreFile(path string, logger *zerolog.Logger) ([]fingerprint.Hash, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("loadIgnoreFile: read %s: %w", path, err)
	}

	hashes, diagnostics, err := fingerprint.Load(strings.NewReader(string(data)))
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
			logger.Warn().Str("pattern", pattern).Err(err).
				Msg("secrets scanner: invalid glob pattern, skipping")
			continue
		}
		if len(matches) == 0 {
			logger.Warn().Str("pattern", pattern).
				Msg("secrets scanner: glob matched no paths, skipping")
			continue
		}
		for _, m := range matches {
			result = appendUnique(result, seen, m)
		}
	}

	if len(result) == 0 {
		logger.Warn().Str("fallback", fallbackDir).
			Msg("secrets scanner: no valid target directories resolved, falling back to target_directory")
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
