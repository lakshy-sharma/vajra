// internal/analyzer/ldpreload.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"vajra/internal/utilities"
	sharedconfig "vajra/shared/config"
	"vajra/shared/models"
)

// LDPreloadAnalyzer checks /proc/PID/environ for LD_PRELOAD or
// LD_LIBRARY_PATH entries pointing outside the operator-configured
// trusted library path whitelist.
//
// A whitelist is the correct model here: the set of legitimate library
// directories is small and stable, while the set of attacker-controlled
// paths (tmpfs, /dev/shm, home directories, arbitrary overlays) is
// unbounded and grows with each new technique.
type LDPreloadAnalyzer struct {
	logger       *zerolog.Logger
	trustedPaths []string // from AlertPolicySettings.TrustedLDPaths
}

func NewLDPreloadAnalyzer(logger *zerolog.Logger, policy sharedconfig.AlertPolicySettings) *LDPreloadAnalyzer {
	return &LDPreloadAnalyzer{
		logger:       logger,
		trustedPaths: policy.TrustedLDPaths,
	}
}

func (a *LDPreloadAnalyzer) Name() string { return "ldpreload" }

func (a *LDPreloadAnalyzer) Analyze(ctx context.Context, path string) (Result, error) {
	pid, ok := PIDFromCtx(ctx)
	if !ok || pid == 0 {
		return Result{Severity: models.SeverityClean}, nil
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		// Process already exited — not worth surfacing.
		return Result{Severity: models.SeverityClean}, nil
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Split(utilities.NullScanner)

	var findings []string
	for sc.Scan() {
		entry := sc.Text()
		idx := strings.IndexByte(entry, '=')
		if idx < 0 {
			continue
		}
		key, value := entry[:idx], entry[idx+1:]
		if key != "LD_PRELOAD" && key != "LD_LIBRARY_PATH" {
			continue
		}
		for _, libPath := range strings.Split(value, ":") {
			libPath = strings.TrimSpace(libPath)
			if libPath == "" || a.isTrusted(libPath) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s=%s", key, libPath))
			a.logger.Warn().
				Uint32("pid", pid).
				Str("exe", path).
				Str("key", key).
				Str("value", libPath).
				Msg("ldpreload: library path outside trusted whitelist")
		}
	}

	if len(findings) == 0 {
		return Result{Severity: models.SeverityClean}, nil
	}
	return Result{
		Severity: models.SeverityHigh,
		Notes:    "ld_preload: " + strings.Join(findings, ", "),
	}, nil
}

// isTrusted reports whether libPath begins with a known-good library
// directory. Uses utilities.HasPathPrefix to prevent /usr/lib.evil matching /usr/lib.
func (a *LDPreloadAnalyzer) isTrusted(libPath string) bool {
	for _, trusted := range a.trustedPaths {
		if utilities.HasPathPrefix(libPath, trusted) {
			return true
		}
	}
	return false
}
