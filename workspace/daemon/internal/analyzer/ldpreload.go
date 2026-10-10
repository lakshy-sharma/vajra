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
	"vajra/shared/models"
)

// standardLibPaths are the directories LD_PRELOAD and LD_LIBRARY_PATH
// entries must reside in to be considered legitimate.
var standardLibPaths = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	"/usr/local/lib",
	"/usr/local/lib64",
	"/snap/",
	"/var/lib/snapd/",
}

// LDPreloadAnalyzer checks /proc/PID/environ for LD_PRELOAD or
// LD_LIBRARY_PATH entries pointing outside standard library paths.
// Catches runtime injection that the autorun scanner misses because
// autorun only checks /etc/ld.so.preload at rest.
type LDPreloadAnalyzer struct {
	logger *zerolog.Logger
}

func NewLDPreloadAnalyzer(logger *zerolog.Logger) *LDPreloadAnalyzer {
	return &LDPreloadAnalyzer{logger: logger}
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
	sc.Split(splitOnNull)

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
			if libPath == "" || isStandardLibPath(libPath) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s=%s", key, libPath))
			a.logger.Warn().
				Uint32("pid", pid).
				Str("exe", path).
				Str("key", key).
				Str("value", libPath).
				Msg("ldpreload: non-standard library path")
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

func isStandardLibPath(p string) bool {
	for _, std := range standardLibPaths {
		if strings.HasPrefix(p, std) {
			return true
		}
	}
	return false
}

// splitOnNull is a bufio.SplitFunc for null-delimited /proc/PID/environ.
func splitOnNull(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
