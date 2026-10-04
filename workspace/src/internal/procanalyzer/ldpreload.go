// internal/procanalyzer/ldpreload.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package procanalyzer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"vajra/internal/analyzer"
	"vajra/shared/models"
)

// standardLibPaths are the directories LD_PRELOAD and
// LD_LIBRARY_PATH entries must reside in to be considered
// legitimate. Paths outside these are flagged as suspicious.
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

// LDPreloadAnalyzer reads /proc/PID/environ on every execve
// event and checks for LD_PRELOAD or LD_LIBRARY_PATH entries
// pointing outside standard library paths.
//
// This closes the gap between the autorun scanner (which checks
// /etc/ld.so.preload at rest) and runtime injection (which sets
// the variable in the process environment at exec time).
//
// Severity: HIGH.
// A process with LD_PRELOAD set to a non-standard path is a
// strong indicator of library injection or hooking.
type LDPreloadAnalyzer struct {
	logger *zerolog.Logger
}

func NewLDPreloadAnalyzer(logger *zerolog.Logger) *LDPreloadAnalyzer {
	return &LDPreloadAnalyzer{logger: logger}
}

func (a *LDPreloadAnalyzer) Name() string {
	return "ldpreload"
}

// Analyze reads /proc/PID/environ and checks LD_PRELOAD and
// LD_LIBRARY_PATH. Returns HIGH if any suspicious path is found.
func (a *LDPreloadAnalyzer) Analyze(ctx context.Context, path string) (analyzer.AnalysisResult, error) {
	pid, ok := analyzer.PIDFromCtx(ctx)
	if !ok || pid == 0 {
		// No PID in context — not a process event, skip silently.
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	environPath := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(environPath)
	if err != nil {
		// Process already exited — not an error worth surfacing.
		a.logger.Debug().
			Uint32("pid", pid).
			Str("path", environPath).
			Msg("ldpreload: could not read environ, process likely exited")
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	// /proc/PID/environ is a sequence of null-terminated KEY=VALUE
	// strings. bufio.Scanner with a null-byte split handles this.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(splitNull)

	var findings []string

	for scanner.Scan() {
		entry := scanner.Text()

		var key, value string
		if idx := strings.IndexByte(entry, '='); idx >= 0 {
			key = entry[:idx]
			value = entry[idx+1:]
		} else {
			continue
		}

		if key != "LD_PRELOAD" && key != "LD_LIBRARY_PATH" {
			continue
		}

		// Each variable can contain colon-separated paths.
		for _, libPath := range strings.Split(value, ":") {
			libPath = strings.TrimSpace(libPath)
			if libPath == "" {
				continue
			}
			if !isStandardLibPath(libPath) {
				findings = append(findings,
					fmt.Sprintf("%s=%s", key, libPath))
				a.logger.Warn().
					Uint32("pid", pid).
					Str("exe", path).
					Str("variable", key).
					Str("value", libPath).
					Msg("ldpreload: non-standard library path detected")
			}
		}
	}

	if len(findings) == 0 {
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	return analyzer.AnalysisResult{
		Severity: models.SeverityHigh,
		Notes:    fmt.Sprintf("ld_preload: %s", strings.Join(findings, ", ")),
	}, nil
}

// isStandardLibPath returns true if libPath is under one of the
// known-good library directories. Prefix match is intentional —
// /usr/lib/x86_64-linux-gnu/ is legitimate even though it is not
// in the exact list above.
func isStandardLibPath(libPath string) bool {
	for _, std := range standardLibPaths {
		if strings.HasPrefix(libPath, std) {
			return true
		}
	}
	return false
}

// splitNull is a bufio.SplitFunc that splits on null bytes.
// Used to parse /proc/PID/environ which is null-delimited.
func splitNull(data []byte, atEOF bool) (advance int, token []byte, err error) {
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
