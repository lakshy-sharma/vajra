// internal/procanalyzer/capability.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package procanalyzer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"vajra/internal/analyzer"
	"vajra/shared/models"
)

// dangerousCapabilities maps capability bit positions to names.
// These are the capabilities that provide meaningful privilege
// escalation or evasion when held by unexpected processes.
//
// CAP_SYS_ADMIN  (21) — broadest capability, nearly root
// CAP_SYS_PTRACE (19) — can inspect and control any process
// CAP_NET_RAW    (13) — raw socket access, packet crafting
// CAP_DAC_OVERRIDE(1) — bypass file permission checks
// CAP_SETUID     (7)  — can assume any UID including root
// CAP_SETGID     (6)  — can assume any GID
// CAP_SYS_MODULE (16) — can load/unload kernel modules
var dangerousCapabilities = map[uint]string{
	1:  "CAP_DAC_OVERRIDE",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	13: "CAP_NET_RAW",
	16: "CAP_SYS_MODULE",
	19: "CAP_SYS_PTRACE",
	21: "CAP_SYS_ADMIN",
}

// CapabilityAnalyzer reads /proc/PID/status and checks the
// CapEff (effective capability) bitmask for dangerous capabilities.
//
// Intentionally does NOT consult the process exclusion list —
// a trusted process name holding CAP_SYS_ADMIN is more suspicious
// than an unknown one, not less. A compromised system daemon is
// exactly the threat model this catches.
//
// Severity: HIGH.
type CapabilityAnalyzer struct {
	logger *zerolog.Logger
}

func NewCapabilityAnalyzer(logger *zerolog.Logger) *CapabilityAnalyzer {
	return &CapabilityAnalyzer{logger: logger}
}

func (a *CapabilityAnalyzer) Name() string {
	return "capability"
}

// Analyze reads /proc/PID/status and parses the CapEff field.
func (a *CapabilityAnalyzer) Analyze(ctx context.Context, path string) (analyzer.AnalysisResult, error) {
	pid, ok := analyzer.PIDFromCtx(ctx)
	if !ok || pid == 0 {
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	capEff, err := readCapEff(pid)
	if err != nil {
		a.logger.Debug().
			Err(err).
			Uint32("pid", pid).
			Msg("capability: could not read CapEff, process likely exited")
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	// Check each dangerous capability bit.
	var found []string
	for bit, name := range dangerousCapabilities {
		if capEff&(1<<bit) != 0 {
			found = append(found, name)
		}
	}

	if len(found) == 0 {
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	a.logger.Warn().
		Uint32("pid", pid).
		Str("exe", path).
		Strs("capabilities", found).
		Uint64("cap_eff", capEff).
		Msg("capability: dangerous effective capabilities detected")

	return analyzer.AnalysisResult{
		Severity: models.SeverityHigh,
		Notes:    fmt.Sprintf("dangerous_caps: %s", strings.Join(found, ", ")),
	}, nil
}

// readCapEff parses the CapEff line from /proc/PID/status.
// Returns the effective capability bitmask as a uint64.
func readCapEff(pid uint32) (uint64, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	f, err := os.Open(statusPath)
	if err != nil {
		return 0, fmt.Errorf("capability: open %s: %w", statusPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		// Format: "CapEff:\t000001ffffffffff"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("capability: unexpected CapEff format: %q", line)
		}
		val, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("capability: parse CapEff %q: %w", fields[1], err)
		}
		return val, nil
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("capability: scan %s: %w", statusPath, err)
	}

	return 0, fmt.Errorf("capability: CapEff not found in %s", statusPath)
}
