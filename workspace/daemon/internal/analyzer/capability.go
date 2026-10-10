// internal/analyzer/capability.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package analyzer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"vajra/shared/models"
)

// dangerousCapabilities maps bit positions to names.
// These capabilities provide meaningful privilege escalation or
// evasion when held by unexpected processes.
var dangerousCapabilities = map[uint]string{
	1:  "CAP_DAC_OVERRIDE",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	13: "CAP_NET_RAW",
	16: "CAP_SYS_MODULE",
	19: "CAP_SYS_PTRACE",
	21: "CAP_SYS_ADMIN",
}

// CapabilityAnalyzer checks /proc/PID/status for dangerous effective
// capabilities. Intentionally ignores the process exclusion list —
// a trusted process holding CAP_SYS_ADMIN is more suspicious, not less.
type CapabilityAnalyzer struct {
	logger *zerolog.Logger
}

func NewCapabilityAnalyzer(logger *zerolog.Logger) *CapabilityAnalyzer {
	return &CapabilityAnalyzer{logger: logger}
}

func (a *CapabilityAnalyzer) Name() string { return "capability" }

func (a *CapabilityAnalyzer) Analyze(ctx context.Context, path string) (Result, error) {
	pid, ok := PIDFromCtx(ctx)
	if !ok || pid == 0 {
		return Result{Severity: models.SeverityClean}, nil
	}

	capEff, err := readCapEff(pid)
	if err != nil {
		return Result{Severity: models.SeverityClean}, nil
	}

	var found []string
	for bit, name := range dangerousCapabilities {
		if capEff&(1<<bit) != 0 {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return Result{Severity: models.SeverityClean}, nil
	}

	a.logger.Warn().
		Uint32("pid", pid).
		Str("exe", path).
		Strs("capabilities", found).
		Uint64("cap_eff", capEff).
		Msg("capability: dangerous effective capabilities")

	return Result{
		Severity: models.SeverityHigh,
		Notes:    "dangerous_caps: " + strings.Join(found, ", "),
	}, nil
}

func readCapEff(pid uint32) (uint64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("capability: unexpected CapEff format: %q", line)
		}
		return strconv.ParseUint(fields[1], 16, 64)
	}
	return 0, fmt.Errorf("capability: CapEff not found for pid %d", pid)
}
