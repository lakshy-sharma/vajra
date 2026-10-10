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
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	sharedconfig "vajra/shared/config"
	"vajra/shared/models"
)

// capabilityBits maps Linux capability names to their bit positions in CapEff.
// These are kernel ABI constants — the bit assignments never change for
// capabilities that exist; new kernel capabilities receive new, higher bits.
var capabilityBits = map[string]uint{
	"CAP_CHOWN":              0,
	"CAP_DAC_OVERRIDE":       1,
	"CAP_DAC_READ_SEARCH":    2,
	"CAP_FOWNER":             3,
	"CAP_FSETID":             4,
	"CAP_KILL":               5,
	"CAP_SETGID":             6,
	"CAP_SETUID":             7,
	"CAP_SETPCAP":            8,
	"CAP_NET_BIND_SERVICE":   10,
	"CAP_NET_ADMIN":          12,
	"CAP_NET_RAW":            13,
	"CAP_SYS_MODULE":         16,
	"CAP_SYS_RAWIO":          17,
	"CAP_SYS_PTRACE":         19,
	"CAP_SYS_ADMIN":          21,
	"CAP_SETFCAP":            31,
	"CAP_PERFMON":            38,
	"CAP_BPF":                39,
	"CAP_CHECKPOINT_RESTORE": 40,
}

// CapabilityAnalyzer checks /proc/PID/status for dangerous effective
// capabilities. Which capabilities are dangerous is operator-configurable —
// the list comes from AlertPolicySettings rather than being hardcoded here.
type CapabilityAnalyzer struct {
	logger     *zerolog.Logger
	dangerBits map[string]uint     // name → bit, pre-resolved from config at construction
	exclusions map[string][]string // comm → []capability names to ignore for that process
}

func NewCapabilityAnalyzer(logger *zerolog.Logger, policy sharedconfig.AlertPolicySettings) *CapabilityAnalyzer {
	// Resolve capability names to bit positions once at startup so Analyze
	// does no map lookup against the full capabilityBits table per event.
	dangerBits := make(map[string]uint, len(policy.DangerousCapabilities))
	for _, name := range policy.DangerousCapabilities {
		if bit, ok := capabilityBits[name]; ok {
			dangerBits[name] = bit
		} else {
			logger.Warn().Str("capability", name).Msg("capability analyzer: unknown capability name in config — skipped")
		}
	}
	return &CapabilityAnalyzer{
		logger:     logger,
		dangerBits: dangerBits,
		exclusions: policy.ProcessCapabilityExclusions,
	}
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

	// comm is used to look up per-process exclusions. Read from /proc rather
	// than relying on the path basename — a symlink could have a misleading name.
	comm := readComm(pid)
	excluded := a.exclusions[comm]

	var found []string
	for name, bit := range a.dangerBits {
		if capEff&(1<<bit) == 0 {
			continue
		}
		if capExcluded(excluded, name) {
			continue
		}
		found = append(found, name)
	}
	if len(found) == 0 {
		return Result{Severity: models.SeverityClean}, nil
	}

	// Sort for deterministic Notes output — map iteration order is random.
	sort.Strings(found)

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

// readComm returns the process comm name from /proc/PID/comm.
// Returns empty string on failure — callers treat an empty comm as
// having no exclusions, which is the safe direction.
func readComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return filepath.Base(strings.TrimSpace(string(data)))
}

// capExcluded reports whether name appears in the per-process exclusion list.
func capExcluded(exclusions []string, name string) bool {
	for _, e := range exclusions {
		if e == name {
			return true
		}
	}
	return false
}
