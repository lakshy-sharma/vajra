//go:build linux

package utilities

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SystemInfo holds stable system identifiers computed once at startup.
// Pass this as a dependency to any component that needs endpoint
// identity or accurate event timestamps.
type SystemInfo struct {
	// MachineID is the content of /etc/machine-id — stable across reboots,
	// unique per OS installation, managed by systemd.
	MachineID string

	// BootEpoch is the Unix timestamp (seconds) of the last system boot.
	// Used to convert eBPF timestamps (nanoseconds since boot via
	// bpf_ktime_get_ns) to wall clock time.
	// Computed as: time.Now().Unix() - uptime_seconds
	BootEpoch int64
}

// LoadSystemInfo reads machine identity and boot time from /proc
// and /etc. Called once at startup in Entrypoint.
func LoadSystemInfo() (SystemInfo, error) {
	machineID, err := readMachineID()
	if err != nil {
		return SystemInfo{}, fmt.Errorf("system info: machine id: %w", err)
	}

	bootEpoch, err := readBootEpoch()
	if err != nil {
		return SystemInfo{}, fmt.Errorf("system info: boot epoch: %w", err)
	}

	return SystemInfo{
		MachineID: machineID,
		BootEpoch: bootEpoch,
	}, nil
}

// EBPFTimestampToUnix converts a bpf_ktime_get_ns() timestamp
// (nanoseconds since boot) to a Unix epoch second using the
// precomputed BootEpoch.
func (s SystemInfo) EBPFTimestampToUnix(nsecSinceBoot uint64) int64 {
	return s.BootEpoch + int64(nsecSinceBoot/1e9)
}

func readMachineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", fmt.Errorf("read /etc/machine-id: %w", err)
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return "", fmt.Errorf("/etc/machine-id is empty")
	}
	return id, nil
}

// readBootEpoch reads /proc/uptime and subtracts uptime from the
// current wall clock to get the Unix timestamp of last boot.
// /proc/uptime format: "<uptime_seconds> <idle_seconds>"
func readBootEpoch() (int64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("read /proc/uptime: %w", err)
	}

	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}

	// uptime is a float like "12345.67" — we only need second precision.
	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parse uptime %q: %w", fields[0], err)
	}

	// Use a single time.Now() call to avoid drift between the
	// uptime read and the wall clock read.
	nowUnix := nowUnixSeconds()
	return nowUnix - int64(uptime), nil
}

func nowUnixSeconds() int64 {
	return time.Now().Unix()
}
