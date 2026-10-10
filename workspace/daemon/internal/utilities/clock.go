// internal/utilities/clock.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package utilities

import (
	"fmt"
	"os"
	"strings"
	"syscall"
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
// (nanoseconds since boot) to Unix epoch seconds for DB storage.
// Sub-second precision is truncated — use EBPFTimestampToUnixNano
// when event ordering within the same second matters.
func (s SystemInfo) EBPFTimestampToUnix(nsecSinceBoot uint64) int64 {
	return s.BootEpoch + int64(nsecSinceBoot)/int64(time.Second)
}

// EBPFTimestampToUnixNano converts a bpf_ktime_get_ns() timestamp to
// nanoseconds since Unix epoch. Use this for sub-second event ordering
// in the eBPF dispatcher; EBPFTimestampToUnix is for DB storage.
func (s SystemInfo) EBPFTimestampToUnixNano(nsecSinceBoot uint64) int64 {
	return s.BootEpoch*int64(time.Second) + int64(nsecSinceBoot)
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

// readBootEpoch uses syscall.Sysinfo to get uptime — one syscall with no
// text parsing, no float conversion, and no allocation. Parsing /proc/uptime
// as a float would lose precision and require string handling for no gain.
func readBootEpoch() (int64, error) {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0, fmt.Errorf("sysinfo: %w", err)
	}
	// Subtract in a single expression to minimise the window between
	// the syscall and the wall clock read.
	return time.Now().Unix() - si.Uptime, nil
}
