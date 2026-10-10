// internal/utilities/procfs.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package utilities

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcStatus holds key fields parsed from /proc/PID/status in one read.
// Reading status once and extracting all needed fields avoids the PPID,
// UID, and GID reads each opening the file separately.
type ProcStatus struct {
	PPID uint32
	UID  uint32
	GID  uint32
	EUID uint32
	EGID uint32
}

// ReadProcStatus reads /proc/PID/status once and returns the parsed fields.
// Returns zero values on any error — callers treat 0 as unknown rather than fatal.
func ReadProcStatus(pid uint32) ProcStatus {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ProcStatus{}
	}
	var s ProcStatus
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		switch {
		case bytes.HasPrefix(line, []byte("PPid:")):
			fields := bytes.Fields(line)
			if len(fields) >= 2 {
				s.PPID = uint32(parseStatusU64(fields[1]))
			}
		case bytes.HasPrefix(line, []byte("Uid:")):
			// Format: "Uid:\treal\teffective\tsaved\tfs"
			fields := bytes.Fields(line)
			if len(fields) >= 3 {
				s.UID = uint32(parseStatusU64(fields[1]))
				s.EUID = uint32(parseStatusU64(fields[2]))
			}
		case bytes.HasPrefix(line, []byte("Gid:")):
			fields := bytes.Fields(line)
			if len(fields) >= 3 {
				s.GID = uint32(parseStatusU64(fields[1]))
				s.EGID = uint32(parseStatusU64(fields[2]))
			}
		}
	}
	return s
}

func parseStatusU64(b []byte) uint64 {
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// ReadCmdline reads /proc/PID/cmdline into a space-separated string.
// The kernel delimits arguments with null bytes, not spaces — bytes.Split
// is the correct split rather than any string manipulation on the raw data.
func ReadCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	parts := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	args := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			args = append(args, string(p))
		}
	}
	return strings.Join(args, " ")
}
