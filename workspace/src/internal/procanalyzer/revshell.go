// internal/procanalyzer/revshell.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package procanalyzer

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"vajra/internal/analyzer"
	"vajra/shared/models"
)

// RevShellAnalyzer detects reverse shells by checking whether
// a process has a network socket as its stdin, stdout, or stderr.
//
// Method:
//  1. Read /proc/PID/fd/0, /proc/PID/fd/1, /proc/PID/fd/2
//     (stdin, stdout, stderr) via Readlink.
//  2. If any resolve to "socket:[inode]", extract the inode.
//  3. Check /proc/net/tcp and /proc/net/tcp6 for that inode.
//  4. If found, the process has a network socket as its terminal
//     which is a classic reverse shell pattern.
//
// Severity: CRITICAL.
// Legitimate processes do not have sockets as their stdio.
type RevShellAnalyzer struct {
	logger *zerolog.Logger
}

func NewRevShellAnalyzer(logger *zerolog.Logger) *RevShellAnalyzer {
	return &RevShellAnalyzer{logger: logger}
}

func (a *RevShellAnalyzer) Name() string {
	return "revshell"
}

// Analyze checks /proc/PID/fd/0,1,2 against /proc/net/tcp*.
func (a *RevShellAnalyzer) Analyze(ctx context.Context, path string) (analyzer.AnalysisResult, error) {
	pid, ok := analyzer.PIDFromCtx(ctx)
	if !ok || pid == 0 {
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	// ── Step 1: collect socket inodes from stdio fds ──────────
	socketInodes := make(map[uint64]int) // inode → fd number
	for _, fd := range []int{0, 1, 2} {
		fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
		target, err := os.Readlink(fdPath)
		if err != nil {
			// fd doesn't exist or process exited — not unusual.
			continue
		}

		// Symlink targets for sockets look like: socket:[1234567]
		inode, ok := parseSocketInode(target)
		if !ok {
			continue
		}
		socketInodes[inode] = fd
	}

	if len(socketInodes) == 0 {
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	// ── Step 2: check /proc/net/tcp and /proc/net/tcp6 ───────
	netConnections, err := readNetTCP()
	if err != nil {
		a.logger.Debug().
			Err(err).
			Uint32("pid", pid).
			Msg("revshell: could not read /proc/net/tcp")
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	// ── Step 3: cross-reference ───────────────────────────────
	var findings []string
	for inode, fd := range socketInodes {
		if conn, found := netConnections[inode]; found {
			fdName := fdName(fd)
			finding := fmt.Sprintf("%s→socket(inode=%d,remote=%s:%d)",
				fdName, inode, conn.remoteAddr, conn.remotePort)
			findings = append(findings, finding)

			a.logger.Warn().
				Uint32("pid", pid).
				Str("exe", path).
				Str("fd", fdName).
				Uint64("inode", inode).
				Str("remote_addr", conn.remoteAddr).
				Uint16("remote_port", conn.remotePort).
				Msg("revshell: stdio file descriptor is a network socket")
		}
	}

	if len(findings) == 0 {
		return analyzer.AnalysisResult{Severity: models.SeverityClean}, nil
	}

	return analyzer.AnalysisResult{
		Severity: models.SeverityCritical,
		Notes:    fmt.Sprintf("reverse_shell: %s", strings.Join(findings, "; ")),
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────

type netConn struct {
	remoteAddr string
	remotePort uint16
}

// parseSocketInode extracts the inode from a symlink target
// of the form "socket:[inode]". Returns 0, false if not a socket.
func parseSocketInode(target string) (uint64, bool) {
	const prefix = "socket:["
	const suffix = "]"
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, suffix) {
		return 0, false
	}
	inodeStr := target[len(prefix) : len(target)-len(suffix)]
	inode, err := strconv.ParseUint(inodeStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// readNetTCP reads /proc/net/tcp and /proc/net/tcp6 and returns
// a map of inode → connection details for all established connections.
func readNetTCP() (map[uint64]netConn, error) {
	result := make(map[uint64]netConn)

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if err := parseNetTCPFile(path, result); err != nil {
			// tcp6 may not exist on all kernels — not fatal.
			continue
		}
	}

	return result, nil
}

// parseNetTCPFile parses one /proc/net/tcp* file into the result map.
// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
func parseNetTCPFile(path string, result map[uint64]netConn) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	isIPv6 := strings.HasSuffix(path, "tcp6")

	scanner := bufio.NewScanner(f)
	// Skip header line.
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Minimum fields: sl(0) local(1) remote(2) state(3) ... inode(9)
		if len(fields) < 10 {
			continue
		}

		remoteHex := fields[2]
		inodeStr := fields[9]

		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}

		remoteAddr, remotePort, err := parseHexAddr(remoteHex, isIPv6)
		if err != nil {
			continue
		}

		result[inode] = netConn{
			remoteAddr: remoteAddr,
			remotePort: remotePort,
		}
	}

	return scanner.Err()
}

// parseHexAddr decodes a hex-encoded address:port from /proc/net/tcp*.
// IPv4 format: "0101007F:0035" (little-endian 32-bit addr, 16-bit port)
// IPv6 format: "00000000000000000000000001000000:0035" (little-endian 128-bit)
func parseHexAddr(hexAddr string, isIPv6 bool) (string, uint16, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("revshell: invalid addr format: %s", hexAddr)
	}

	addrHex := parts[0]
	portHex := parts[1]

	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("revshell: invalid port: %s", portHex)
	}

	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", 0, fmt.Errorf("revshell: invalid addr hex: %s", addrHex)
	}

	var ip net.IP
	if isIPv6 {
		if len(addrBytes) != 16 {
			return "", 0, fmt.Errorf("revshell: expected 16 bytes for ipv6, got %d", len(addrBytes))
		}
		// Reverse byte order within each 4-byte group.
		reversed := make([]byte, 16)
		for i := 0; i < 4; i++ {
			reversed[i*4+0] = addrBytes[i*4+3]
			reversed[i*4+1] = addrBytes[i*4+2]
			reversed[i*4+2] = addrBytes[i*4+1]
			reversed[i*4+3] = addrBytes[i*4+0]
		}
		ip = net.IP(reversed)
	} else {
		if len(addrBytes) != 4 {
			return "", 0, fmt.Errorf("revshell: expected 4 bytes for ipv4, got %d", len(addrBytes))
		}
		// Little-endian: reverse all 4 bytes.
		ip = net.IP([]byte{addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0]})
	}

	return ip.String(), uint16(port64), nil
}

// fdName returns a human-readable name for file descriptor 0, 1, or 2.
func fdName(fd int) string {
	switch fd {
	case 0:
		return "stdin"
	case 1:
		return "stdout"
	case 2:
		return "stderr"
	default:
		return fmt.Sprintf("fd%d", fd)
	}
}
