// internal/watcher/dupwatcher.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package watcher

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/ebpf"
	"vajra/internal/findings"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

const dupDedupWindow = 30 * time.Second

type dupDedupKey struct {
	pid   uint32
	inode uint64
}

type dupDedupEntry struct {
	lastSeen time.Time
}

// DupWatcher detects reverse shells by watching dup2/dup3 onto stdio.
// Writes through FindingWriter to detections — not to security_events.
// Reverse shell is a detection, not raw telemetry.
//
// No process name filtering — any process redirecting a network socket
// onto fd 0/1/2 is suspicious regardless of comm.
type DupWatcher struct {
	logger  *zerolog.Logger
	writer  *findings.FindingWriter
	sysInfo utilities.SystemInfo
}

func NewDupWatcher(
	logger *zerolog.Logger,
	writer *findings.FindingWriter,
	sysInfo utilities.SystemInfo,
) *DupWatcher {
	return &DupWatcher{logger: logger, writer: writer, sysInfo: sysInfo}
}

func (dw *DupWatcher) Name() string { return "dup_watcher" }

func (dw *DupWatcher) Run(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.DupEvent) {
	defer wg.Done()
	dw.logger.Info().Msg("dup watcher started")

	dedup := make(map[dupDedupKey]dupDedupEntry)
	cleanupTicker := time.NewTicker(dupDedupWindow)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			dw.logger.Info().Msg("dup watcher stopped")
			return
		case <-cleanupTicker.C:
			now := time.Now()
			for k, v := range dedup {
				if now.Sub(v.lastSeen) > dupDedupWindow {
					delete(dedup, k)
				}
			}
		case event, ok := <-ch:
			if !ok {
				return
			}
			dw.handle(ctx, event, dedup)
		}
	}
}

func (dw *DupWatcher) handle(ctx context.Context, event ebpf.DupEvent, dedup map[dupDedupKey]dupDedupEntry) {
	comm := ebpf.CStringToGo(event.Comm[:])

	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", event.PID, event.OldFd))
	if err != nil {
		// Process exited before check — not unusual.
		return
	}

	inode, ok := parseSocketInode(target)
	if !ok {
		return
	}

	// Dedup before the /proc/net read — most dup2 calls are not sockets.
	key := dupDedupKey{pid: event.PID, inode: inode}
	now := time.Now()
	if entry, seen := dedup[key]; seen && now.Sub(entry.lastSeen) < dupDedupWindow {
		dw.logger.Debug().Uint32("pid", event.PID).Uint64("inode", inode).Msg("dup watcher: suppressed within window")
		return
	}
	dedup[key] = dupDedupEntry{lastSeen: now}

	netSockets, err := readNetSockets()
	if err != nil {
		dw.logger.Debug().Err(err).Uint32("pid", event.PID).Msg("dup watcher: could not read /proc/net")
		return
	}

	conn, found := netSockets[inode]
	if !found {
		// Not an inet socket — AF_UNIX and pipes correctly excluded
		// because their inodes never appear in /proc/net/tcp* or udp*.
		return
	}

	fdLabel := dupFdName(int(event.NewFd))
	dw.logger.Warn().
		Uint32("pid", event.PID).
		Uint32("ppid", event.PPID).
		Str("comm", comm).
		Str("fd", fdLabel).
		Str("proto", conn.proto).
		Str("remote", fmt.Sprintf("%s:%d", conn.remoteAddr, conn.remotePort)).
		Msg("REVERSE SHELL: stdio redirected to network socket")

	f := findings.Finding{
		Source:      findings.SourceDupWatcher,
		Severity:    models.SeverityCritical,
		Status:      models.StatusNew,
		DetectedAt:  dw.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		PID:         event.PID,
		PPID:        event.PPID,
		UID:         event.UID,
		ProcessName: comm,
		RuleID:      "reverse_shell",
		Notes:       fmt.Sprintf("reverse_shell: comm=%s %s→%s(inode=%d,remote=%s:%d)", comm, fdLabel, conn.proto, inode, conn.remoteAddr, conn.remotePort),
		RemoteAddr:  conn.remoteAddr,
		RemotePort:  conn.remotePort,
		Protocol:    conn.proto,
		SocketInode: inode,
	}

	if _, err := dw.writer.Write(ctx, f); err != nil {
		dw.logger.Error().Err(err).Uint32("pid", event.PID).Msg("dup watcher: write failed")
	}
}

// ── Socket helpers ────────────────────────────────────────────

type netConn struct {
	remoteAddr string
	remotePort uint16
	proto      string
}

func parseSocketInode(target string) (uint64, bool) {
	const prefix = "socket:["
	const suffix = "]"
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, suffix) {
		return 0, false
	}
	inode, err := strconv.ParseUint(target[len(prefix):len(target)-len(suffix)], 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

func readNetSockets() (map[uint64]netConn, error) {
	result := make(map[uint64]netConn)
	for _, entry := range []struct {
		path  string
		proto string
		ipv6  bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp6", true},
	} {
		_ = parseNetFile(entry.path, entry.proto, entry.ipv6, result)
	}
	return result, nil
}

func parseNetFile(path, proto string, isIPv6 bool, result map[uint64]netConn) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // skip header

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseHexAddr(fields[2], isIPv6)
		if err != nil {
			continue
		}
		result[inode] = netConn{remoteAddr: remoteAddr, remotePort: remotePort, proto: proto}
	}
	return sc.Err()
}

func parseHexAddr(hexAddr string, isIPv6 bool) (string, uint16, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("dupwatcher: invalid addr: %s", hexAddr)
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("dupwatcher: invalid port: %s", parts[1])
	}
	addrBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, fmt.Errorf("dupwatcher: invalid addr hex: %s", parts[0])
	}

	var ip net.IP
	if isIPv6 {
		if len(addrBytes) != 16 {
			return "", 0, fmt.Errorf("dupwatcher: ipv6 needs 16 bytes, got %d", len(addrBytes))
		}
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
			return "", 0, fmt.Errorf("dupwatcher: ipv4 needs 4 bytes, got %d", len(addrBytes))
		}
		ip = net.IP([]byte{addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0]})
	}
	return ip.String(), uint16(port64), nil
}

func dupFdName(fd int) string {
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
