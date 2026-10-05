// internal/jobs/dupwatcher.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

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
	"vajra/internal/db/queries"
	"vajra/internal/ebpf"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

const dupDedupWindow = 30 * time.Second

// dupDedupKey uniquely identifies a reverse shell detection.
// Keyed on pid+inode so the same process redirecting the same
// socket multiple times within the window is suppressed.
type dupDedupKey struct {
	pid   uint32
	inode uint64
}

type dupDedupEntry struct {
	lastSeen time.Time
}

// DupWatcher consumes DupEvents from the dup2/dup3 tracepoints and
// performs a socket check on the source fd. If oldfd resolves to a
// network socket, the process has redirected a network connection onto
// stdio — a reverse shell regardless of what process it is.
//
// No process name filtering is applied. Any process that dup2s a network
// socket onto fd 0, 1, or 2 is suspicious — a trojaned cron job or
// daemon doing this is more suspicious than a shell doing it, not less.
//
// Deduplication: same pid+inode within dupDedupWindow suppresses repeated
// inserts. bash -i >& /dev/tcp/... calls dup2 multiple times for the same
// socket — without dedup this produces a storm of identical CRITICAL rows.
type DupWatcher struct {
	logger  *zerolog.Logger
	secQ    *queries.SecurityQueries
	sysInfo utilities.SystemInfo
}

func NewDupWatcher(
	logger *zerolog.Logger,
	secQ *queries.SecurityQueries,
	sysInfo utilities.SystemInfo,
) *DupWatcher {
	return &DupWatcher{
		logger:  logger,
		secQ:    secQ,
		sysInfo: sysInfo,
	}
}

// Run reads DupEvents until ctx is cancelled.
// dedup map is owned exclusively by this goroutine — no mutex needed.
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
			dw.handle(event, dedup)
		}
	}
}

func (dw *DupWatcher) handle(event ebpf.DupEvent, dedup map[dupDedupKey]dupDedupEntry) {
	comm := ebpf.CStringToGo(event.Comm[:])

	// Resolve oldfd to a socket inode via /proc/PID/fd/N.
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", event.PID, event.OldFd)
	target, err := os.Readlink(fdPath)
	if err != nil {
		// Process exited before we could check — not unusual, not an error.
		return
	}

	inode, ok := parseDupSocketInode(target)
	if !ok {
		// oldfd is not a socket — normal dup2 usage, discard silently.
		return
	}

	// Dedup check — suppress repeated detections for the same pid+inode
	// within the window. bash -i >& /dev/tcp/... calls dup2 several times
	// for the same socket fd producing identical events in rapid succession.
	key := dupDedupKey{pid: event.PID, inode: inode}
	now := time.Now()
	if entry, seen := dedup[key]; seen {
		if now.Sub(entry.lastSeen) < dupDedupWindow {
			dw.logger.Debug().
				Uint32("pid", event.PID).
				Uint64("inode", inode).
				Msg("dup watcher: detection suppressed within dedup window")
			return
		}
	}
	dedup[key] = dupDedupEntry{lastSeen: now}

	// Build inet socket map and check if this inode is a network connection.
	netSockets, err := dupReadNetSockets()
	if err != nil {
		dw.logger.Debug().
			Err(err).
			Uint32("pid", event.PID).
			Msg("dup watcher: could not read /proc/net socket tables")
		return
	}

	conn, found := netSockets[inode]
	if !found {
		// Socket inode exists but not in any inet table.
		// AF_UNIX inodes never appear in /proc/net/tcp* or /proc/net/udp*
		// so this correctly excludes them without explicit family checking.
		return
	}

	fdLabel := dupFdName(int(event.NewFd))
	finding := fmt.Sprintf("%s→%s(inode=%d,remote=%s:%d)",
		fdLabel, conn.proto, inode, conn.remoteAddr, conn.remotePort)

	dw.logger.Warn().
		Uint32("pid", event.PID).
		Uint32("ppid", event.PPID).
		Str("comm", comm).
		Str("fd", fdLabel).
		Uint32("oldfd", event.OldFd).
		Uint32("newfd", event.NewFd).
		Str("proto", conn.proto).
		Uint64("inode", inode).
		Str("remote_addr", conn.remoteAddr).
		Uint16("remote_port", conn.remotePort).
		Msg("REVERSE SHELL DETECTED: stdio fd redirected to network socket")

	record := &models.SecurityEvent{
		EventTime:   dw.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		EventName:   "reverse_shell",
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: comm,
		Details: fmt.Sprintf(
			`{"oldfd":%d,"newfd":%d,"ppid":%d,"inode":%d,"proto":%q,"remote_addr":%q,"remote_port":%d}`,
			event.OldFd, event.NewFd, event.PPID, inode,
			conn.proto, conn.remoteAddr, conn.remotePort,
		),
		Severity:  models.SeverityCritical,
		Status:    models.StatusNew,
		MachineID: dw.sysInfo.MachineID,
		Notes:     fmt.Sprintf("reverse_shell: comm=%s %s", comm, finding),
	}

	if err := dw.secQ.Insert(record); err != nil {
		dw.logger.Error().
			Err(err).
			Uint32("pid", event.PID).
			Msg("dup watcher: DB insert failed")
	}
}

// ── Socket helpers ────────────────────────────────────────────────────────────

type dupNetConn struct {
	remoteAddr string
	remotePort uint16
	proto      string
}

// parseDupSocketInode extracts the inode from a /proc/PID/fd/N symlink
// target of the form "socket:[inode]".
func parseDupSocketInode(target string) (uint64, bool) {
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

// dupReadNetSockets builds an inode → connection map from all inet socket
// tables. AF_UNIX sockets are excluded by construction — /proc/net/unix
// is not read.
func dupReadNetSockets() (map[uint64]dupNetConn, error) {
	result := make(map[uint64]dupNetConn)

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
		_ = dupParseNetFile(entry.path, entry.proto, entry.ipv6, result)
	}

	return result, nil
}

// dupParseNetFile parses one /proc/net/{tcp,tcp6,udp,udp6} file.
// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
func dupParseNetFile(path, proto string, isIPv6 bool, result map[uint64]dupNetConn) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // skip header line

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		remoteAddr, remotePort, err := dupParseHexAddr(fields[2], isIPv6)
		if err != nil {
			continue
		}

		result[inode] = dupNetConn{
			remoteAddr: remoteAddr,
			remotePort: remotePort,
			proto:      proto,
		}
	}

	return sc.Err()
}

// dupParseHexAddr decodes a hex-encoded "addr:port" from /proc/net socket files.
// IPv4: little-endian 32-bit address. IPv6: little-endian per 4-byte group.
func dupParseHexAddr(hexAddr string, isIPv6 bool) (string, uint16, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("dupwatcher: invalid addr format: %s", hexAddr)
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
			return "", 0, fmt.Errorf("dupwatcher: expected 16 bytes for ipv6, got %d", len(addrBytes))
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
			return "", 0, fmt.Errorf("dupwatcher: expected 4 bytes for ipv4, got %d", len(addrBytes))
		}
		ip = net.IP([]byte{addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0]})
	}

	return ip.String(), uint16(port64), nil
}

// dupFdName returns a human-readable stdio fd name.
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
