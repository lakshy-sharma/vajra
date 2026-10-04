// internal/jobs/eventsink.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db/queries"
	"vajra/internal/ebpf"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

var highValuePorts = map[uint16]bool{
	22:    true,
	23:    true,
	3389:  true,
	5900:  true,
	4444:  true,
	4445:  true,
	31337: true,
}

type memDedupKey struct {
	pid  uint32
	prot uint32
}

type memDedupEntry struct {
	lastSeen time.Time
}

const memDedupWindow = 30 * time.Second

type EventSink struct {
	logger  *zerolog.Logger
	netQ    *queries.NetworkQueries
	memQ    *queries.MemoryQueries
	secQ    *queries.SecurityQueries
	sysInfo utilities.SystemInfo
}

func NewEventSink(
	logger *zerolog.Logger,
	netQ *queries.NetworkQueries,
	memQ *queries.MemoryQueries,
	secQ *queries.SecurityQueries,
	sysInfo utilities.SystemInfo,
) *EventSink {
	return &EventSink{
		logger:  logger,
		netQ:    netQ,
		memQ:    memQ,
		secQ:    secQ,
		sysInfo: sysInfo,
	}
}

func (es *EventSink) Run(ctx context.Context, wg *sync.WaitGroup, ch *ebpf.Channels) {
	wg.Add(1)
	go es.consumeNetwork(ctx, wg, ch.Network)
	wg.Add(1)
	go es.consumeMemory(ctx, wg, ch.Memory)
	wg.Add(1)
	go es.consumeSecurity(ctx, wg, ch.Security)
	wg.Add(1)
	go es.consumeModule(ctx, wg, ch.Module)
}

func (es *EventSink) consumeNetwork(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.NetworkEvent) {
	defer wg.Done()
	es.logger.Info().Msg("event sink: network consumer started")
	for {
		select {
		case <-ctx.Done():
			es.logger.Info().Msg("event sink: network consumer stopped")
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			es.handleNetwork(event)
		}
	}
}

func (es *EventSink) handleNetwork(event ebpf.NetworkEvent) {
	record := &models.NetworkEvent{
		EventTime:   es.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: ebpf.CStringToGo(event.Comm[:]),
		SrcAddr:     formatIP(event.SrcAddr, event.Family),
		DstAddr:     formatIP(event.DstAddr, event.Family),
		SrcPort:     event.SrcPort,
		DstPort:     event.DstPort,
		Protocol:    protocolName(event.Protocol),
		Severity:    classifyNetworkSeverity(event.DstPort),
		Status:      models.StatusNew,
		MachineID:   es.sysInfo.MachineID,
	}

	if err := es.netQ.Insert(record); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Str("dst", record.DstAddr).Msg("event sink: network insert failed")
		return
	}

	if record.Severity == models.SeverityHigh || record.Severity == models.SeverityCritical {
		es.logger.Warn().
			Uint32("pid", event.PID).
			Str("process", record.ProcessName).
			Str("dst_addr", record.DstAddr).
			Uint16("dst_port", record.DstPort).
			Str("severity", string(record.Severity)).
			Msg("event sink: high-value network connection")
		return
	}

	es.logger.Debug().Uint32("pid", event.PID).Str("dst", record.DstAddr).Msg("event sink: network event recorded")
}

func (es *EventSink) consumeMemory(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.MmapEvent) {
	defer wg.Done()
	es.logger.Info().Msg("event sink: memory consumer started")

	dedup := make(map[memDedupKey]memDedupEntry)
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			es.logger.Info().Msg("event sink: memory consumer stopped")
			return
		case <-cleanupTicker.C:
			now := time.Now()
			for k, v := range dedup {
				if now.Sub(v.lastSeen) > memDedupWindow {
					delete(dedup, k)
				}
			}
		case event, ok := <-ch:
			if !ok {
				return
			}
			es.handleMemory(event, dedup)
		}
	}
}

func (es *EventSink) handleMemory(event ebpf.MmapEvent, dedup map[memDedupKey]memDedupEntry) {
	severity := classifyMemorySeverity(event.Prot)

	if severity != models.SeverityCritical {
		key := memDedupKey{pid: event.PID, prot: event.Prot}
		now := time.Now()
		if entry, seen := dedup[key]; seen {
			if now.Sub(entry.lastSeen) < memDedupWindow {
				es.logger.Debug().
					Uint32("pid", event.PID).
					Uint32("prot", event.Prot).
					Msg("event sink: memory event deduplicated")
				return
			}
		}
		dedup[key] = memDedupEntry{lastSeen: now}
	}

	record := &models.MemoryEvent{
		EventTime:   es.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: ebpf.CStringToGo(event.Comm[:]),
		Address:     event.Addr,
		Length:      event.Length,
		Protection:  event.Prot,
		Flags:       event.MapFlags,
		FilePath:    ebpf.CStringToGo(event.Filename[:]),
		Severity:    severity,
		Status:      models.StatusNew,
		MachineID:   es.sysInfo.MachineID,
	}

	if err := es.memQ.Insert(record); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Msg("event sink: memory insert failed")
		return
	}

	if severity == models.SeverityCritical {
		es.logger.Warn().
			Uint32("pid", event.PID).
			Str("process", record.ProcessName).
			Uint64("addr", event.Addr).
			Uint32("prot", event.Prot).
			Msg("event sink: CRITICAL memory protection flags detected")
		return
	}

	es.logger.Debug().Uint32("pid", event.PID).Uint64("addr", event.Addr).Msg("event sink: memory event recorded")
}

func (es *EventSink) consumeSecurity(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.SecurityEvent) {
	defer wg.Done()
	es.logger.Info().Msg("event sink: security consumer started")
	for {
		select {
		case <-ctx.Done():
			es.logger.Info().Msg("event sink: security consumer stopped")
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			es.handleSecurity(event)
		}
	}
}

func (es *EventSink) handleSecurity(event ebpf.SecurityEvent) {
	severity := classifySecuritySeverity(event.EventName)

	record := &models.SecurityEvent{
		EventTime:   es.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		EventName:   event.EventName,
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: event.Comm,
		TargetPID:   event.TargetPID,
		Details:     event.Details,
		Severity:    severity,
		Status:      models.StatusNew,
		MachineID:   es.sysInfo.MachineID,
	}

	if err := es.secQ.Insert(record); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Str("event", event.EventName).Msg("event sink: security insert failed")
		return
	}

	if severity == models.SeverityHigh || severity == models.SeverityCritical {
		es.logger.Warn().
			Uint32("pid", event.PID).
			Str("process", event.Comm).
			Str("event_name", event.EventName).
			Str("severity", string(severity)).
			Msg("event sink: security event recorded")
		return
	}

	es.logger.Debug().Uint32("pid", event.PID).Str("event", event.EventName).Msg("event sink: security event recorded")
}

func (es *EventSink) consumeModule(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.ModuleEvent) {
	defer wg.Done()
	es.logger.Info().Msg("event sink: module consumer started")
	for {
		select {
		case <-ctx.Done():
			es.logger.Info().Msg("event sink: module consumer stopped")
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			es.handleModule(event)
		}
	}
}

func (es *EventSink) handleModule(event ebpf.ModuleEvent) {
	moduleName := ebpf.CStringToGo(event.Name[:])

	record := &models.SecurityEvent{
		EventTime:   es.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		EventName:   "module_load",
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: ebpf.CStringToGo(event.Comm[:]),
		Details:     fmt.Sprintf(`{"module_name":%q}`, moduleName),
		Severity:    models.SeverityCritical,
		Status:      models.StatusNew,
		MachineID:   es.sysInfo.MachineID,
	}

	if err := es.secQ.Insert(record); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Str("module", moduleName).Msg("event sink: module insert failed")
		return
	}

	es.logger.Warn().
		Uint32("pid", event.PID).
		Str("process", record.ProcessName).
		Str("module_name", moduleName).
		Msg("event sink: kernel module load recorded")
}

// ── Severity classifiers ──────────────────────────────────────

func classifyNetworkSeverity(dstPort uint16) models.EventSeverity {
	if dstPort == 0 {
		return models.SeverityMedium
	}
	if highValuePorts[dstPort] {
		return models.SeverityHigh
	}
	return models.SeverityLow
}

func classifyMemorySeverity(prot uint32) models.EventSeverity {
	const (
		PROT_WRITE = 0x2
		PROT_EXEC  = 0x4
	)
	if prot&PROT_WRITE != 0 && prot&PROT_EXEC != 0 {
		return models.SeverityCritical
	}
	if prot&PROT_EXEC != 0 {
		return models.SeverityHigh
	}
	return models.SeverityLow
}

func classifySecuritySeverity(eventName string) models.EventSeverity {
	switch eventName {
	case "ptrace", "capset":
		return models.SeverityHigh
	case "namespace_create", "namespace_enter":
		return models.SeverityMedium
	case "dns":
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

// ── Helpers ───────────────────────────────────────────────────

func formatIP(addr [16]byte, family uint8) string {
	const (
		AF_INET  = 2
		AF_INET6 = 10
	)
	switch family {
	case AF_INET:
		return net.IP(addr[:4]).String()
	case AF_INET6:
		return net.IP(addr[:16]).String()
	default:
		return net.IP(addr[:4]).String()
	}
}

func protocolName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}
