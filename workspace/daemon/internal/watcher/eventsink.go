// internal/watcher/eventsink.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db/queries"
	"vajra/internal/ebpf"
	"vajra/internal/utilities"
	sharedconfig "vajra/shared/config"
	"vajra/shared/models"
)

type memDedupKey struct {
	pid  uint32
	prot uint32
}

type memDedupEntry struct {
	lastSeen time.Time
}

const memDedupWindow = 30 * time.Second

// EventSink records raw kernel telemetry — network, memory, security,
// module events. No detection logic; heuristic severity only.
// Detection logic lives in watchers and scanners that write Finding values.
type EventSink struct {
	logger        *zerolog.Logger
	netQ          *queries.NetworkQueries
	memQ          *queries.MemoryQueries
	secQ          *queries.SecurityQueries
	sysInfo       utilities.SystemInfo
	inboundPorts  map[uint16]bool // W4: driven by AlertPolicySettings
	outboundPorts map[uint16]bool
}

func NewEventSink(
	logger *zerolog.Logger,
	netQ *queries.NetworkQueries,
	memQ *queries.MemoryQueries,
	secQ *queries.SecurityQueries,
	sysInfo utilities.SystemInfo,
	policy sharedconfig.AlertPolicySettings,
) *EventSink {
	inbound := make(map[uint16]bool, len(policy.HighValueInboundPorts))
	for _, p := range policy.HighValueInboundPorts {
		inbound[p] = true
	}
	outbound := make(map[uint16]bool, len(policy.HighValueOutboundPorts))
	for _, p := range policy.HighValueOutboundPorts {
		outbound[p] = true
	}
	return &EventSink{
		logger:        logger,
		netQ:          netQ,
		memQ:          memQ,
		secQ:          secQ,
		sysInfo:       sysInfo,
		inboundPorts:  inbound,
		outboundPorts: outbound,
	}
}

func (es *EventSink) Name() string { return "event_sink" }

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
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			es.handleNetwork(ctx, event, time.Now().Unix())
		}
	}
}

func (es *EventSink) handleNetwork(ctx context.Context, event ebpf.NetworkEvent, now int64) {
	// W5: unknown address family is logged and dropped, not silently defaulted.
	srcAddr, err := formatIP(event.SrcAddr, event.Family)
	if err != nil {
		es.logger.Warn().Err(err).Uint32("pid", event.PID).Msg("event sink: unknown address family, skipping network event")
		return
	}
	dstAddr, err := formatIP(event.DstAddr, event.Family)
	if err != nil {
		es.logger.Warn().Err(err).Uint32("pid", event.PID).Msg("event sink: unknown address family, skipping network event")
		return
	}

	record := &models.NetworkEvent{
		EventTime:   es.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: ebpf.CStringToGo(event.Comm[:]),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		SrcPort:     event.SrcPort,
		DstPort:     event.DstPort,
		Protocol:    protocolName(event.Protocol),
		Severity:    es.classifyNetworkSeverity(event.DstPort),
		Status:      models.StatusNew,
		MachineID:   es.sysInfo.MachineID,
	}

	if err := es.netQ.Insert(ctx, record, now); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Msg("event sink: network insert failed")
		return
	}

	if record.Severity >= models.SeverityHigh {
		es.logger.Warn().
			Uint32("pid", event.PID).
			Str("process", record.ProcessName).
			Str("dst", record.DstAddr).
			Uint16("dst_port", record.DstPort).
			Msg("event sink: high-value network connection")
	}
}

func (es *EventSink) consumeMemory(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.MmapEvent) {
	defer wg.Done()
	es.logger.Info().Msg("event sink: memory consumer started")

	dedup := make(map[memDedupKey]memDedupEntry)
	cleanupTicker := time.NewTicker(memDedupWindow)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
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
			es.handleMemory(ctx, event, dedup, time.Now().Unix())
		}
	}
}

func (es *EventSink) handleMemory(ctx context.Context, event ebpf.MmapEvent, dedup map[memDedupKey]memDedupEntry, now int64) {
	severity := classifyMemorySeverity(event.Prot)

	if severity != models.SeverityCritical {
		key := memDedupKey{pid: event.PID, prot: event.Prot}
		t := time.Now()
		if entry, seen := dedup[key]; seen && t.Sub(entry.lastSeen) < memDedupWindow {
			return
		}
		dedup[key] = memDedupEntry{lastSeen: t}
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

	if err := es.memQ.Insert(ctx, record, now); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Msg("event sink: memory insert failed")
		return
	}

	if severity == models.SeverityCritical {
		es.logger.Warn().
			Uint32("pid", event.PID).
			Str("process", record.ProcessName).
			Uint64("addr", event.Addr).
			Uint32("prot", event.Prot).
			Msg("event sink: W^X memory mapping")
	}
}

func (es *EventSink) consumeSecurity(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.SecurityEvent) {
	defer wg.Done()
	es.logger.Info().Msg("event sink: security consumer started")
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			es.handleSecurity(ctx, event, time.Now().Unix())
		}
	}
}

func (es *EventSink) handleSecurity(ctx context.Context, event ebpf.SecurityEvent, now int64) {
	record := &models.SecurityEvent{
		EventTime:   es.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		EventName:   event.EventName,
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: event.Comm,
		TargetPID:   event.TargetPID,
		Details:     event.Details,
		Severity:    classifySecuritySeverity(event.EventName),
		Status:      models.StatusNew,
		MachineID:   es.sysInfo.MachineID,
	}

	if err := es.secQ.Insert(ctx, record, now); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Msg("event sink: security insert failed")
		return
	}

	if record.Severity >= models.SeverityHigh {
		es.logger.Warn().
			Uint32("pid", event.PID).
			Str("process", event.Comm).
			Str("event", event.EventName).
			Msg("event sink: high-severity security event")
	}
}

func (es *EventSink) consumeModule(ctx context.Context, wg *sync.WaitGroup, ch <-chan ebpf.ModuleEvent) {
	defer wg.Done()
	es.logger.Info().Msg("event sink: module consumer started")
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			es.handleModule(ctx, event, time.Now().Unix())
		}
	}
}

// moduleDetails is used for JSON encoding of the module name.
// W6: replaced fmt.Sprintf JSON construction with encoding/json.
type moduleDetails struct {
	ModuleName string `json:"module_name"`
}

func (es *EventSink) handleModule(ctx context.Context, event ebpf.ModuleEvent, now int64) {
	moduleName := ebpf.CStringToGo(event.Name[:])

	details, err := json.Marshal(moduleDetails{ModuleName: moduleName})
	if err != nil {
		details = []byte("{}") // json.Marshal on a string field cannot fail in practice
	}

	record := &models.SecurityEvent{
		EventTime:   es.sysInfo.EBPFTimestampToUnix(event.Timestamp),
		EventType:   event.Type,
		EventName:   "module_load",
		PID:         event.PID,
		UID:         event.UID,
		ProcessName: ebpf.CStringToGo(event.Comm[:]),
		Details:     string(details),
		Severity:    models.SeverityCritical,
		Status:      models.StatusNew,
		MachineID:   es.sysInfo.MachineID,
	}

	if err := es.secQ.Insert(ctx, record, now); err != nil {
		es.logger.Error().Err(err).Uint32("pid", event.PID).Msg("event sink: module insert failed")
		return
	}

	es.logger.Warn().
		Uint32("pid", event.PID).
		Str("process", record.ProcessName).
		Str("module", moduleName).
		Msg("event sink: kernel module load")
}

// ── Severity classifiers ──────────────────────────────────────

// classifyNetworkSeverity checks the destination port against both inbound
// and outbound high-value port sets from config. W4: was a hardcoded map.
func (es *EventSink) classifyNetworkSeverity(dstPort uint16) models.EventSeverity {
	if dstPort == 0 {
		return models.SeverityMedium
	}
	if es.inboundPorts[dstPort] || es.outboundPorts[dstPort] {
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

// ── Network helpers ───────────────────────────────────────────

// formatIP converts a kernel address buffer to a string.
// W5: returns an error for unknown address families instead of silently
// defaulting to IPv4, which would produce a meaningless address.
func formatIP(addr [16]byte, family uint8) (string, error) {
	const (
		AF_INET  = 2
		AF_INET6 = 10
	)
	switch family {
	case AF_INET:
		return net.IP(addr[:4]).String(), nil
	case AF_INET6:
		return net.IP(addr[:16]).String(), nil
	default:
		return "", fmt.Errorf("unknown address family %d", family)
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
