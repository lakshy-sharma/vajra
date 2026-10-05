// internal/ebpf/dispatcher.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package ebpf

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

// Dispatcher reads RawEvents from the listener and fans them
// out onto the typed channels in Channels. It translates
// PtraceEvent, CapsetEvent, and NamespaceEvent into
// SecurityEvent before forwarding — those three all land in
// the security_events table and share the same consumer.
type Dispatcher struct {
	logger *zerolog.Logger
}

// NewDispatcher creates a Dispatcher.
func NewDispatcher(logger *zerolog.Logger) *Dispatcher {
	return &Dispatcher{logger: logger}
}

// Run reads from rawCh and fans out to ch until ctx is cancelled
// or rawCh is closed. Intended to run as a goroutine.
// The caller owns all channels and is responsible for draining
// consumers before relying on shutdown to be clean.
func (d *Dispatcher) Run(ctx context.Context, rawCh <-chan RawEvent, ch *Channels) {
	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-rawCh:
			if !ok {
				return
			}
			d.route(event, ch)
		}
	}
}

// route sends a single RawEvent to the correct typed channel.
// Unrecognised event types are logged at debug level and dropped.
func (d *Dispatcher) route(event RawEvent, ch *Channels) {
	switch event.Type {

	// ── Dup stdio → Dup channel ───────────────────────────────
	// Raw DupEvent sent directly to DupWatcher. Not converted to
	// SecurityEvent here — DupWatcher performs the socket check and
	// writes to security_events itself only on confirmed detections.
	case EventTypeProcessDupStdio:
		e, ok := event.Data.(DupEvent)
		if !ok {
			d.logBadType(event.Type, "DupEvent")
			return
		}
		select {
		case ch.Dup <- e:
		default:
			d.logDrop(event.Type)
		}
	// ── Process events → Process channel ─────────────────────
	case EventTypeProcessExec,
		EventTypeProcessSetuid,
		EventTypeProcessSetgid,
		EventTypeProcessMemfd:
		e, ok := event.Data.(ProcessEvent)
		if !ok {
			d.logBadType(event.Type, "ProcessEvent")
			return
		}
		select {
		case ch.Process <- e:
		default:
			d.logDrop(event.Type)
		}

	// ── Mmap / mprotect → Memory channel ─────────────────────
	case EventTypeProcessMmap,
		EventTypeProcessMprotect:
		e, ok := event.Data.(MmapEvent)
		if !ok {
			d.logBadType(event.Type, "MmapEvent")
			return
		}
		select {
		case ch.Memory <- e:
		default:
			d.logDrop(event.Type)
		}

	// ── Ptrace → Security channel ─────────────────────────────
	case EventTypeProcessPtrace:
		e, ok := event.Data.(PtraceEvent)
		if !ok {
			d.logBadType(event.Type, "PtraceEvent")
			return
		}
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: "ptrace",
			PID:       e.PID,
			UID:       e.UID,
			Comm:      CStringToGo(e.Comm[:]),
			TargetPID: e.TargetPID,
			Details:   fmt.Sprintf(`{"request":%d}`, e.Request),
			Timestamp: e.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.logDrop(event.Type)
		}

	// ── Capset → Security channel ─────────────────────────────
	case EventTypeProcessCapset:
		e, ok := event.Data.(CapsetEvent)
		if !ok {
			d.logBadType(event.Type, "CapsetEvent")
			return
		}
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: "capset",
			PID:       e.PID,
			UID:       e.UID,
			Comm:      CStringToGo(e.Comm[:]),
			Details: fmt.Sprintf(
				`{"effective":%d,"permitted":%d,"inheritable":%d}`,
				e.Effective, e.Permitted, e.Inheritable,
			),
			Timestamp: e.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.logDrop(event.Type)
		}

	// ── File events → File channel ────────────────────────────
	case EventTypeFileOpen,
		EventTypeFileDelete,
		EventTypeFileRename,
		EventTypeFileChmod:
		e, ok := event.Data.(FileEvent)
		if !ok {
			d.logBadType(event.Type, "FileEvent")
			return
		}
		select {
		case ch.File <- e:
		default:
			d.logDrop(event.Type)
		}

	// ── Network events → Network channel ─────────────────────
	case EventTypeNetConnect,
		EventTypeNetBind,
		EventTypeNetRawSock,
		EventTypeNetPacket:
		e, ok := event.Data.(NetworkEvent)
		if !ok {
			d.logBadType(event.Type, "NetworkEvent")
			return
		}
		select {
		case ch.Network <- e:
		default:
			d.logDrop(event.Type)
		}

	// ── DNS → Network channel ─────────────────────────────────
	// DNS is a DNSEvent not a NetworkEvent — consumers on the
	// Network channel must handle both types. We wrap it in a
	// NetworkEvent with Type=EventTypeNetDNS so the channel
	// stays single-typed, storing the parsed data in Details.
	// Alternative: add a separate DNS channel. For now one
	// channel keeps the consumer count low.
	case EventTypeNetDNS:
		dns, ok := event.Data.(DNSEvent)
		if !ok {
			d.logBadType(event.Type, "DNSEvent")
			return
		}
		// Store DNS as a SecurityEvent so the security job can
		// log C2-related DNS queries without a separate channel.
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: "dns",
			PID:       dns.PID,
			UID:       dns.UID,
			Comm:      dns.Comm,
			Details:   dnsDetails(dns),
			Timestamp: dns.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.logDrop(event.Type)
		}

	// ── Module events → Module channel ───────────────────────
	case EventTypeModuleLoad:
		e, ok := event.Data.(ModuleEvent)
		if !ok {
			d.logBadType(event.Type, "ModuleEvent")
			return
		}
		select {
		case ch.Module <- e:
		default:
			d.logDrop(event.Type)
		}

	// ── Namespace events → Security channel ──────────────────
	case EventTypeNamespaceCreate,
		EventTypeNamespaceEnter:
		e, ok := event.Data.(NamespaceEvent)
		if !ok {
			d.logBadType(event.Type, "NamespaceEvent")
			return
		}
		name := "namespace_create"
		if event.Type == EventTypeNamespaceEnter {
			name = "namespace_enter"
		}
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: name,
			PID:       e.PID,
			UID:       e.UID,
			Comm:      CStringToGo(e.Comm[:]),
			Details:   fmt.Sprintf(`{"ns_type":%d,"flags":%d}`, e.NSType, e.Flags),
			Timestamp: e.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.logDrop(event.Type)
		}

	default:
		d.logger.Debug().
			Uint32("type", event.Type).
			Msg("dispatcher: unknown event type dropped")
	}
}

// dnsDetails builds a compact JSON string from a parsed DNSEvent
// for storage in SecurityEvent.Details.
func dnsDetails(dns DNSEvent) string {
	if len(dns.Questions) == 0 {
		return `{"questions":[]}`
	}
	// Build a minimal representation without importing encoding/json
	// to keep this hot path allocation-light.
	out := `{"questions":[`
	for i, q := range dns.Questions {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`{"name":%q,"type":%q}`, q.Name, q.Type)
	}
	out += `],"answers":[`
	for i, a := range dns.Answers {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`{"name":%q,"ip":%q,"ttl":%d}`, a.Name, a.IP, a.TTL)
	}
	out += `]}`
	return out
}

func (d *Dispatcher) logBadType(eventType uint32, expected string) {
	d.logger.Error().
		Uint32("event_type", eventType).
		Str("expected", expected).
		Msg("dispatcher: type assertion failed — likely a deserialization bug")
}

// In dispatcher.go — replace logDrop
func (d *Dispatcher) logDrop(eventType uint32) {
	d.logger.Debug().
		Uint32("event_type", eventType).
		Str("event_name", EventTypeName(eventType)).
		Msg("dispatcher: typed channel full — event dropped")
}
