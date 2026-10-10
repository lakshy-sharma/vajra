// internal/ebpf/dispatcher.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/rs/zerolog"
)

// Dispatcher reads RawEvents from the listener and fans them out onto the
// typed channels in Channels. It translates PtraceEvent, CapsetEvent,
// NamespaceEvent, and DNSEvent into SecurityEvent before forwarding.
type Dispatcher struct {
	logger *zerolog.Logger
	drops  atomic.Int64 // E5: counts channel-full drops
}

func NewDispatcher(logger *zerolog.Logger) *Dispatcher {
	return &Dispatcher{logger: logger}
}

// Drops returns the number of events dropped due to full typed channels
// since the dispatcher was created. Safe to call from any goroutine.
func (d *Dispatcher) Drops() int64 {
	return d.drops.Load()
}

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

// route sends a RawEvent to the correct typed channel.
// E2: reads concrete fields directly — no type assertions needed.
func (d *Dispatcher) route(event RawEvent, ch *Channels) {
	switch event.Type {

	case EventTypeProcessDupStdio:
		select {
		case ch.Dup <- event.Dup:
		default:
			d.drop(event.Type)
		}

	case EventTypeProcessExec,
		EventTypeProcessSetuid,
		EventTypeProcessSetgid,
		EventTypeProcessMemfd:
		select {
		case ch.Process <- event.Process:
		default:
			d.drop(event.Type)
		}

	case EventTypeProcessMmap,
		EventTypeProcessMprotect:
		select {
		case ch.Memory <- event.Memory:
		default:
			d.drop(event.Type)
		}

	case EventTypeProcessPtrace:
		details, _ := json.Marshal(ptraceDetails{Request: event.Ptrace.Request})
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: "ptrace",
			PID:       event.Ptrace.PID,
			UID:       event.Ptrace.UID,
			Comm:      CStringToGo(event.Ptrace.Comm[:]),
			TargetPID: event.Ptrace.TargetPID,
			Details:   string(details),
			Timestamp: event.Ptrace.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.drop(event.Type)
		}

	case EventTypeProcessCapset:
		details, _ := json.Marshal(capsetDetails{
			Effective:   event.Capset.Effective,
			Permitted:   event.Capset.Permitted,
			Inheritable: event.Capset.Inheritable,
		})
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: "capset",
			PID:       event.Capset.PID,
			UID:       event.Capset.UID,
			Comm:      CStringToGo(event.Capset.Comm[:]),
			Details:   string(details),
			Timestamp: event.Capset.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.drop(event.Type)
		}

	case EventTypeFileOpen,
		EventTypeFileDelete,
		EventTypeFileRename,
		EventTypeFileChmod:
		select {
		case ch.File <- event.File:
		default:
			d.drop(event.Type)
		}

	case EventTypeNetConnect,
		EventTypeNetBind,
		EventTypeNetRawSock,
		EventTypeNetPacket:
		select {
		case ch.Network <- event.Network:
		default:
			d.drop(event.Type)
		}

	case EventTypeNetDNS:
		if event.DNS == nil {
			d.logger.Error().Msg("dispatcher: nil DNS event")
			return
		}
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: "dns",
			PID:       event.DNS.PID,
			UID:       event.DNS.UID,
			Comm:      event.DNS.Comm,
			Details:   dnsDetails(*event.DNS),
			Timestamp: event.DNS.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.drop(event.Type)
		}

	case EventTypeModuleLoad:
		select {
		case ch.Module <- event.Module:
		default:
			d.drop(event.Type)
		}

	case EventTypeNamespaceCreate,
		EventTypeNamespaceEnter:
		name := "namespace_create"
		if event.Type == EventTypeNamespaceEnter {
			name = "namespace_enter"
		}
		details, _ := json.Marshal(namespaceDetails{
			NSType: event.Namespace.NSType,
			Flags:  event.Namespace.Flags,
		})
		sec := SecurityEvent{
			Type:      event.Type,
			EventName: name,
			PID:       event.Namespace.PID,
			UID:       event.Namespace.UID,
			Comm:      CStringToGo(event.Namespace.Comm[:]),
			Details:   string(details),
			Timestamp: event.Namespace.Timestamp,
		}
		select {
		case ch.Security <- sec:
		default:
			d.drop(event.Type)
		}

	default:
		d.logger.Debug().Uint32("type", event.Type).Msg("dispatcher: unknown event type dropped")
	}
}

// drop counts and logs a channel-full event.
// E5: atomic counter tracks total drops; callers can read Drops() for metrics.
func (d *Dispatcher) drop(eventType uint32) {
	d.drops.Add(1)
	d.logger.Debug().
		Uint32("event_type", eventType).
		Str("event_name", EventTypeName(eventType)).
		Msg("dispatcher: typed channel full — event dropped")
}

// ── Details structs for encoding/json ────────────────────────────────────────
// E4: replaced fmt.Sprintf JSON string building with encoding/json structs.

type ptraceDetails struct {
	Request uint32 `json:"request"`
}

type capsetDetails struct {
	Effective   uint64 `json:"effective"`
	Permitted   uint64 `json:"permitted"`
	Inheritable uint64 `json:"inheritable"`
}

type namespaceDetails struct {
	NSType uint32 `json:"ns_type"`
	Flags  uint32 `json:"flags"`
}

type dnsDetailsPayload struct {
	Questions []dnsQuestionJSON `json:"questions"`
	Answers   []dnsAnswerJSON   `json:"answers"`
}

type dnsQuestionJSON struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type dnsAnswerJSON struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	TTL  uint32 `json:"ttl"`
}

// dnsDetails serialises a DNSEvent into a JSON string for SecurityEvent.Details.
// E4: replaced += string concatenation loop with encoding/json.
func dnsDetails(dns DNSEvent) string {
	payload := dnsDetailsPayload{
		Questions: make([]dnsQuestionJSON, len(dns.Questions)),
		Answers:   make([]dnsAnswerJSON, len(dns.Answers)),
	}
	for i, q := range dns.Questions {
		payload.Questions[i] = dnsQuestionJSON{Name: q.Name, Type: q.Type}
	}
	for i, a := range dns.Answers {
		payload.Answers[i] = dnsAnswerJSON{Name: a.Name, IP: a.IP, TTL: a.TTL}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"questions":[],"answers":[],"error":%q}`, err.Error())
	}
	return string(b)
}
