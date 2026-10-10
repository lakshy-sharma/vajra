// internal/ebpf/listener.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_${GOARCH}" -target amd64,arm64 -output-dir . bpf ./c/ebpf_events.c -- -I./c

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	cerr "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
)

// Listener loads the BPF program, attaches all tracepoints,
// and streams deserialized RawEvents into the channel passed to Start.
type Listener struct {
	logger *zerolog.Logger
	objs   bpfObjects
	links  []link.Link
	reader *perf.Reader
	once   sync.Once
}

func NewListener(logger *zerolog.Logger) (*Listener, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf.NewListener: remove memlock: %w", err)
	}

	l := &Listener{logger: logger}

	if err := loadBpfObjects(&l.objs, nil); err != nil {
		var ve *cerr.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf.NewListener: verifier error: %w\n%+v", err, ve)
		}
		return nil, fmt.Errorf("ebpf.NewListener: load objects: %w", err)
	}

	return l, nil
}

// Start attaches tracepoints, opens the perf reader, and launches the read
// loop. perfRingPages must be a power of two — config validation enforces this.
// E3: was hardcoded to os.Getpagesize()*64.
func (l *Listener) Start(ctx context.Context, rawCh chan<- RawEvent, perfRingPages int) error {
	l.attachTracepoints()

	if len(l.links) == 0 {
		return fmt.Errorf("ebpf.Listener.Start: no tracepoints attached successfully")
	}

	var err error
	l.reader, err = perf.NewReader(l.objs.Events, os.Getpagesize()*perfRingPages)
	if err != nil {
		return fmt.Errorf("ebpf.Listener.Start: perf reader: %w", err)
	}

	go l.readLoop(ctx, rawCh)

	l.logger.Info().
		Int("tracepoints", len(l.links)).
		Int("perf_ring_pages", perfRingPages).
		Msg("ebpf listener started")

	return nil
}

func (l *Listener) Stop() {
	l.once.Do(func() {
		if l.reader != nil {
			l.reader.Close()
		}
		for _, lnk := range l.links {
			lnk.Close()
		}
		l.objs.Close()
		l.logger.Info().Msg("ebpf listener stopped")
	})
}

func (l *Listener) attachTracepoints() {
	type entry struct {
		group string
		name  string
		prog  *cerr.Program
	}

	points := []entry{
		{"syscalls", "sys_enter_execve", l.objs.TraceExecve},
		{"syscalls", "sys_enter_setuid", l.objs.TraceSetuid},
		{"syscalls", "sys_enter_setgid", l.objs.TraceSetgid},
		{"syscalls", "sys_enter_memfd_create", l.objs.TraceMemfdCreate},
		{"syscalls", "sys_enter_ptrace", l.objs.TracePtrace},
		{"syscalls", "sys_enter_mmap", l.objs.TraceMmap},
		{"syscalls", "sys_enter_mprotect", l.objs.TraceMprotect},
		{"syscalls", "sys_enter_capset", l.objs.TraceCapset},
		{"syscalls", "sys_enter_dup2", l.objs.TraceDup2},
		{"syscalls", "sys_enter_dup3", l.objs.TraceDup3},
		{"syscalls", "sys_enter_openat", l.objs.TraceOpenat},
		{"syscalls", "sys_enter_unlinkat", l.objs.TraceUnlinkat},
		{"syscalls", "sys_enter_renameat2", l.objs.TraceRenameat2},
		{"syscalls", "sys_enter_fchmodat", l.objs.TraceFchmodat},
		{"syscalls", "sys_enter_connect", l.objs.TraceConnect},
		{"syscalls", "sys_enter_bind", l.objs.TraceBind},
		{"syscalls", "sys_enter_socket", l.objs.TraceSocket},
		{"syscalls", "sys_enter_sendto", l.objs.TraceSendto},
		{"syscalls", "sys_enter_sendmsg", l.objs.TraceSendmsg},
		{"syscalls", "sys_enter_init_module", l.objs.TraceInitModule},
		{"syscalls", "sys_enter_finit_module", l.objs.TraceFinitModule},
		{"syscalls", "sys_enter_unshare", l.objs.TraceUnshare},
		{"syscalls", "sys_enter_setns", l.objs.TraceSetns},
	}

	for _, p := range points {
		lnk, err := link.Tracepoint(p.group, p.name, p.prog, nil)
		if err != nil {
			l.logger.Warn().
				Err(err).
				Str("tracepoint", p.group+"/"+p.name).
				Msg("tracepoint attach failed — skipping")
			continue
		}
		l.links = append(l.links, lnk)
		l.logger.Debug().Str("tracepoint", p.group+"/"+p.name).Msg("tracepoint attached")
	}
}

func (l *Listener) readLoop(ctx context.Context, rawCh chan<- RawEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			l.logger.Error().Err(err).Msg("perf read error")
			continue
		}

		if record.LostSamples > 0 {
			l.logger.Warn().Uint64("lost", record.LostSamples).Msg("perf ring full — samples dropped by kernel")
		}

		event, err := l.deserialize(record.RawSample)
		if err != nil {
			l.logger.Debug().Err(err).Msg("deserialize skipped")
			continue
		}

		select {
		case rawCh <- event:
		default:
			l.logger.Warn().Uint32("type", event.Type).Msg("raw channel full — event dropped")
		}
	}
}

// deserialize reads the event type and fills the matching field of a RawEvent.
// E2: sets one concrete field instead of boxing into Data interface{}.
func (l *Listener) deserialize(raw []byte) (RawEvent, error) {
	if len(raw) < 4 {
		return RawEvent{}, fmt.Errorf("record too short (%d bytes)", len(raw))
	}

	eventType := binary.LittleEndian.Uint32(raw[0:4])
	r := bytes.NewReader(raw)
	var evt RawEvent
	evt.Type = eventType

	switch eventType {

	case EventTypeProcessExec,
		EventTypeProcessSetuid,
		EventTypeProcessSetgid,
		EventTypeProcessMemfd:
		if err := binary.Read(r, binary.LittleEndian, &evt.Process); err != nil {
			return RawEvent{}, fmt.Errorf("ProcessEvent decode: %w", err)
		}

	case EventTypeProcessPtrace:
		if err := binary.Read(r, binary.LittleEndian, &evt.Ptrace); err != nil {
			return RawEvent{}, fmt.Errorf("PtraceEvent decode: %w", err)
		}

	case EventTypeProcessMmap,
		EventTypeProcessMprotect:
		if err := binary.Read(r, binary.LittleEndian, &evt.Memory); err != nil {
			return RawEvent{}, fmt.Errorf("MmapEvent decode: %w", err)
		}

	case EventTypeProcessCapset:
		if err := binary.Read(r, binary.LittleEndian, &evt.Capset); err != nil {
			return RawEvent{}, fmt.Errorf("CapsetEvent decode: %w", err)
		}

	case EventTypeProcessDupStdio:
		if err := binary.Read(r, binary.LittleEndian, &evt.Dup); err != nil {
			return RawEvent{}, fmt.Errorf("DupEvent decode: %w", err)
		}

	case EventTypeFileOpen,
		EventTypeFileDelete,
		EventTypeFileRename,
		EventTypeFileChmod:
		if err := binary.Read(r, binary.LittleEndian, &evt.File); err != nil {
			return RawEvent{}, fmt.Errorf("FileEvent decode: %w", err)
		}

	case EventTypeNetConnect,
		EventTypeNetBind,
		EventTypeNetRawSock,
		EventTypeNetPacket:
		if err := binary.Read(r, binary.LittleEndian, &evt.Network); err != nil {
			return RawEvent{}, fmt.Errorf("NetworkEvent decode: %w", err)
		}

	case EventTypeNetDNS:
		var rawDNS dnsEventRaw
		if err := binary.Read(r, binary.LittleEndian, &rawDNS); err != nil {
			return RawEvent{}, fmt.Errorf("dnsEventRaw decode: %w", err)
		}
		dns, err := parseDNS(rawDNS)
		if err != nil {
			return RawEvent{}, fmt.Errorf("DNS parse: %w", err)
		}
		evt.DNS = &dns

	case EventTypeModuleLoad:
		if err := binary.Read(r, binary.LittleEndian, &evt.Module); err != nil {
			return RawEvent{}, fmt.Errorf("ModuleEvent decode: %w", err)
		}

	case EventTypeNamespaceCreate,
		EventTypeNamespaceEnter:
		if err := binary.Read(r, binary.LittleEndian, &evt.Namespace); err != nil {
			return RawEvent{}, fmt.Errorf("NamespaceEvent decode: %w", err)
		}

	default:
		return RawEvent{}, fmt.Errorf("unknown event type %d", eventType)
	}

	return evt, nil
}

// parseDNS is a package-level function so the dispatcher can call it
// without holding a Listener reference.
func parseDNS(raw dnsEventRaw) (DNSEvent, error) {
	event := DNSEvent{
		PID:       raw.PID,
		UID:       raw.UID,
		Comm:      CStringToGo(raw.Comm[:]),
		Timestamp: raw.Timestamp,
	}

	payloadLen := raw.PayloadLen
	if payloadLen > uint32(len(raw.Payload)) {
		payloadLen = uint32(len(raw.Payload))
	}
	if payloadLen == 0 {
		return event, fmt.Errorf("empty DNS payload")
	}

	packet := gopacket.NewPacket(
		raw.Payload[:payloadLen],
		layers.LayerTypeDNS,
		gopacket.Default,
	)

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return event, fmt.Errorf("no DNS layer in packet")
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return event, fmt.Errorf("DNS layer type assertion failed")
	}

	for _, q := range dns.Questions {
		event.Questions = append(event.Questions, DNSQuestion{
			Name: string(q.Name),
			Type: q.Type.String(),
		})
	}

	for _, a := range dns.Answers {
		ans := DNSAnswer{Name: string(a.Name), TTL: a.TTL}
		if a.IP != nil {
			ans.IP = a.IP.String()
		}
		event.Answers = append(event.Answers, ans)
	}

	return event, nil
}
