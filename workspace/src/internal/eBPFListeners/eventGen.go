package eBPFListeners

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Event types - Process Events
const (
	EventTypeProcessExec     = 1
	EventTypeProcessExit     = 2
	EventTypeProcessFork     = 3
	EventTypeProcessSetuid   = 4
	EventTypeProcessSetgid   = 5
	EventTypeProcessPtrace   = 6
	EventTypeProcessPrctl    = 7
	EventTypeProcessMemfd    = 8
	EventTypeProcessMmap     = 9
	EventTypeProcessMprotect = 10
)

// Event types - File Events
const (
	EventTypeFileOpen        = 20
	EventTypeFileCreate      = 21
	EventTypeFileDelete      = 22
	EventTypeFileRename      = 23
	EventTypeFileChmod       = 24
	EventTypeFileChown       = 25
	EventTypeFileLink        = 26
	EventTypeFileSymlink     = 27
	EventTypeFileTruncate    = 28
	EventTypeFileSetxattr    = 29
	EventTypeFileRemovexattr = 30
)

// Event types - Network Events
const (
	EventTypeNetConnect = 40
	EventTypeNetBind    = 41
	EventTypeNetListen  = 42
	EventTypeNetAccept  = 43
	EventTypeNetSendmsg = 44
	EventTypeNetRecvmsg = 45
)

// Event types - Module/Driver Events
const (
	EventTypeModuleLoad   = 60
	EventTypeModuleUnload = 61
	EventTypeBPFLoad      = 62
	EventTypeBPFAttach    = 63
)

// ProcessEvent represents a process-related event
type ProcessEvent struct {
	Type      uint32
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	EUID      uint32
	EGID      uint32
	Comm      [16]byte
	Filename  [256]byte
	Args      [512]byte // For command line arguments
	Cwd       [256]byte // Current working directory
	Timestamp uint64
	Ret       int64 // Return value for syscalls
}

// FileEvent represents a filesystem-related event
type FileEvent struct {
	Type       uint32
	PID        uint32
	UID        uint32
	GID        uint32
	Comm       [16]byte
	Filename   [256]byte
	TargetPath [256]byte // For rename, link, symlink operations
	Mode       uint32    // File permissions for chmod
	Flags      uint32    // Open flags
	Timestamp  uint64
	Size       uint64 // For truncate operations
	Ret        int64  // Return value
}

// NetworkEvent represents a network-related event
type NetworkEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	SrcAddr   [16]byte // IPv4 or IPv6
	DstAddr   [16]byte
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Family    uint8 // AF_INET or AF_INET6
	Timestamp uint64
	Ret       int64
}

// ModuleEvent represents kernel module/eBPF loading events
type ModuleEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	Name      [256]byte
	Timestamp uint64
	Ret       int64
}

// MmapEvent represents memory mapping events (useful for detecting code injection)
type MmapEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	Comm      [16]byte
	Addr      uint64
	Length    uint64
	Prot      uint32 // Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC)
	Flags     uint32 // MAP_PRIVATE, MAP_ANONYMOUS, etc.
	Fd        int32
	Filename  [256]byte
	Timestamp uint64
}

// PtraceEvent represents ptrace events (debugging/injection attempts)
type PtraceEvent struct {
	Type      uint32
	PID       uint32
	TargetPID uint32
	UID       uint32
	Comm      [16]byte
	Request   uint32
	Timestamp uint64
	Ret       int64
}

// EventCallback is the function signature for event callbacks
type EventCallback func(eventType uint32, data interface{})

// EventGenerator manages eBPF programs and event collection
type EventGenerator struct {
	objs     *bpfObjects
	links    []link.Link
	reader   *perf.Reader
	callback EventCallback
}

// bpfObjects contains all eBPF programs and maps
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target amd64,arm64 bpf ebpf_events.c -- -I.

// NewEventGenerator creates a new eBPF event generator for EDR
func NewEventGenerator(callback EventCallback) (*EventGenerator, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	eg := &EventGenerator{
		objs:     objs,
		callback: callback,
	}

	return eg, nil
}

// Start begins monitoring for events
func (eg *EventGenerator) Start() error {
	var err error

	// Process events
	eg.attachTracepoint("syscalls", "sys_enter_execve", eg.objs.TraceExecve)
	eg.attachTracepoint("syscalls", "sys_enter_exit_group", eg.objs.TraceExitGroup)
	eg.attachTracepoint("syscalls", "sys_enter_clone", eg.objs.TraceClone)
	eg.attachTracepoint("syscalls", "sys_enter_setuid", eg.objs.TraceSetuid)
	eg.attachTracepoint("syscalls", "sys_enter_setgid", eg.objs.TraceSetgid)
	eg.attachTracepoint("syscalls", "sys_enter_ptrace", eg.objs.TracePtrace)
	eg.attachTracepoint("syscalls", "sys_enter_prctl", eg.objs.TracePrctl)
	eg.attachTracepoint("syscalls", "sys_enter_memfd_create", eg.objs.TraceMemfdCreate)
	eg.attachTracepoint("syscalls", "sys_enter_mmap", eg.objs.TraceMmap)
	eg.attachTracepoint("syscalls", "sys_enter_mprotect", eg.objs.TraceMprotect)

	// File events
	eg.attachTracepoint("syscalls", "sys_enter_openat", eg.objs.TraceOpenat)
	eg.attachTracepoint("syscalls", "sys_enter_unlinkat", eg.objs.TraceUnlinkat)
	eg.attachTracepoint("syscalls", "sys_enter_renameat2", eg.objs.TraceRenameat2)
	eg.attachTracepoint("syscalls", "sys_enter_fchmodat", eg.objs.TraceFchmodat)
	eg.attachTracepoint("syscalls", "sys_enter_fchownat", eg.objs.TraceFchownat)
	eg.attachTracepoint("syscalls", "sys_enter_linkat", eg.objs.TraceLinkat)
	eg.attachTracepoint("syscalls", "sys_enter_symlinkat", eg.objs.TraceSymlinkat)
	eg.attachTracepoint("syscalls", "sys_enter_truncate", eg.objs.TraceTruncate)
	eg.attachTracepoint("syscalls", "sys_enter_setxattr", eg.objs.TraceSetxattr)
	eg.attachTracepoint("syscalls", "sys_enter_removexattr", eg.objs.TraceRemovexattr)

	// Network events
	eg.attachTracepoint("syscalls", "sys_enter_connect", eg.objs.TraceConnect)
	eg.attachTracepoint("syscalls", "sys_enter_bind", eg.objs.TraceBind)
	eg.attachTracepoint("syscalls", "sys_enter_listen", eg.objs.TraceListen)
	eg.attachTracepoint("syscalls", "sys_enter_accept", eg.objs.TraceAccept)
	eg.attachTracepoint("syscalls", "sys_enter_sendmsg", eg.objs.TraceSendmsg)
	eg.attachTracepoint("syscalls", "sys_enter_recvmsg", eg.objs.TraceRecvmsg)

	// Module/BPF events
	eg.attachTracepoint("syscalls", "sys_enter_init_module", eg.objs.TraceInitModule)
	eg.attachTracepoint("syscalls", "sys_enter_delete_module", eg.objs.TraceDeleteModule)
	eg.attachTracepoint("syscalls", "sys_enter_bpf", eg.objs.TraceBpf)

	// Open perf event reader
	eg.reader, err = perf.NewReader(eg.objs.Events, os.Getpagesize()*64) // Larger buffer for EDR
	if err != nil {
		return fmt.Errorf("creating perf reader: %w", err)
	}

	go eg.readEvents()

	return nil
}

// attachTracepoint is a helper to attach tracepoints
func (eg *EventGenerator) attachTracepoint(group, name string, prog *ebpf.Program) {
	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		log.Printf("Warning: failed to attach %s/%s: %v", group, name, err)
		return
	}
	eg.links = append(eg.links, l)
}

// readEvents continuously reads and processes events from the perf buffer
func (eg *EventGenerator) readEvents() {
	for {
		record, err := eg.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf array: %v", err)
			continue
		}

		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample[0:4])

		switch {
		case eventType >= 1 && eventType <= 10: // Process events
			var event ProcessEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				eg.callback(eventType, event)
			}

		case eventType >= 20 && eventType <= 30: // File events
			var event FileEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				eg.callback(eventType, event)
			}

		case eventType >= 40 && eventType <= 45: // Network events
			var event NetworkEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				eg.callback(eventType, event)
			}

		case eventType >= 60 && eventType <= 63: // Module events
			var event ModuleEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				eg.callback(eventType, event)
			}

		case eventType == EventTypeProcessMmap:
			var event MmapEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				eg.callback(eventType, event)
			}

		case eventType == EventTypeProcessPtrace:
			var event PtraceEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				eg.callback(eventType, event)
			}
		}
	}
}

// Stop stops the event generator and cleans up resources
func (eg *EventGenerator) Stop() {
	if eg.reader != nil {
		eg.reader.Close()
	}
	for _, l := range eg.links {
		l.Close()
	}
	if eg.objs != nil {
		eg.objs.Events.Close()
	}
}

// EDR-focused event callback with security context
// func edrEventCallback(eventType uint32, data interface{}) {
// 	switch eventType {
// 	// Critical Process Events
// 	case EventTypeProcessExec:
// 		event := data.(ProcessEvent)
// 		fmt.Printf("[CRITICAL] Process Exec: PID=%d PPID=%d UID=%d EUID=%d Comm=%s File=%s Args=%s CWD=%s\n",
// 			event.PID, event.PPID, event.UID, event.EUID,
// 			utilities.ConvertCStringToGo(event.Comm[:]), utilities.ConvertCStringToGo(event.Filename[:]),
// 			utilities.ConvertCStringToGo(event.Args[:]), utilities.ConvertCStringToGo(event.Cwd[:]))

// 	case EventTypeProcessFork:
// 		event := data.(ProcessEvent)
// 		fmt.Printf("[INFO] Process Fork: PID=%d -> Child=%d Comm=%s\n",
// 			event.PPID, event.PID, utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeProcessSetuid:
// 		event := data.(ProcessEvent)
// 		fmt.Printf("[HIGH] Privilege Change (setuid): PID=%d UID=%d->%d EUID=%d Comm=%s\n",
// 			event.PID, event.UID, event.EUID, event.EUID, utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeProcessPtrace:
// 		event := data.(PtraceEvent)
// 		fmt.Printf("[CRITICAL] Ptrace Detected: PID=%d -> TargetPID=%d Request=0x%x Comm=%s\n",
// 			event.PID, event.TargetPID, event.Request, utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeProcessMemfd:
// 		event := data.(ProcessEvent)
// 		fmt.Printf("[HIGH] Memfd Create: PID=%d Name=%s Comm=%s (Possible fileless execution)\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Filename[:]), utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeProcessMmap:
// 		event := data.(MmapEvent)
// 		if event.Prot&0x4 != 0 { // PROT_EXEC
// 			fmt.Printf("[HIGH] Executable Mmap: PID=%d Addr=0x%x Size=%d Prot=0x%x Flags=0x%x File=%s Comm=%s\n",
// 				event.PID, event.Addr, event.Length, event.Prot, event.Flags,
// 				utilities.ConvertCStringToGo(event.Filename[:]), utilities.ConvertCStringToGo(event.Comm[:]))
// 		}

// 	case EventTypeProcessMprotect:
// 		event := data.(ProcessEvent)
// 		fmt.Printf("[HIGH] Memory Protection Change: PID=%d Comm=%s (Possible code injection)\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Comm[:]))

// 	// File Events
// 	case EventTypeFileCreate:
// 		event := data.(FileEvent)
// 		fmt.Printf("[INFO] File Created: PID=%d File=%s Comm=%s\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Filename[:]), utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeFileDelete:
// 		event := data.(FileEvent)
// 		fmt.Printf("[MEDIUM] File Deleted: PID=%d File=%s Comm=%s\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Filename[:]), utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeFileRename:
// 		event := data.(FileEvent)
// 		fmt.Printf("[MEDIUM] File Renamed: PID=%d From=%s To=%s Comm=%s\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Filename[:]), utilities.ConvertCStringToGo(event.TargetPath[:]), utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeFileChmod:
// 		event := data.(FileEvent)
// 		fmt.Printf("[MEDIUM] Permission Changed: PID=%d File=%s Mode=0%o Comm=%s\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Filename[:]), event.Mode, utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeFileSetxattr:
// 		event := data.(FileEvent)
// 		fmt.Printf("[INFO] Extended Attribute Set: PID=%d File=%s Comm=%s\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Filename[:]), utilities.ConvertCStringToGo(event.Comm[:]))

// 	// Network Events
// 	case EventTypeNetConnect:
// 		event := data.(NetworkEvent)
// 		fmt.Printf("[INFO] Network Connect: PID=%d Comm=%s Port=%d Protocol=%d\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Comm[:]), event.DstPort, event.Protocol)

// 	case EventTypeNetBind:
// 		event := data.(NetworkEvent)
// 		fmt.Printf("[INFO] Network Bind: PID=%d Comm=%s Port=%d\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Comm[:]), event.SrcPort)

// 	case EventTypeNetListen:
// 		event := data.(NetworkEvent)
// 		fmt.Printf("[MEDIUM] Network Listen: PID=%d Comm=%s Port=%d\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Comm[:]), event.SrcPort)

// 	// Module Events
// 	case EventTypeModuleLoad:
// 		event := data.(ModuleEvent)
// 		fmt.Printf("[CRITICAL] Kernel Module Load: PID=%d Module=%s Comm=%s\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Name[:]), utilities.ConvertCStringToGo(event.Comm[:]))

// 	case EventTypeBPFLoad:
// 		event := data.(ModuleEvent)
// 		fmt.Printf("[HIGH] eBPF Program Load: PID=%d Name=%s Comm=%s\n",
// 			event.PID, utilities.ConvertCStringToGo(event.Name[:]), utilities.ConvertCStringToGo(event.Comm[:]))
// 	}
// }
