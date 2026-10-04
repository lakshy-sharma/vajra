// internal/ebpf/types.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package ebpf

import "bytes"

// ============================================================
// Event type constants.
// MUST match the #define values in c/ebpf_events.c exactly.
// ============================================================

const (
	// Process events
	EventTypeProcessExec     uint32 = 1
	EventTypeProcessSetuid   uint32 = 4
	EventTypeProcessSetgid   uint32 = 5
	EventTypeProcessPtrace   uint32 = 6
	EventTypeProcessMemfd    uint32 = 8
	EventTypeProcessMmap     uint32 = 9
	EventTypeProcessMprotect uint32 = 10
	EventTypeProcessCapset   uint32 = 11

	// File events
	EventTypeFileOpen   uint32 = 20
	EventTypeFileDelete uint32 = 22
	EventTypeFileRename uint32 = 23
	EventTypeFileChmod  uint32 = 24

	// Network events
	EventTypeNetConnect uint32 = 40
	EventTypeNetBind    uint32 = 41
	EventTypeNetDNS     uint32 = 46
	EventTypeNetRawSock uint32 = 47
	EventTypeNetPacket  uint32 = 48

	// Module events
	EventTypeModuleLoad uint32 = 60

	// Namespace events
	EventTypeNamespaceCreate uint32 = 70
	EventTypeNamespaceEnter  uint32 = 71
)

// ============================================================
// RawEvent — the only type that flows out of the listener
// into the dispatcher. Data holds a typed struct boxed as
// interface{} after deserialization.
// ============================================================

type RawEvent struct {
	Type uint32
	Data interface{}
}

// ============================================================
// Go-side event structs.
//
// Field layout mirrors the C structs in c/ebpf_events.c
// exactly, including explicit pad fields.
// binary.Read in the listener reads these field by field in
// order, so every pad byte in C must have a corresponding
// field here.
// ============================================================

// ProcessEvent mirrors struct process_event.
// Used for: execve, setuid, setgid, memfd_create.
// Size: 7×4 + 16 + 256 + 512 + 256 + 4 + 4 + 8 + 8 = 1096 bytes
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
	Args      [512]byte
	CWD       [256]byte
	Pad0      uint32  // mirrors __u32 _pad0 in C
	Flags     uint32  // memfd flags or 0
	Pad1      [4]byte // ← added: mirrors _ [4]byte in bpfProcessEvent
	Timestamp uint64
	Ret       int64
}

// FileEvent mirrors struct file_event.
// Used for: openat (O_CREAT), unlinkat, renameat2, fchmodat.
// Size: 4×4 + 16 + 256 + 256 + 4 + 4 + 8 + 8 + 8 = 580 bytes
type FileEvent struct {
	Type       uint32
	PID        uint32
	UID        uint32
	GID        uint32
	Comm       [16]byte
	Filename   [256]byte
	TargetPath [256]byte
	Mode       uint32
	Flags      uint32
	Timestamp  uint64
	Size       uint64
	Ret        int64
}

// NetworkEvent mirrors struct network_event.
// Used for: connect, bind, socket (raw/packet), DNS.
// Size: 4×4 + 16 + 16 + 16 + 2 + 2 + 1 + 1 + 2 + 8 + 8 = 88 bytes
type NetworkEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	SrcAddr   [16]byte
	DstAddr   [16]byte
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Family    uint8
	Pad0      [2]byte // mirrors __u8 _pad0[2] in C
	Timestamp uint64
	Ret       int64
}

// MmapEvent mirrors struct mmap_event.
// Used for: mmap (PROT_EXEC only), mprotect (PROT_EXEC only).
// Size: 3×4 + 16 + 4 + 8 + 8 + 4 + 4 + 4 + 4 + 256 + 8 = 336 bytes
type MmapEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	Comm      [16]byte
	Pad0      uint32 // mirrors __u32 _pad0 in C
	Addr      uint64
	Length    uint64
	Prot      uint32
	MapFlags  uint32
	Fd        int32
	Pad1      uint32 // mirrors __u32 _pad1 in C
	Filename  [256]byte
	Timestamp uint64
}

// PtraceEvent mirrors struct ptrace_event.
// Used for: ptrace only.
// Size: 4×4 + 16 + 4 + 4 + 8 + 8 = 56 bytes
type PtraceEvent struct {
	Type      uint32
	PID       uint32
	TargetPID uint32
	UID       uint32
	Comm      [16]byte
	Request   uint32
	Pad0      uint32 // mirrors __u32 _pad0 in C
	Timestamp uint64
	Ret       int64
}

// CapsetEvent mirrors struct capset_event.
// Used for: capset only.
// Size: 3×4 + 16 + 4 + 8 + 8 + 8 + 8 + 8 = 72 bytes
type CapsetEvent struct {
	Type        uint32
	PID         uint32
	UID         uint32
	Comm        [16]byte
	Pad0        uint32 // mirrors __u32 _pad0 in C
	Effective   uint64
	Permitted   uint64
	Inheritable uint64
	Timestamp   uint64
	Ret         int64
}

// NamespaceEvent mirrors struct namespace_event.
// Used for: unshare, setns.
// Size: 3×4 + 16 + 4 + 4 + 8 + 8 = 52 bytes
type NamespaceEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	Comm      [16]byte
	NSType    uint32
	Flags     uint32
	Pad1      [4]byte // ← added: mirrors _ [4]byte in bpfNamespaceEvent
	Timestamp uint64
	Ret       int64
}

// ModuleEvent mirrors struct module_event.
// Used for: init_module, finit_module.
// Size: 4×4 + 16 + 256 + 8 + 8 = 304 bytes
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

// dnsEventRaw mirrors struct dns_event_raw.
// Unexported — used only inside the listener for binary.Read.
// The listener parses the payload with gopacket and produces
// a DNSEvent which is what the dispatcher and consumers see.
// Size: 2×4 + 8 + 16 + 2×4 + 256 = 296 bytes
type dnsEventRaw struct {
	Type       uint32
	PID        uint32
	Timestamp  uint64
	Comm       [16]byte
	UID        uint32
	PayloadLen uint32
	Payload    [256]byte
}

// ============================================================
// Dispatcher-level types.
// These are produced by the dispatcher, not deserialized
// directly from eBPF bytes.
// ============================================================

// SecurityEvent consolidates ptrace, capset, and namespace
// events into a single type for the security_events table.
// The dispatcher translates PtraceEvent / CapsetEvent /
// NamespaceEvent into this before sending downstream.
type SecurityEvent struct {
	Type      uint32
	EventName string
	PID       uint32
	UID       uint32
	Comm      string
	TargetPID uint32 // ptrace only, 0 otherwise
	Details   string // JSON string of event-specific fields
	Timestamp uint64
}

// DNSQuestion is one question entry from a parsed DNS packet.
type DNSQuestion struct {
	Name string
	Type string
}

// DNSAnswer is one answer entry from a parsed DNS packet.
type DNSAnswer struct {
	Name string
	IP   string
	TTL  uint32
}

// DNSEvent is the parsed DNS event produced by the listener
// from a dnsEventRaw after gopacket parsing.
// Sent on the Network channel with Type = EventTypeNetDNS.
type DNSEvent struct {
	PID       uint32
	UID       uint32
	Comm      string
	Timestamp uint64
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

// ============================================================
// Channel bundle.
// Created once in service.go, passed to the dispatcher and
// to every job that consumes events.
// ============================================================

// Channels holds one typed channel per event category.
// Buffer depth should match the YARA pool queue size so
// neither side applies unwanted back-pressure on the other.
type Channels struct {
	Process   chan ProcessEvent
	File      chan FileEvent
	Network   chan NetworkEvent
	Memory    chan MmapEvent // mmap + mprotect events
	Security  chan SecurityEvent
	Module    chan ModuleEvent
	Namespace chan NamespaceEvent
}

// NewChannels allocates all typed event channels.
func NewChannels(bufferDepth int) *Channels {
	return &Channels{
		Process:   make(chan ProcessEvent, bufferDepth),
		File:      make(chan FileEvent, bufferDepth),
		Network:   make(chan NetworkEvent, bufferDepth),
		Memory:    make(chan MmapEvent, bufferDepth),
		Security:  make(chan SecurityEvent, bufferDepth),
		Module:    make(chan ModuleEvent, bufferDepth),
		Namespace: make(chan NamespaceEvent, bufferDepth),
	}
}

// ============================================================
// Helpers
// ============================================================

// CStringToGo converts a null-terminated C string held in a
// byte slice to a Go string. Replaces utilities.ConvertCStringToGo.
func CStringToGo(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

// In types.go — add this function
func EventTypeName(t uint32) string {
	names := map[uint32]string{
		1:  "execve",
		4:  "setuid",
		5:  "setgid",
		6:  "ptrace",
		8:  "memfd_create",
		9:  "mmap",
		10: "mprotect",
		11: "capset",
		20: "file_open",
		22: "file_delete",
		23: "file_rename",
		24: "file_chmod",
		40: "net_connect",
		41: "net_bind",
		46: "net_dns",
		47: "net_raw_sock",
		48: "net_packet",
		60: "module_load",
		70: "ns_create",
		71: "ns_enter",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return "unknown"
}
