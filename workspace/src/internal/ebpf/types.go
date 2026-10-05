// internal/ebpf/types.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package ebpf

import "bytes"

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
	EventTypeProcessDupStdio uint32 = 12 // dup2/dup3 onto fd 0/1/2

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

type RawEvent struct {
	Type uint32
	Data interface{}
}

// ProcessEvent mirrors struct process_event.
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
	Pad0      uint32
	Flags     uint32
	Pad1      [4]byte
	Timestamp uint64
	Ret       int64
}

// FileEvent mirrors struct file_event.
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
	Pad0      [2]byte
	Timestamp uint64
	Ret       int64
}

// MmapEvent mirrors struct mmap_event.
type MmapEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	Comm      [16]byte
	Pad0      uint32
	Addr      uint64
	Length    uint64
	Prot      uint32
	MapFlags  uint32
	Fd        int32
	Pad1      uint32
	Filename  [256]byte
	Timestamp uint64
}

// PtraceEvent mirrors struct ptrace_event.
type PtraceEvent struct {
	Type      uint32
	PID       uint32
	TargetPID uint32
	UID       uint32
	Comm      [16]byte
	Request   uint32
	Pad0      uint32
	Timestamp uint64
	Ret       int64
}

// CapsetEvent mirrors struct capset_event.
type CapsetEvent struct {
	Type        uint32
	PID         uint32
	UID         uint32
	Comm        [16]byte
	Pad0        uint32
	Effective   uint64
	Permitted   uint64
	Inheritable uint64
	Timestamp   uint64
	Ret         int64
}

// DupEvent mirrors struct dup_event.
// Emitted when dup2 or dup3 redirects any fd onto stdin, stdout, or stderr.
// OldFd is the source — if it resolves to a network socket inode in
// /proc/net/tcp* the combination is a reverse shell.
// NewFd is always 0, 1, or 2 — kernel-side filter enforces this.
// Size: 4+4+4+4+16+4+4+8 = 48 bytes
type DupEvent struct {
	Type      uint32
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      [16]byte
	OldFd     uint32
	NewFd     uint32
	Timestamp uint64
}

// NamespaceEvent mirrors struct namespace_event.
type NamespaceEvent struct {
	Type      uint32
	PID       uint32
	UID       uint32
	Comm      [16]byte
	NSType    uint32
	Flags     uint32
	Pad1      [4]byte
	Timestamp uint64
	Ret       int64
}

// ModuleEvent mirrors struct module_event.
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

type dnsEventRaw struct {
	Type       uint32
	PID        uint32
	Timestamp  uint64
	Comm       [16]byte
	UID        uint32
	PayloadLen uint32
	Payload    [256]byte
}

// SecurityEvent consolidates ptrace, capset, namespace, and dup_stdio
// events into a single type for the security_events table.
type SecurityEvent struct {
	Type      uint32
	EventName string
	PID       uint32
	UID       uint32
	Comm      string
	TargetPID uint32
	Details   string
	Timestamp uint64
}

type DNSQuestion struct {
	Name string
	Type string
}

type DNSAnswer struct {
	Name string
	IP   string
	TTL  uint32
}

type DNSEvent struct {
	PID       uint32
	UID       uint32
	Comm      string
	Timestamp uint64
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

type Channels struct {
	Process   chan ProcessEvent
	File      chan FileEvent
	Network   chan NetworkEvent
	Memory    chan MmapEvent
	Security  chan SecurityEvent
	Module    chan ModuleEvent
	Namespace chan NamespaceEvent
	Dup       chan DupEvent
}

func NewChannels(bufferDepth int) *Channels {
	return &Channels{
		Process:   make(chan ProcessEvent, bufferDepth),
		File:      make(chan FileEvent, bufferDepth),
		Network:   make(chan NetworkEvent, bufferDepth),
		Memory:    make(chan MmapEvent, bufferDepth),
		Security:  make(chan SecurityEvent, bufferDepth),
		Module:    make(chan ModuleEvent, bufferDepth),
		Namespace: make(chan NamespaceEvent, bufferDepth),
		Dup:       make(chan DupEvent, bufferDepth),
	}
}

func CStringToGo(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

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
		12: "dup_stdio",
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
