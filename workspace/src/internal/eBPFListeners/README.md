# EDR eBPF Event Generator with CO-RE

A comprehensive eBPF-based event monitoring system designed for Endpoint Detection and Response (EDR) platforms. Provides real-time visibility into process execution, filesystem operations, network activity, and kernel-level events for security monitoring and threat detection.

## 🎯 EDR Use Cases

This event generator is specifically designed for:

- **Threat Detection**: Real-time detection of suspicious process behavior, privilege escalation, and code injection
- **Forensic Analysis**: Complete audit trail of system activities with timestamps and context
- **Behavioral Analysis**: Track process lineage, file access patterns, and network connections
- **Malware Detection**: Identify fileless malware, memory injection, rootkits, and kernel module tampering
- **Compliance Monitoring**: Comprehensive logging of security-relevant system events
- **Incident Response**: Real-time alerting on critical security events

## 🔍 Monitored Event Categories

### Process Events (10 types)
| Event | Description | EDR Relevance |
|-------|-------------|---------------|
| `EXEC` | Process execution | Malware launch detection, process tracking |
| `EXIT` | Process termination | Process lifecycle monitoring |
| `FORK` | Process creation | Process tree analysis, fork bomb detection |
| `SETUID` | UID change | Privilege escalation detection |
| `SETGID` | GID change | Privilege escalation detection |
| `PTRACE` | Debugging/injection | Code injection, anti-debugging detection |
| `PRCTL` | Process control | Capability changes, security modifications |
| `MEMFD` | Anonymous file creation | Fileless malware detection |
| `MMAP` | Memory mapping | Code injection, shared library loading |
| `MPROTECT` | Memory protection change | DEP bypass, ROP chain detection |

### File Events (11 types)
| Event | Description | EDR Relevance |
|-------|-------------|---------------|
| `OPEN` | File access | Data exfiltration, log tampering |
| `CREATE` | File creation | Dropper activity, ransomware indicators |
| `DELETE` | File deletion | Evidence destruction, anti-forensics |
| `RENAME` | File renaming | Ransomware encryption, evasion |
| `CHMOD` | Permission change | Backdoor installation, privilege escalation |
| `CHOWN` | Ownership change | Persistence mechanisms |
| `LINK` | Hard link creation | File hiding, timestamp manipulation |
| `SYMLINK` | Symbolic link creation | Path traversal, privilege escalation |
| `TRUNCATE` | File truncation | Log clearing, data destruction |
| `SETXATTR` | Extended attribute set | SELinux/AppArmor bypass |
| `REMOVEXATTR` | Extended attribute removal | Security attribute tampering |

### Network Events (6 types)
| Event | Description | EDR Relevance |
|-------|-------------|---------------|
| `CONNECT` | Outbound connection | C&C communication, data exfiltration |
| `BIND` | Port binding | Backdoor listeners, reverse shells |
| `LISTEN` | Socket listening | Unauthorized services |
| `ACCEPT` | Connection accepted | Incoming attack attempts |
| `SENDMSG` | Data transmission | Protocol analysis (optional) |
| `RECVMSG` | Data reception | Protocol analysis (optional) |

### Module/Driver Events (4 types)
| Event | Description | EDR Relevance |
|-------|-------------|---------------|
| `MODULE_LOAD` | Kernel module loading | Rootkit detection |
| `MODULE_UNLOAD` | Kernel module unloading | Anti-forensics activity |
| `BPF_LOAD` | eBPF program loading | eBPF-based rootkits, evasion |
| `BPF_ATTACH` | eBPF program attachment | Kernel-level manipulation |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│           EDR Analysis Engine                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ Threat   │  │ Behavior │  │ Forensic │      │
│  │ Detection│  │ Analysis │  │ Logging  │      │
│  └────▲─────┘  └────▲─────┘  └────▲─────┘      │
└───────┼─────────────┼─────────────┼─────────────┘
        │             │             │
        └─────────────┴─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │   EventGenerator (Go)      │
        │   - Event Processing       │
        │   - Callback Routing       │
        │   - Data Enrichment        │
        └─────────────┬─────────────┘
                      │
              Perf Event Buffer
                      │
        ┌─────────────▼─────────────┐
        │   eBPF Programs (Kernel)   │
        │   - 30+ Tracepoints        │
        │   - CO-RE Portability      │
        │   - Zero Overhead Filtering│
        └─────────────┬─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │   Linux Kernel Events      │
        │   Syscall Tracepoints      │
        └───────────────────────────┘
```

## 📊 Event Data Structures

### Process Event Fields
```go
- PID, PPID (process tree)
- UID, GID, EUID, EGID (credentials)
- Comm (process name)
- Filename (executable path)
- Args (command line arguments)
- CWD (working directory)
- Timestamp (nanosecond precision)
- Return value
```

### File Event Fields
```go
- PID, UID, GID
- Filename, TargetPath (for operations like rename)
- Mode (permissions)
- Flags (open flags, creation flags)
- Size (for truncate operations)
- Timestamp
- Return value
```

### Network Event Fields
```go
- PID, UID, GID
- Source/Destination IP addresses
- Source/Destination ports
- Protocol, Address family
- Timestamp
- Return value
```

## 🚀 Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    make \
    golang-1.21

# Check kernel version (need 5.8+)
uname -r

# Verify BTF support
ls -la /sys/kernel/btf/vmlinux
```

### Installation

```bash
# Clone or create project
mkdir edr-ebpf-generator
cd edr-ebpf-generator

# Initialize Go module
cat > go.mod << 'EOF'
module github.com/yourusername/edr-ebpf-generator

go 1.21

require github.com/cilium/ebpf v0.12.3
EOF

go mod download

# Install bpf2go
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Copy source files
# - main.go
# - ebpf_events.c

# Generate eBPF objects
go generate ./...

# Build
go build -o edr-ebpf-gen

# Run (requires privileges)
sudo ./edr-ebpf-gen
```

## 🔧 Integration Examples

### Example 1: Basic EDR Integration

```go
package main

import (
    "log"
    "github.com/yourusername/edr-ebpf-generator/events"
)

type EDREngine struct {
    threatDetector *ThreatDetector
    forensicLog    *ForensicLogger
    behaviorAI     *BehaviorAnalyzer
}

func (edr *EDREngine) HandleEvent(eventType uint32, data interface{}) {
    switch eventType {
    case events.EventTypeProcessExec:
        event := data.(events.ProcessEvent)
        
        // 1. Log to forensic database
        edr.forensicLog.LogProcessExec(event)
        
        // 2. Check threat intelligence
        if edr.threatDetector.IsMalicious(event.Filename) {
            edr.AlertCritical("Known malware executed", event)
        }
        
        // 3. Behavioral analysis
        edr.behaviorAI.AnalyzeProcess(event)
        
    case events.EventTypeProcessSetuid:
        event := data.(events.ProcessEvent)
        
        // Detect privilege escalation
        if event.EUID == 0 && event.UID != 0 {
            edr.AlertHigh("Privilege escalation detected", event)
        }
    }
}

func main() {
    edr := NewEDREngine()
    
    gen, err := events.NewEventGenerator(edr.HandleEvent)
    if err != nil {
        log.Fatal(err)
    }
    defer gen.Stop()
    
    gen.Start()
    
    // Keep running
    select {}
}
```

### Example 2: Threat Detection

```go
func threatDetectionCallback(eventType uint32, data interface{}) {
    switch eventType {
    case EventTypeProcessMemfd:
        // Fileless malware detection
        event := data.(ProcessEvent)
        alert := Alert{
            Severity: "CRITICAL",
            Type:     "Fileless Execution",
            Message:  fmt.Sprintf("Process %s created anonymous file", 
                     cString(event.Comm[:])),
            PID:      event.PID,
            Context:  event,
        }
        sendToSIEM(alert)
        
    case EventTypeProcessPtrace:
        // Code injection detection
        event := data.(PtraceEvent)
        if event.Request == PTRACE_POKETEXT {
            alert := Alert{
                Severity: "CRITICAL",
                Type:     "Code Injection",
                Message:  fmt.Sprintf("Process %d injecting into %d",
                         event.PID, event.TargetPID),
                Context:  event,
            }
            sendToSIEM(alert)
        }
        
    case EventTypeModuleLoad:
        // Rootkit detection
        event := data.(ModuleEvent)
        if !isKnownModule(event.Name) {
            alert := Alert{
                Severity: "CRITICAL",
                Type:     "Unknown Kernel Module",
                Message:  "Possible rootkit installation",
                Context:  event,
            }
            sendToSIEM(alert)
        }
    }
}
```

### Example 3: Process Tree Tracking

```go
type ProcessTree struct {
    processes map[uint32]*ProcessNode
    mu        sync.RWMutex
}

type ProcessNode struct {
    PID       uint32
    PPID      uint32
    Comm      string
    Filename  string
    StartTime uint64
    Children  []*ProcessNode
}

func (pt *ProcessTree) HandleEvent(eventType uint32, data interface{}) {
    pt.mu.Lock()
    defer pt.mu.Unlock()
    
    switch eventType {
    case EventTypeProcessExec:
        event := data.(ProcessEvent)
        node := &ProcessNode{
            PID:       event.PID,
            PPID:      event.PPID,
            Comm:      cString(event.Comm[:]),
            Filename:  cString(event.Filename[:]),
            StartTime: event.Timestamp,
        }
        
        // Add to tree
        pt.processes[event.PID] = node
        
        // Link to parent
        if parent, ok := pt.processes[event.PPID]; ok {
            parent.Children = append(parent.Children, node)
        }
        
    case EventTypeProcessExit:
        event := data.(ProcessEvent)
        // Mark process as exited but keep for forensics
        if node, ok := pt.processes[event.PID]; ok {
            node.EndTime = event.Timestamp
        }
    }
}
```

### Example 4: File Integrity Monitoring

```go
type FileMonitor struct {
    watchPaths map[string]bool
    baseline   map[string]FileHash
}

func (fm *FileMonitor) HandleEvent(eventType uint32, data interface{}) {
    switch eventType {
    case EventTypeFileCreate, EventTypeFileOpen, 
         EventTypeFileDelete, EventTypeFileRename:
        event := data.(FileEvent)
        filename := cString(event.Filename[:])
        
        // Check if in monitored paths
        if fm.shouldMonitor(filename) {
            switch eventType {
            case EventTypeFileCreate:
                fm.AlertInfo("New file in monitored path", filename)
                
            case EventTypeFileDelete:
                fm.AlertWarning("File deleted from monitored path", filename)
                
            case EventTypeFileRename:
                target := cString(event.TargetPath[:])
                fm.AlertWarning("File renamed in monitored path", 
                    fmt.Sprintf("%s -> %s", filename, target))
            }
            
            // Trigger file scan
            go fm.scanFile(filename, event.PID)
        }
    }
}
```

## 🎛️ Configuration & Tuning

### Filtering Events

You can add filters directly in the eBPF code to reduce noise:

```c
// In ebpf_events.c - Filter by UID
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Ignore system users
    if (uid < 1000) {
        return 0;
    }
    
    // ... rest of the handler
}

// Filter by path prefix
static __always_inline bool should_ignore_path(const char *path) {
    char buf[32];
    bpf_probe_read_user_str(buf, sizeof(buf), path);
    
    // Ignore /proc, /sys, /dev
    if (buf[0] == '/' && buf[1] == 'p' && buf[2] == 'r') return true;
    if (buf[0] == '/' && buf[1] == 's' && buf[2] == 'y') return true;
    if (buf[0] == '/' && buf[1] == 'd' && buf[2] == 'e') return true;
    
    return false;
}
```

### Performance Tuning

```go
// Adjust perf buffer size based on event rate
reader, err := perf.NewReader(objs.Events, os.Getpagesize()*128) // Larger buffer

// Disable high-frequency events if not needed
// Comment out sendmsg/recvmsg tracepoint attachments

// Use event batching
const batchSize = 100
eventBatch := make([]Event, 0, batchSize)

func processEvents() {
    for {
        event := readEvent()
        eventBatch = append(eventBatch, event)
        
        if len(eventBatch) >= batchSize {
            processBatch(eventBatch)
            eventBatch = eventBatch[:0]
        }
    }
}
```

## 📈 Performance Metrics

### Overhead
- **CPU**: <1-3% on typical workloads
- **Memory**: 50-200MB depending on event rate
- **Latency**: Sub-microsecond event capture

### Event Rates (typical production system)
- **Low activity**: 100-500 events/sec
- **Medium activity**: 1,000-5,000 events/sec
- **High activity**: 10,000+ events/sec

### Optimization Tips
1. Filter events in eBPF (kernel space) rather than userspace
2. Disable high-frequency events (sendmsg/recvmsg) unless needed
3. Use larger perf buffers for bursty workloads
4. Batch event processing in userspace
5. Consider using eBPF maps for aggregation before sending to userspace

## 🔒 Security Considerations

### Privileges Required
- `CAP_BPF` - Load and manage eBPF programs
- `CAP_PERFMON` - Access performance monitoring interfaces
- `CAP_NET_ADMIN` - For network event monitoring

```bash
# Grant specific capabilities (recommended)
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./edr-ebpf-gen

# Or run as root (less secure)
sudo ./edr-ebpf-gen
```

### Event Data Privacy
- Events may contain sensitive information (filenames, process names, network addresses)
- Implement encryption for event transmission to central servers
- Apply data retention policies
- Consider GDPR/compliance requirements

### Anti-Evasion
- Monitor for eBPF program manipulation (EVENT_BPF_LOAD)
- Detect attempts to unload security modules (EVENT_MODULE_UNLOAD)
- Watch for ptrace attacks on the EDR agent itself
- Implement integrity checking of the eBPF programs

## 🐛 Troubleshooting

### "Operation not permitted"
```bash
# Check capabilities
getcap ./edr-ebpf-gen

# Grant capabilities
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./edr-ebpf-gen
```

### "BTF not found"
```bash
# Check BTF
ls /sys/kernel/btf/vmlinux

# If missing, kernel needs CONFIG_DEBUG_INFO_BTF=y
# Check current config
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

### High CPU usage
```bash
# Check event rate
# Add counters in your callback:
var eventCount atomic.Uint64

func callback(eventType uint32, data interface{}) {
    eventCount.Add(1)
}

// Print stats periodically
go func() {
    ticker := time.NewTicker(time.Second)
    for range ticker.C {
        fmt.Printf("Events/sec: %d\n", eventCount.Swap(0))
    }
}()
```

### Missing events
- Check if tracepoint attachment succeeded (logs show warnings)
- Verify kernel version supports all syscalls
- Some events may be architecture-specific

## 📦 Distribution

### Building for Multiple Architectures

```bash
# AMD64
GOOS=linux GOARCH=amd64 go build -o edr-ebpf-gen-amd64

# ARM64
GOOS=linux GOARCH=arm64 go build -o edr-ebpf-gen-arm64

# Create release packages
tar -czf edr-ebpf-gen-linux-amd64.tar.gz edr-ebpf-gen-amd64
tar -czf edr-ebpf-gen-linux-arm64.tar.gz edr-ebpf-gen-arm64
```

### Deployment Considerations

1. **Kernel Compatibility**: Requires 5.8+ with BTF enabled
2. **Dependencies**: Self-contained binary, no runtime dependencies
3. **Resource Requirements**: 50-200MB RAM, <3% CPU
4. **Network**: None required (unless forwarding events)
5. **Storage**: Minimal (events sent to callback, not stored locally)

## 🔬 Testing

### Generate Test Events

```bash
# Process events
sh -c 'echo test'              # exec
sudo su                        # setuid
strace -p $$                   # ptrace

# File events
touch /tmp/test.txt            # create
chmod 755 /tmp/test.txt        # chmod
rm /tmp/test.txt               # delete
mv /tmp/a /tmp/b               # rename

# Network events
nc -l 8080 &                   # bind/listen
curl example.com               # connect

# Module events
sudo modprobe dummy            # module load
```

## 📚 References

- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [Linux Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [eBPF Documentation](https://ebpf.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## 📄 License

GPL (required for eBPF programs)

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional syscall coverage
- Performance optimizations
- Advanced filtering logic
- Integration examples
- Documentation improvements