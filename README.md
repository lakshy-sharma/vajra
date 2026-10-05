# Vajra EDR

An endpoint detection and response system engineered to be soft on your systems and your security teams.

A huge shoutout to [Kraken](https://github.com/botherder/kraken) which is my inspiration to start this project.

Made with ❤️ in India

## Goals

Build a modern, production-grade endpoint detection and response system with routine scanning, behavioral monitoring, and remediation — without becoming a resource hog or an alert machine gun.

**What makes us different?**

1. Reduced memory and CPU footprint through careful engineering and load-aware autotune.
2. Alert fatigue addressed at the architecture level — unified dedup, result caching, and a single Finding writer across all detection sources.
3. eBPF-based monitoring — no kernel modules, no polling, no missed events.
4. Normalized detection schema — all findings from all sources land in one table, making the UI, sync, and response system simple.
5. Composable analyzer pipeline — YARA, hash lookup, LD_PRELOAD, capability abuse, and LOLBin checks run as independent stages. Adding a new analyzer is one struct and one line in service.go.

## Current Features

- eBPF syscall monitoring — process execution, file creation, network connections, memory events, dup2/dup3 stdio redirection, namespace operations, kernel module loads
- Reverse shell detection via dup2/dup3 tracepoints — catches `bash -i >& /dev/tcp/...` that exec-time inspection misses
- YARA file and process scanning via an autotuning worker pool with load-average awareness
- Three-condition file eligibility — execute bit, magic bytes, or triggered by known interpreter
- Runtime process analysis — LD_PRELOAD injection, dangerous capability detection
- Autorun/persistence scanner — all major Linux persistence categories (systemd, cron, shell profiles, PAM, LD_PRELOAD, XDG, D-Bus, at jobs, anacron, SysV init)
- Unified detection schema — all sources write through FindingWriter to a single detections table with normalized extension tables
- Evidence snapshots — /proc state captured immediately on HIGH/CRITICAL detections
- Process tree — every execve written as adjacency list for server-side recursive CTE traversal
- SQLite persistence — WAL mode, retention-based cleanup, append-only audit log
- Intelligent deduplication — TTL-based scan cache, QuickHash (head+tail+mtime), alert dedup with count tracking
- Automatic YARA rule updates from YARA Forge with 7-generation archive rotation
- CLI — `vajra scan [dir]`, `vajra rules update/status`

## Architecture

eBPF Kernel Events
│
▼
Listener → Dispatcher (typed channel fan-out)
│
├── File chan → FileScanner → Analyzer Pipeline → FindingWriter → detections
├── Process chan → ProcessScanner → Content + Runtime Pipelines → FindingWriter → detections
├── Dup chan → DupWatcher → socket check → FindingWriter → detections
├── Network/Memory/Security/Module → EventSink → raw telemetry tables
│
└── (pull-based, periodic)
AutorunScanner → FindingWriter → detections + autoruns

## Resources Required

- **CPUs**: 2 minimum, 4 recommended
- **RAM**: 100 MB typical
- **Kernel**: 5.11+ with `CONFIG_DEBUG_INFO_BTF=y`

## Platform Support

| OS | amd64 | arm64 |
|---|---|---|
| Ubuntu 24.04+ | Yes | Planned |
| Debian Trixie+ | Yes | Planned |
| Fedora 42+ | Planned | Planned |
| Windows 11 | Not Started | — |
| macOS | Not Started | — |

## Installation

```bash
sudo dpkg -i vajra_<version>_amd64.deb
sudo systemctl start vajra
sudo systemctl status vajra
```

Configuration: `/etc/vajra/config.yaml` — Logs: `/var/log/vajra/` — Database: `/var/lib/vajra/`

## CLI

```bash
vajra -c /etc/vajra/config.yaml    # start in monitor mode
vajra scan [directory]             # blocking full filesystem scan
vajra rules update                 # check and download updated YARA rules
vajra rules status                 # show current rules version and archive count
```

## Build

### Dependencies

**Debian/Ubuntu**

build-essential clang llvm libbpf-dev
linux-headers-$(uname -r) linux-tools-$(uname -r)
libyara-dev bpftool

**RHEL/Fedora**

clang llvm libbpf-devel kernel-devel bpftool yara-devel

### First-time setup

```bash
make generate-ebpf   # generate vmlinux.h and compile BPF program
```

Only needed once, or when `ebpf_events.c` changes.

### Build

```bash
make linux_amd64
make linux_arm64
```

## Configuration Reference

```yaml
generic_settings:
  operation_mode: monitor
  work_directory: /var/lib/vajra
  db_directory: /var/lib/vajra
  db_filename: vajra.db

rules_settings:
  rules_filepath: /opt/vajra/rules.zip
  rules_archive_dir: /var/lib/vajra/rules-archive
  rules_remote_url: https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip
  rules_sync_interval_hour: 24
  rules_archive_count: 7

scan_settings:
  target_directory: /
  exclusion_rules:
    exclude_paths:
      - /proc
      - /sys
      - /dev
    exclude_extensions:
      - .swp
      - .lock
    exclude_processes:
      - systemd-journal
      - systemd-udevd

timing_settings:
  autorun_scan_time_min: 30
  database_cleanup_time_hour: 24
  database_retention_days: 90
  shutdown_timeout_sec: 30
  single_file_scan_timeout_sec: 30
  dedup_window_min: 5

performance_settings:
  default_threads: 2
  max_allowed_threads: 8
  scan_queue_size: 1000
```

## Security

If you spot any security issues please contact <lakshy.d.sharma@gmail.com> directly.
