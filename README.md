# Vajra

An endpoint detection and response system engineered to be soft on your systems and your security teams.

A huge shoutout to [Kraken](https://github.com/botherder/kraken) which is my inspiration to start this project.

Made with :heart: in India

## Goals

Build a modern endpoint detection and response system capable of routine system scans, behavioral monitoring, and remediation of malicious files.

**What makes us different?**

1. Reduced memory and CPU footprint through modern languages and careful engineering.
2. Extra attention to minimizing alert fatigue through intelligent filtering and deduplication.
3. eBPF-based monitoring — no kernel modules, no polling, no missed events.
4. Single self-contained binary with embedded YARA rules and SQLite persistence.
5. Analyzer pipeline architecture — YARA, hash lookup, LD_PRELOAD, reverse shell, and capability abuse checks run as composable stages.

For roadmap and feature development plans refer to TODO.md.

## Current Features

1. eBPF syscall monitoring — file creation, process execution, network connections, memory events, namespace operations, kernel module loads.
2. YARA file and process scanning via an autotuning worker pool with load-average awareness.
3. Analyzer pipeline — pluggable detection stages with result caching, short-circuit on CRITICAL, and separate content vs runtime pipelines for process events.
4. Runtime process analysis — LD_PRELOAD injection detection, reverse shell detection via stdio fd inspection, dangerous capability detection.
5. Autorun/persistence scanner covering all major Linux persistence categories (systemd, cron, shell profiles, PAM, LD_PRELOAD, XDG, D-Bus, at jobs, anacron, SysV init).
6. SQLite-backed event storage with retention-based cleanup and alert deduplication.
7. Intelligent deduplication — TTL-based scan cache, magic-byte file filtering, head+tail+mtime QuickHash, alert-level dedup with count tracking.
8. Automatic YARA rule updates from YARA Forge with 7-generation archive rotation.
9. Network, memory, security, and module event persistence with severity classification.

## Architecture

eBPF Kernel Events
│
▼
Listener → Dispatcher (fan-out)
│
├── File channel → FileScanner → Analyzer Pipeline → DB
├── Process channel → ProcessScanner → Content Pipeline + Runtime Pipeline → DB
├── Network/Memory/Security/Module channels → EventSink → DB
└── Autorun scanner (periodic) → DB

## Resources Required

1. **CPUs**: 2 minimum, 4 recommended *(configurable)*
2. **RAM**: 100 MB typical
3. **Kernel**: 5.11+ with `CONFIG_DEBUG_INFO_BTF=y`

## Platform Support Matrix

| OS | amd64 | arm64 |
|-|-|-|
| Ubuntu 24.04+ | Yes | Planned |
| Debian Trixie+ | Yes | Planned |
| Fedora 42+ | Planned | Planned |
| Windows 11 | Not Started | Not Started |
| macOS | Not Started | Not Started |

## Installation

Download the latest `.deb` package from releases and install:

```bash
sudo dpkg -i vajra_<version>_amd64.deb
sudo systemctl start vajra
sudo systemctl status vajra
```

Configuration lives at `/etc/vajra/config.yaml`. Logs at `/var/log/vajra/`. Database at `/var/lib/vajra/`.

## CLI

```bash
vajra -c /etc/vajra/config.yaml          # start in monitor mode
vajra rules update                        # check and download updated YARA rules
vajra rules status                        # show current rules version and archive count
```

## Contributing

### Build Dependencies

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

### Configuration

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
Best effort will be made to understand and resolve concerns quickly.
Thank you for your awareness in advance.
