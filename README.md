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

For roadmap and feature development plans refer to TODO.md.

## Current Features

1. eBPF syscall monitoring — file creation, process execution, network connections, memory events, namespace operations.
2. YARA file and process scanning via an autotuning worker pool.
3. Autorun/persistence scanner covering all major Linux persistence categories (systemd, cron, shell profiles, PAM, LD_PRELOAD, XDG, D-Bus, at jobs, anacron, SysV init).
4. SQLite-backed event storage with retention-based cleanup.
5. Intelligent deduplication via TTL-based scan cache and magic-byte file filtering.

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

## Contributing

### Build Dependencies

**Debian/Ubuntu**

build-essential
clang
llvm
libbpf-dev
linux-headers-$(uname -r)
linux-tools-$(uname -r)
libyara-dev
bpftool

**RHEL/Fedora**

clang
llvm
libbpf-devel
kernel-devel
bpftool
yara-devel

### First-time setup

Generate `vmlinux.h` and compile the eBPF program. This requires a running kernel
with BTF enabled and only needs to be done once, or whenever `ebpf_events.c` changes.

make generate-ebpf

### Build

Linux amd64

make linux_amd64

Linux arm64

make linux_arm64

### Configuration

Copy and edit the example config before running:

```yaml
generic_settings:
  operation_mode: monitor
  work_directory: /var/lib/vajra
  db_directory: /var/lib/vajra
  db_filename: vajra.db

scan_settings:
  target_directory: /
  rules_filepath: /opt/vajra/rules.zip
  exclusion_rules:
    exclude_paths:
      - /proc
      - /sys
      - /dev
    exclude_extensions: []
    exclude_patterns: []
    exclude_processes:
      - systemd-journal
      - systemd-udevd

timing_settings:
  autorun_scan_time_min: 30
  database_cleanup_time_hour: 24
  database_retention_days: 90
  shutdown_timeout_sec: 30
  single_file_scan_timeout_sec: 30

performance_settings:
  default_threads: 2
  max_allowed_threads: 8
  scan_queue_size: 1000
```

## Security

If you spot any security issues please contact <lakshy.d.sharma@gmail.com> directly.
Best effort will be made to understand and resolve concerns quickly.
Thank you for your awareness in advance.
