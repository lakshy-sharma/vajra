# Vajra EDR

An endpoint detection and response system engineered to be soft on your systems and your security teams.

A huge shoutout to [Kraken](https://github.com/botherder/kraken) which is my inspiration to start this project.

Made with ❤️ in India

## Goals

Build a modern, production-grade endpoint detection and response system with routine scanning, behavioral monitoring, and remediation — without becoming a resource hog or an alert machine gun.

**What makes us different?**

1. Minimal resource footprint — careful engineering and load-aware tuning keep CPU and memory usage low even under heavy workloads.
2. Alert fatigue addressed at the architecture level — unified deduplication and a single detection writer across all sources mean your team sees signal, not noise.
3. eBPF-based monitoring — hooks directly into the Linux kernel with no kernel modules, no polling, and no missed events.
4. Normalized detection schema — every finding from every source lands in one table, making dashboards, sync, and response straightforward.
5. Composable detection pipeline — hash lookup, YARA scanning, and behavioral checks run as independent stages. Adding a new detection is one struct and one line.

## Current Features

- **Real-time kernel monitoring** — tracks process launches, file writes, network connections, memory operations, and privilege changes as they happen
- **Reverse shell detection** — catches attackers redirecting a shell over the network, including techniques that bypass traditional exec-time inspection
- **YARA scanning** — scans files and running processes against a community ruleset via a self-tuning worker pool that backs off under system load
- **Malware hash detection** — checks file hashes against a known-bad dataset before running YARA, short-circuiting the pipeline on confirmed malware
- **Behavioral process analysis** — detects library injection and dangerous Linux capability abuse at runtime
- **Persistence scanner** — monitors all major Linux persistence locations: systemd units, cron jobs, shell profiles, PAM modules, XDG autostart, D-Bus services, SysV init scripts, and more
- **Secrets scanner** — finds credentials, API keys, and tokens left in files across the filesystem using the betterleaks engine, with a fingerprint-based ignore list for known false positives
- **Evidence snapshots** — captures live process state immediately on high-severity detections, before the process can exit or clean up
- **Process tree** — records every process launch as an ancestry chain for forensic investigation
- **Intelligent deduplication** — suppresses repeated alerts for the same finding within a configurable window, keeping alert volume manageable
- **Automatic rule updates** — pulls the latest YARA rules from YARA Forge on a schedule with archive rotation
- **CLI** — on-demand scanning, rule management, hash database updates, and secrets ignore list management

## Architecture

```
eBPF Kernel Events
│
▼
Listener → Dispatcher (typed channel fan-out)
│
├── File events → FileScanner → Analyzer Pipeline → FindingWriter → detections
├── Process events → ProcessScanner → Content + Runtime Pipelines → FindingWriter → detections
├── Network events → Reverse Shell Detector → FindingWriter → detections
├── All other events → EventSink → raw telemetry tables
│
└── (periodic)
AutorunScanner → FindingWriter → detections + autoruns
SecretsScanner → FindingWriter → detections

```

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
vajra -c /etc/vajra/config.yaml       # start in monitor mode
vajra scan [directory]                 # run a full on-demand scan
vajra rules update                     # download latest YARA rules
vajra rules status                     # show current rules version
vajra hashes update                    # rebuild malware hash database
vajra hashes status                    # show hash database status
vajra secrets ignore <detection_id>    # mark a secrets finding as noise
vajra secrets export-ignore            # write ignore list for next scan
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
make generate-ebpf   # compile the kernel instrumentation — only needed once
```

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
  rules_archive_dir: /opt/vajra/rules-archive
  rules_remote_url: https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip
  rules_sync_interval_hour: 24
  rules_archive_count: 7

threat_intel_settings:
  malware_bazaar_auth_key: ""
  bloom_filter_path: /opt/vajra/hashes.bloom
  hash_sync_interval_hour: 24

scan_settings:
  target_directory: /
  secrets:
    target_directories:
      - /home
      - /root
      - /etc
      - /opt
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
