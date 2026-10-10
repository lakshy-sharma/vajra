# Vajra EDR

An endpoint detection and response system engineered to be soft on your systems and your security teams.

A huge shoutout to [Kraken](https://github.com/botherder/kraken) which is my inspiration to start this project.

Made with ❤️ in India

---

## Goals

Build a modern, production-grade endpoint detection and response system with routine scanning, behavioural monitoring, and remediation — without becoming a resource hog or an alert machine gun.

**What makes us different?**

1. **Minimal resource footprint** — load-aware YARA pool tuning keeps CPU usage low under heavy workloads.
2. **Alert fatigue addressed at the architecture level** — unified deduplication and a single detection writer across all sources mean your team sees signal, not noise.
3. **eBPF-based monitoring** — hooks directly into the Linux kernel with no kernel modules, no polling, and no missed events.
4. **Normalised detection schema** — every finding from every source lands in one table, making dashboards, sync, and response straightforward.
5. **Composable detection pipeline** — hash lookup, YARA scanning, and behavioural checks run as independent stages. Adding a new detection is one struct and one line.

---

## Features

- **Real-time kernel monitoring** — tracks process launches, file writes, network connections, memory operations, and privilege changes via eBPF tracepoints
- **Reverse shell detection** — catches dup2/dup3 onto stdin/stdout/stderr, including techniques that bypass exec-time inspection
- **YARA scanning** — scans files and running processes against a community ruleset via a self-tuning worker pool that backs off under system load
- **Malware hash detection** — checks SHA256 against MalwareBazaar dataset before YARA, short-circuiting the pipeline on confirmed malware
- **Behavioural process analysis** — detects LD_PRELOAD injection and dangerous Linux capability abuse at runtime
- **Persistence scanner** — monitors all major Linux persistence locations: systemd units (system, user, timer), cron, shell profiles, PAM modules, XDG autostart, D-Bus services, SysV init, at jobs, anacron, LD_PRELOAD config
- **Secrets scanner** — finds credentials, API keys, and tokens across the filesystem using the betterleaks engine; fingerprint-based ignore list for known false positives
- **Evidence snapshots** — captures live /proc state immediately on HIGH/CRITICAL detections, before the process can exit or clean up
- **Process tree** — records every execve as an ancestry chain for forensic investigation; never pruned
- **Intelligent deduplication** — suppresses repeated alerts within a configurable window, configurable per severity
- **Automatic rule updates** — YARA Forge rules synced on a schedule with archive rotation and zip integrity validation
- **Desktop UI** — Wails-based read-only dashboard for detections, events, autoruns, and configuration
- **CLI** — on-demand scanning, rule management, hash database updates, and secrets ignore list management

---

## Architecture

```
eBPF tracepoints (kernel)
│
▼
Listener (perf ring) → Dispatcher (typed channel fan-out)
│
├─ ch.File     → FileScanner    → Content Pipeline      → FindingWriter → detections
├─ ch.Process  → ProcessScanner → Content + Runtime      → FindingWriter → detections
│                                  Pipelines                              process_tree
├─ ch.Dup      → DupWatcher     → socket inode lookup   → FindingWriter → detections
└─ ch.Network  → EventSink      → network_events
   ch.Memory   →                → memory_events
   ch.Security →                → security_events
   ch.Module   →                → security_events

(periodic)
AutorunScanner  → FindingWriter → detections + autoruns
SecretsScanner  → FindingWriter → detections

(jobs)
RuleSyncer  — YARA Forge rule updates
HashSyncer  — MalwareBazaar Bloom filter rebuild
StatSyncer  — event_statistics aggregation
DBCleanup   — retention enforcement

(UI — separate binary)
vajra-ui → SQLite WAL read-only → detections, events, autoruns, config
```

---

## Resource Requirements

- **CPUs**: 2 minimum, 4 recommended
- **RAM**: ~100 MB typical (Bloom filter ~4 MB, YARA rules variable)
- **Kernel**: 5.11+ with `CONFIG_DEBUG_INFO_BTF=y`
- **Disk**: 1 GB recommended for database and rule archives

---

## Platform Support

| OS | amd64 | arm64 |
|---|---|---|
| Ubuntu 24.04+ | ✅ | Planned |
| Debian Trixie+ | ✅ | Planned |
| Fedora 42+ | Planned | Planned |
| Windows | Not started | — |
| macOS | Not started | — |

---

## Quick Start

### 1. Install

```bash
sudo dpkg -i vajra_<version>_amd64.deb
```

This installs:

- `/opt/vajra/vajra` — daemon + CLI binary
- `/opt/vajra/vajra-ui` — desktop UI binary (if built separately)
- `/etc/vajra/config.yaml` — default configuration
- `/lib/systemd/system/vajra.service` — systemd unit

### 2. Configure

Edit `/etc/vajra/config.yaml`. At minimum set:

```yaml
threat_intel_settings:
  api_key: "your-malwarebazaar-api-key"   # from bazaar.abuse.ch — leave blank to disable hash checking
  bloom_filter_path: /opt/vajra/hashes.bloom

rules_settings:
  rules_filepath: /opt/vajra/rules.zip
```

Get a free MalwareBazaar API key at [bazaar.abuse.ch](https://bazaar.abuse.ch/api/).

### 3. Download initial rules and hash database

```bash
sudo vajra rules update
sudo vajra hashes update   # requires api_key to be set
```

### 4. Start

```bash
sudo systemctl enable --now vajra
sudo systemctl status vajra
```

### 5. Run the UI (optional)

```bash
/opt/vajra/vajra-ui
```

The UI opens the database read-only. No root required.

---

## CLI Reference

```bash
# Daemon
sudo vajra                             # start in monitor mode (same as systemd service)
sudo vajra -c /etc/vajra/config.yaml  # use a specific config file

# On-demand scan
sudo vajra scan                        # scan target_directory from config
sudo vajra scan /opt                   # scan a specific directory

# YARA rules
sudo vajra rules update                # download latest YARA Forge bundle
sudo vajra rules status                # show current rules file hash and archive count

# Malware hashes
sudo vajra hashes update               # rebuild Bloom filter from MalwareBazaar
sudo vajra hashes status               # show Bloom filter path, size, last update

# Secrets scanner ignore list
sudo vajra secrets ignore <id>         # mark a detection as noise (by detection ID)
sudo vajra secrets export-ignore       # write fingerprints to ignore file; restart daemon to apply
```

---

## Building from Source

### Prerequisites

**Debian / Ubuntu**

```bash
sudo apt install build-essential clang llvm libbpf-dev bpftool \
    linux-headers-$(uname -r) linux-tools-$(uname -r) libyara-dev
```

**Fedora / RHEL**

```bash
sudo dnf install clang llvm libbpf-devel bpftool kernel-devel yara-devel
```

**Go toolchain**

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

**UI (optional)**

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
# also requires Node.js >= 20 and npm
```

### First-time eBPF generation

Only needed once per machine, or when `internal/ebpf/c/ebpf_events.c` changes:

```bash
make generate-ebpf
```

This generates `bpf_x86_bpfel.go`, `bpf_arm64_bpfel.go`, and their `.o` files. The generated files are committed to the repository — other developers without the BPF toolchain can build without running this step.

### Build daemon

```bash
make linux_amd64     # produces release/vajra and release/vajra_<version>_amd64.deb
make linux_arm64
```

### Build UI

```bash
make ui              # produces release/vajra-ui
```

### Build everything

```bash
make linux_amd64 ui
```

### Other targets

```bash
make run             # run agent locally (requires root for eBPF)
make test            # run all tests
make lint            # go vet + staticcheck
make clean           # remove release artifacts
make clean-ebpf      # remove release artifacts and generated eBPF files
```

---

## Configuration Reference

The config file lives at `/etc/vajra/config.yaml` and is owned by root with mode `0600`. The daemon rejects config files not owned by root.

```yaml
generic_settings:
  mode: monitor                     # monitor | enforce | diagnose
  db_directory: /var/lib/vajra
  db_filename: vajra.db
  work_directory: /var/lib/vajra/work
  machine_id: ""                    # populated automatically from /etc/machine-id

scan_settings:
  target_directory: /               # root for full-filesystem scans
  excluded_paths:                   # specific files or paths to skip (not directories)
    - /proc
    - /sys
    - /dev
  excluded_processes:               # process comm names never scanned
    - systemd-journal
  max_file_size_bytes: 104857600    # 100 MiB — files larger than this are hashed but not YARA-scanned
  yara_snapshot_bytes: 128          # bytes of matched content stored per YARA string match

secrets_settings:
  enabled: true
  scan_targets:
    - /home
    - /root
    - /etc
    - /opt
  excluded_paths: []
  minimum_confidence: 80            # 0–100; betterleaks confidence threshold
  ignore_file: ""                   # absolute path to fingerprint ignore file; empty = disabled
  match_context_lines: 3            # surrounding lines captured around each match

performance_settings:
  default_threads: 4                # YARA worker pool steady-state size
  max_allowed_threads: 16           # autotune ceiling
  startup_max_threads: 2            # thread count during startup ramp-up
  startup_rampup_min: 5
  scan_queue_size: 512
  ebpf_perf_ring_pages: 64          # must be a power of two
  yara_autotune_interval_sec: 60
  result_cache_size: 10000          # SHA256 → YARA result LRU entries
  autorun_concurrency: 2            # parallel autorun sources per scan pass

timing_settings:
  single_file_scan_timeout_sec: 30
  dedup_window_min: 15
  autorun_scan_interval_min: 60
  secrets_scan_interval_min: 60
  single_target_secrets_timeout_min: 10
  stats_sync_interval_min: 5
  cleanup_interval_hour: 24
  event_retention_days: 30
  hash_sync_interval_hour: 24
  rules_sync_interval_hour: 24
  startup_procwalk_delay_sec: 30    # delay /proc walk to avoid CPU spike at boot
  startup_secrets_delay_min: 5
  startup_autorun_delay_sec: 15

rules_settings:
  rules_filepath: /opt/vajra/rules.zip
  rules_remote_url: https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip
  rules_archive_dir: /opt/vajra/rules-archive
  rules_archive_count: 5
  rules_sync_interval_hour: 24

threat_intel_settings:
  malwarebazaar_url: https://bazaar.abuse.ch/export/csv/full/
  api_key: ""                       # from bazaar.abuse.ch — leave blank to disable hash checking
  bloom_filter_path: /opt/vajra/hashes.bloom
  bloom_capacity: 10000000
  bloom_fp_rate: 0.001

alert_policy:
  interpreters:                     # paths that trigger file scanning when used as parent process
    - /bin/bash
    - /usr/bin/python3
    # ... (full list in default config)
  lolbins:                          # living-off-the-land binaries
    - curl
    - wget
    - nc
    # ...
  dangerous_capabilities:           # Linux capabilities that trigger HIGH severity
    - CAP_SYS_ADMIN
    - CAP_SYS_PTRACE
    - CAP_SYS_MODULE
    - CAP_BPF
    # ...
  process_capability_exclusions:    # per-process capability allow-list
    openvpn:
      - CAP_NET_ADMIN
      - CAP_NET_RAW
  high_value_inbound_ports:         # ports that trigger HIGH on bind
    - 22
    - 3389
    - 5900
  high_value_outbound_ports:        # ports that trigger HIGH on connect
    - 4444
    - 1337
    - 9001
  trusted_ld_paths:                 # LD_PRELOAD paths considered legitimate
    - /lib
    - /lib64
    - /usr/lib
    - /usr/lib64
    - /usr/local/lib

log_settings:
  directory: /var/log/vajra
  filename: vajra.log
  max_size_mb: 100
  max_backups: 5
  max_age_days: 30
  compress: true
  level: info                       # debug | info | warn | error

ui_settings:
  default_theme: system             # system | dark | light
  window_width: 1280
  window_height: 800
  min_window_width: 900
  min_window_height: 600
  page_size: 50
```

---

## Logs and Data Paths

| Path | Contents |
|---|---|
| `/etc/vajra/config.yaml` | Configuration (root-owned, mode 0600) |
| `/var/lib/vajra/vajra.db` | SQLite database (WAL mode) |
| `/var/lib/vajra/work/` | Temporary extraction for rule processing |
| `/var/log/vajra/vajra.log` | Daemon log (rotating) |
| `/opt/vajra/rules.zip` | Active YARA rule bundle |
| `/opt/vajra/rules-archive/` | Previous rule bundles for rollback |
| `/opt/vajra/hashes.bloom` | MalwareBazaar Bloom filter |

---

## Security

Vajra runs as root to load eBPF programs and read `/proc`. The desktop UI (`vajra-ui`) runs unprivileged and connects to the database read-only. Config writes from the UI go through `pkexec` so the UI process itself never needs elevated privileges.

Config file ownership is verified on every load — the daemon rejects configs not owned by uid 0 to prevent privilege escalation via config poisoning.

If you find a security issue please contact <lakshy.d.sharma@gmail.com> directly.
