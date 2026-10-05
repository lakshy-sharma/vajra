# Vajra EDR — Roadmap

## Completed

- eBPF event collection — process, file, network, memory, namespace, module events
- eBPF dispatcher — typed channel fan-out from raw perf events
- eBPF dup2/dup3 tracepoints — stdio fd redirection events, kernel-side filtered to newfd <= 2
- Event sink — network, memory, security, module channels → DB with severity classification
- Memory event dedup — pid+prot keyed, 30s window, W^X always inserted
- YARA file scanner — eBPF-driven, three-condition eligibility (execute bit, magic bytes, interpreter trigger), QuickHash, TTL dedup, result cache, alert dedup
- YARA process scanner — two-pipeline split: content pipeline (cached, filter-aware) + runtime pipeline (always runs)
- Analyzer interface — Pipeline, RunUncached, MergeResults, ResultCache, PID context helpers
- YARAAnalyzer — wraps pool, short-circuits on CRITICAL
- LDPreloadAnalyzer — /proc/PID/environ, snap path awareness
- CapabilityAnalyzer — CapEff bitmask, fires on trusted processes too
- DupWatcher — dup2/dup3 driven reverse shell detection; pid+inode dedup 30s window; no process name filtering; replaces exec-time RevShellAnalyzer
- Alert deduplication — DedupTracker with configurable window, count increment on existing row
- Autotuning YARA worker pool — exponential moving average, load-average aware scaling
- QuickHash — head 8KB + tail 8KB + mtime, detects in-place binary replacement
- Autorun scanner — all Linux persistence categories (systemd, cron, shell profiles, PAM, LD_PRELOAD, XDG autostart, D-Bus, at jobs, anacron, SysV init)
- SQLite persistence — file, process, network, memory, security, autorun, quarantine, statistics, sync_state, process_tree tables
- Process tree — adjacency list written on every execve before analysis; never pruned; composite index for recursive CTE; GetByPID for shallow LOLBin parent lookup
- DB retention cleanup job
- Rule syncer — GitHub API tag check, download, zip magic verify, 7-generation archive rotation, systemd restart
- Deb packaging — amd64 and arm64, corrected postinst/prerm ordering, systemd hardening
- Endpoint identity — machine_id from /etc/machine-id on all event tables
- Source timestamps — boot epoch conversion, eBPF nanoseconds → wall clock Unix time
- Full command line — /proc/PID/cmdline replaces argv[1]-only eBPF capture
- CWD resolution — /proc/PID/cwd symlink replaces unreliable eBPF last-component
- YARA Forge severity prefixes — MALWARE_, MAL_ → CRITICAL; HKTL_, EXPL_ → HIGH; SUSP_ → MEDIUM
- SystemInfo utility — LoadSystemInfo(), EBPFTimestampToUnix(), single source of truth for boot epoch and machine_id
- sync_state table — watermark table for future remote sync delta shipping
- CLI scan command — vajra scan [directory]; blocking walk; execute bit + magic byte eligibility; two-pass count+scan; progress bar with ETA; spinner during count; DB write same as daemon
- sendmsg DNS fix — bpf_probe_read_user replaces bpf_probe_read_kernel for msg_name
- End-to-end validation on live Linux system — timestamps, machine_id, full cmdline, process tree, reverse shell detection all verified

## Phase 1: Detection System (remaining)

1. **Hash checker analyzer** — `internal/analyzer/hash.go`; SHA256 lookup against `known_bad_hashes` table before YARA; short-circuits content pipeline on CRITICAL match; seeded from MalwareBazaar

2. **MalwareBazaar seed command** — `vajra hashes update` cobra subcommand; downloads full CSV from `https://bazaar.abuse.ch/export/csv/full/`; bulk inserts with `source='malwarebazaar'`; daily refresh via tag-check same pattern as rule syncer

3. **Known-good hash registry** — allowlist checked before known-bad; analyst-managed via CLI; `source='manual'`; hash checker skips YARA for known-good entries

4. **LOLBin pattern matching** — `internal/procanalyzer/lolbin.go`; pattern matching on full cmdline; shallow parent lookup via `ProcessTreeQueries.GetByPID`; config-driven rule list; fires HIGH

5. **Running process scanner** — walk `/proc/PID/exe` on startup and periodic interval; submit each to YARA pool; catches malware running before agent started; dedup against RecentScanTracker

6. **Container tagging** — parse `/proc/PID/cgroup` on execve; extract container ID from Docker/k8s/podman path patterns; add `container_id TEXT` and `container_runtime TEXT` to process_scan_results; empty for host processes

7. **trace_id on process events** — UUIDv7 per execve event stored on process_scan_result; child processes inherit parent trace_id via PPID lookup; enables server-side grouping without full tree traversal

8. **Pre-execution autorun YARA scan** — submit ImagePath to YARA pool before inserting new autorun entry; attach matches to autorun record; requires YaraMatches field on AutorunEntry

9. **Crontab path exception in file scanner** — add `/var/spool/cron/`, `/etc/cron.d/`, `/etc/crontab` to config bypass list; plain text, invisible to magic byte and execute bit checks

10. **EventStatistic aggregation job** — hourly ticker; upsert counts into event_statistics grouped by event_type and date; needed before dashboard is useful

11. **Evidence snapshot on HIGH/CRITICAL** — collect process tree, open FDs, loaded libraries, environ from /proc immediately on HIGH/CRITICAL detection; serialize to JSON blob; separate evidence table with reference to detection row; timing is critical as process state goes stale within seconds

12. **Secrets detection** — evaluate Betterleaks Go API; regex scanning for credentials, API keys, tokens; store location + category + context_hash only, never the secret value; own table `secret_findings`

## Phase 2: Hardening and Visibility

1. **File integrity monitoring** — fsnotify/inotify watcher on critical paths; `/etc/vajra/`, `/opt/vajra/`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` as defaults; CRITICAL alert with before/after hash and modifying PID; own table `fim_events`

2. **User inventory and password age** — read `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`; flag users exceeding PASS_MAX_DAYS as MEDIUM; daily scan; own table `user_inventory`

3. **USB and peripheral monitoring** — udev netlink monitor via go-udev; capture connect/disconnect, vendor/product ID, device class, serial; USB mass storage → HIGH; HID → MEDIUM; own table `usb_events`

4. **Kernel integrity check** — compare /proc/modules vs /sys/module/; detect hidden modules; baseline on first run

5. **Binary changed after exec** — periodic SHA256 comparison of /proc/PID/exe against on-disk file for long-running processes; discrepancy = CRITICAL

6. **Coverage telemetry** — periodic heartbeat to DB: uptime, tracepoint count, events processed, pool queue depth, worker count; agent health visibility

7. **Tamper protection** — watchdog goroutine for critical jobs; chattr +i on binary and config; alert on unexpected SIGKILL/SIGTERM

8. **Audit log of agent actions** — immutable `agent_audit_log` table; every quarantine, kill, rule update, config change recorded

9. **VirusTotal enrichment** — optional, API key in config; SHA256 lookup on HIGH/CRITICAL detections only; rate-limited to free tier; results cached in `known_bad_hashes` with `source='virustotal'`

## Phase 3: Remote Sync

1. **Remote server REST API** — separate service; receives telemetry, detections, heartbeats; pushes config and rule updates; authentication required

2. **Agent-to-server delta sync** — ship rows with id > last_synced_id from sync_state table; compressed; retry on failure; acknowledge before updating watermark; purge job deletes shipped rows older than retention window

3. **Over-the-air agent updates** — pull signed binary from server; verify signature; rollback on startup failure

4. **SIEM export** — structured JSON over syslog; Elasticsearch/Splunk/Loki direct HTTP; Fluentbit-compatible output format

5. **STIX/TAXII ingestion** — server-side component; parse STIX 2.1 bundles from MISP or commercial feeds; populate `known_bad_hashes` with `source='stix'` and `stix_id` back-reference; stix_id column already in schema

## Phase 4: UI

1. **Wails desktop UI** — separate binary, read-only SQLite; schema stable enough to start after Phase 1 complete
2. **Dashboard** — severity trends, agent health, recent detections
3. **Event explorer** — filterable tables per event type
4. **Autorun viewer** — persistence entries with hash and YARA match status
5. **User inventory view** — password age, last login, policy violations
6. **USB event log** — device history with vendor identification
7. **FIM view** — file change history for watched paths
8. **Evidence viewer** — render JSON evidence snapshot for HIGH/CRITICAL detections

## Phase 5: Response System

1. **File quarantine** — move/lock/restore; quarantined_files table already exists
2. **Process termination** — kill by PID via CLI or UI; audit logged
3. **Network isolation** — iptables/nftables block rules; reversible; audit logged
4. **Automated response rules** — configurable actions per severity threshold; audit mode prerequisite
5. **Audit mode vs prevention mode** — global toggle; audit default for safety

## Phase 6: Intelligence

1. **Sigma rule engine** — parse Sigma YAML; match against structured events; belongs server-side where cross-endpoint log sequences are available
2. **systemd journal integration** — real-time auth and service event parsing via journald socket; feeds Sigma engine; prerequisite for login/auth correlation
3. **MITRE ATT&CK mapping** — tag detections with technique IDs; compliance and analyst context
4. **Alert correlation into incidents** — group alerts by process tree, time window, shared indicators; requires process tree and behavioral correlation as prerequisites
5. **Behavioral correlation engine** — multi-event chain detection; download→exec→network, script→child→outbound; requires process tree and months of baseline data
6. **Compliance report generation** — `vajra report`; CIS Benchmark, PCI-DSS, SOC2 evidence

## Dropped or Deferred

- **Password rotation** — operationally dangerous, belongs in IAM tooling
- **Lynis-style hardening audit** — better as `vajra audit` subcommand after Phase 2
- **SSH brute force detection** — becomes a Sigma rule in Phase 6
- **On-demand malware sample fetch** — security risk; rule updates via remote push solve this safely
- **Full Windows support** — deferred until Linux feature set complete
- **macOS support** — not planned; requires Apple Developer account and Endpoint Security framework
- **ML/AI file scoring** — deferred until false negative rate on YARA+hash is measurable over real data
- **Dynamic library injection via uprobes** — high maintenance cost; file scanner already catches new .so files via file events
- **Correlation IDs on individual event tables** — process tree gives server recursive CTE traversal; server assigns correlation IDs when correlating events
- **Flatpak path awareness in LDPreloadAnalyzer** — deferred until a Flatpak false positive is observed in the wild
- **fanotify FAN_OPEN_EXEC** — observe-only exec monitoring to replace magic byte eligibility check; deferred; current three-condition eligibility (execute bit, magic bytes, interpreter trigger) is sufficient for now
- **fentry program type for finit_module** — bpf_d_path unavailable in tracepoints; module name enrichment requires fentry or userspace resolution; deferred
- **RevShellAnalyzer exec-time check** — removed; replaced by dup2/dup3 driven DupWatcher which catches both pre-exec and post-exec socket redirection
