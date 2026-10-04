# Vajra EDR — Roadmap

## Completed

- eBPF event collection — process, file, network, memory, namespace, module events
- eBPF dispatcher — typed channel fan-out from raw perf events
- Event sink — network, memory, security, module channels → DB with severity classification
- Memory event dedup — pid+prot keyed, 60s window, W^X always inserted
- YARA file scanner — eBPF-driven, magic-byte filtering, QuickHash (head+tail+mtime), TTL dedup, result cache, alert dedup
- YARA process scanner — two-pipeline split: content pipeline (cached, filter-aware) + runtime pipeline (always runs)
- Analyzer interface — Pipeline, RunUncached, MergeResults, ResultCache, PID context helpers
- YARAAnalyzer — wraps pool, short-circuits on CRITICAL
- LDPreloadAnalyzer — /proc/PID/environ, snap path awareness
- RevShellAnalyzer — stdio fd inspection against /proc/net/tcp*
- CapabilityAnalyzer — CapEff bitmask, fires on trusted processes too
- Alert deduplication — DedupTracker with configurable window, count increment on existing row
- Autotuning YARA worker pool — exponential moving average, load-average aware scaling
- QuickHash — head 8KB + tail 8KB + mtime, detects in-place binary replacement
- Autorun scanner — all Linux persistence categories (systemd, cron, shell profiles, PAM, LD_PRELOAD, XDG autostart, D-Bus, at jobs, anacron, SysV init)
- SQLite persistence — file, process, network, memory, security, autorun, quarantine, statistics, sync_state tables
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
- End-to-end validation on live Linux system — timestamps, machine_id, full cmdline all verified

## Phase 1: Detection System (remaining)

1. **Hash checker analyzer** [low] — `internal/analyzer/hash.go`; SHA256 lookup against `known_bad_hashes` table before YARA; table columns: sha256, family, source, tags (JSON), added_at, stix_id (null until STIX engine exists); short-circuits content pipeline on CRITICAL match; seeded from MalwareBazaar

2. **MalwareBazaar seed command** [low] — `vajra hashes update` cobra subcommand; downloads full CSV from `https://bazaar.abuse.ch/export/csv/full/`; bulk inserts with `source='malwarebazaar'`; daily refresh via tag-check same pattern as rule syncer

3. **Known-good hash registry** [low] — allowlist checked before known-bad; analyst-managed via CLI; `source='manual'`; hash checker skips YARA for known-good entries; separate from known-bad table

4. **Process tree table** [medium] — adjacency list in `process_tree` table;
   written on every execve event from PPID already in ProcessEvent;
   columns: pid, ppid, comm, exe_path, machine_id, event_time;
   query layer needs recursive CTE for tree traversal;
   this is a foundational data structure, not just a detection feature —
   prerequisites for: LOLBin chain detection (item 5), behavioral correlation
   (Phase 6), server-side attack chain reconstruction, alert correlation into
   incidents, evidence snapshots (item 12), and UEBA baselines;
   every process event already carries PPID so no new eBPF work is needed;
   the server receives a flat stream of events with machine_id and can
   reconstruct the full forest via recursive CTE on (machine_id, ppid, pid)

5. **LOLBin pattern matching** [low] — `internal/procanalyzer/lolbin.go`; pattern matching on full cmdline (now available); covers curl|bash pipes, python/perl/ruby -e inline, bash /dev/tcp, nc -e /bin/sh, base64 decode pipes, wget|sh; config-driven rule list; fires HIGH

6. **Running process scanner** [medium] — walk `/proc/PID/exe` on startup and periodic interval; submit each to YARA pool; catches malware running before agent started; dedup against RecentScanTracker

7. **Container tagging** [medium] — parse `/proc/PID/cgroup` on execve; extract container ID from Docker/k8s/podman path patterns; add `container_id TEXT` and `container_runtime TEXT` to process_scan_results; empty for host processes

8. **trace_id on process events** [low] — UUIDv7 per execve event stored on process_scan_result; child processes inherit parent trace_id via PPID lookup; enables server-side grouping without full tree traversal

9. **Pre-execution autorun YARA scan** [low] — submit ImagePath to YARA pool before inserting new autorun entry; attach matches to autorun record; requires YaraMatches field on AutorunEntry

10. **Crontab path exception in file scanner** [low] — add `/var/spool/cron/`, `/etc/cron.d/`, `/etc/crontab` to config bypass list; these are plain text and invisible to the magic byte check

11. **EventStatistic aggregation job** [low] — hourly ticker; upsert counts into event_statistics grouped by event_type and date; needed before dashboard is useful

12. **Evidence snapshot on HIGH/CRITICAL** [medium] — collect process tree, open FDs, loaded libraries, environ from /proc immediately on HIGH/CRITICAL detection; serialize to JSON blob; separate evidence table with reference to detection row; timing is critical as process state goes stale within seconds

13. **Secrets detection** [medium] — evaluate Betterleaks Go API; regex scanning for credentials, API keys, tokens; store location + category + context_hash only, never the secret value; own table `secret_findings`

14. **CLI scan command** [medium] — `vajra scan` cobra subcommand; blocking filesystem walk with progress output; feeds file and process scanners without daemon

## Phase 2: Hardening and Visibility

1. **File integrity monitoring** [medium] — fsnotify/inotify watcher on critical paths; `/etc/vajra/`, `/opt/vajra/`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` as defaults; CRITICAL alert with before/after hash and modifying PID; own table `fim_events`

2. **User inventory and password age** [low] — read `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`; flag users exceeding PASS_MAX_DAYS as MEDIUM; daily scan; own table `user_inventory`

3. **USB and peripheral monitoring** [medium] — udev netlink monitor via go-udev; capture connect/disconnect, vendor/product ID, device class, serial; USB mass storage → HIGH; HID → MEDIUM; own table `usb_events`

4. **Kernel integrity check** [medium] — compare /proc/modules vs /sys/module/; detect hidden modules; baseline on first run

5. **Binary changed after exec** [medium] — periodic SHA256 comparison of /proc/PID/exe against on-disk file for long-running processes; discrepancy = CRITICAL

6. **Coverage telemetry** [low] — periodic heartbeat to DB: uptime, tracepoint count, events processed, pool queue depth, worker count; agent health visibility

7. **Tamper protection** [medium] — watchdog goroutine for critical jobs; chattr +i on binary and config; alert on unexpected SIGKILL/SIGTERM

8. **Audit log of agent actions** [low] — immutable `agent_audit_log` table; every quarantine, kill, rule update, config change recorded

9. **VirusTotal enrichment** [medium] — optional, API key in config; SHA256 lookup on HIGH/CRITICAL detections only; rate-limited to free tier; results cached in `known_bad_hashes` with `source='virustotal'`

## Phase 3: Remote Sync

1. **Remote server REST API** [high] — separate service; receives telemetry, detections, heartbeats; pushes config and rule updates; authentication required

2. **Agent-to-server delta sync** [high] — ship rows with id > last_synced_id from sync_state table; compressed; retry on failure; acknowledge before updating watermark; purge job deletes shipped rows older than retention window

3. **Over-the-air agent updates** [high] — pull signed binary from server; verify signature; rollback on startup failure

4. **SIEM export** [medium] — structured JSON over syslog; Elasticsearch/Splunk/Loki direct HTTP; Fluentbit-compatible output format

5. **STIX/TAXII ingestion** [medium] — server-side component; parse STIX 2.1 bundles from MISP or commercial feeds; populate `known_bad_hashes` with `source='stix'` and `stix_id` back-reference; Sigma rule distribution via same channel; stix_id column already in schema

## Phase 4: UI

1. **Wails desktop UI** [medium] — separate binary, read-only SQLite; schema stable enough to start after Phase 1 complete
2. **Dashboard** [low] — severity trends, agent health, recent detections
3. **Event explorer** [low] — filterable tables per event type
4. **Autorun viewer** [low] — persistence entries with hash and YARA match status
5. **User inventory view** [low] — password age, last login, policy violations
6. **USB event log** [low] — device history with vendor identification
7. **FIM view** [low] — file change history for watched paths
8. **Evidence viewer** [medium] — render JSON evidence snapshot for HIGH/CRITICAL detections

## Phase 5: Response System

1. **File quarantine** [medium] — move/lock/restore; quarantined_files table already exists
2. **Process termination** [low] — kill by PID via CLI or UI; audit logged
3. **Network isolation** [medium] — iptables/nftables block rules; reversible; audit logged
4. **Automated response rules** [high] — configurable actions per severity threshold; audit mode prerequisite
5. **Audit mode vs prevention mode** [low] — global toggle; audit default for safety

## Phase 6: Intelligence

1. **Sigma rule engine** [high] — parse Sigma YAML; match against structured events; unlocks SSH brute force, auth anomalies, many others as rules not code; belongs server-side where cross-endpoint log sequences are available
2. **systemd journal integration** [medium] — real-time auth and service event parsing via journald socket; feeds Sigma engine; prerequisite for login/auth correlation
3. **MITRE ATT&CK mapping** [medium] — tag detections with technique IDs; compliance and analyst context
4. **Alert correlation into incidents** [high] — group alerts by process tree, time window, shared indicators; requires process tree and behavioral correlation as prerequisites
5. **Behavioral correlation engine** [high, long shot] — multi-event chain detection; download→exec→network, script→child→outbound; requires process tree and months of baseline data
6. **Compliance report generation** [medium] — `vajra report`; CIS Benchmark, PCI-DSS, SOC2 evidence

## Dropped or Deferred

**Password rotation** — operationally dangerous, belongs in IAM tooling.

**Lynis-style hardening audit** — better as `vajra audit` subcommand after Phase 2.

**SSH brute force detection** — becomes a Sigma rule in Phase 6. No value hardcoding before the rule engine exists.

**On-demand malware sample fetch** — security risk. Rule updates via remote push solve this safely.

**Full Windows support** — deferred until Linux feature set complete. ETW requires parallel implementation of similar scale.

**macOS support** — not planned. Requires Apple Developer account and Endpoint Security framework.

**ML/AI file scoring** — deferred until false negative rate on YARA+hash is measurable over real data.

**Dynamic library injection via uprobes** — high maintenance cost, uncertain detection gain given file scanner already catches new .so files via file events.

**Correlation IDs on individual event tables** — deferred. Process tree gives server recursive CTE traversal. trace_id on process_scan_results only is sufficient. Server assigns correlation IDs when it detects related events.

**Flatpak path awareness in LDPreloadAnalyzer** — /run/flatpak/ and ~/.local/share/flatpak/ not yet in standardLibPaths. Will produce false positives on Flatpak apps same as snap did before fix.
