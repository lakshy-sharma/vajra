# Vajra EDR — Roadmap

## Completed

- eBPF event collection — process, file, network, memory, namespace, module, dup2/dup3 events
- eBPF dispatcher — typed channel fan-out from raw perf events
- Event sink — network, memory, security, module → raw telemetry tables with heuristic severity
- Memory event dedup — pid+prot keyed, 30s window, W^X always inserted
- YARA file scanner — eBPF-driven, three-condition eligibility (execute bit, magic bytes, interpreter trigger)
- YARA process scanner — two-pipeline split: content (cached, filter-aware) + runtime (always runs)
- Analyzer interface — Pipeline, RunUncached, MergeResults, ResultCache, PID + SHA256 context helpers
- YARAAnalyzer, LDPreloadAnalyzer, CapabilityAnalyzer
- HashAnalyzer — Bloom filter loaded from MalwareBazaar dataset; short-circuits content pipeline on CRITICAL; gracefully disabled when filter absent
- MalwareBazaar integration — HashSyncer job; downloads full CSV, builds Bloom filter; `vajra hashes update/status` CLI
- DupWatcher — dup2/dup3 driven reverse shell detection; pid+inode dedup 30s window
- Unified detection schema — detections + detection_artifacts + detection_network + detection_secrets + detection_extensions + evidence_snapshots
- FindingWriter — single insertion point for all detection output; dedup, schema routing, evidence capture
- Process tree — adjacency list on every execve, never pruned, composite index for recursive CTE
- Autorun scanner — all 12 Linux persistence categories, diffs against DB state
- Secrets scanner — betterleaks v2 SDK; prefilter with configurable path segment exclusions and browser cache toggle; fingerprint-based ignore list; `vajra secrets ignore/export-ignore` CLI
- Audit log table — append-only component lifecycle and health events
- DB retention cleanup job
- Rule syncer — GitHub API tag check, download, zip verify, 7-generation archive rotation
- Deb packaging — amd64 and arm64
- CLI — vajra scan [dir], vajra rules update/status, vajra hashes update/status, vajra secrets ignore/export-ignore
- Framework refactor — watcher/scanner/job/analyzer layer separation; utilities package with generic dedup, filter, hasher, severity; scanner/yara package
- RuleMatch interface — engine-agnostic severity classification
- Evidence snapshot — /proc state captured on HIGH/CRITICAL
- sendmsg DNS fix — bpf_probe_read_user for msg_name

## Phase 1: Detection (remaining)

1. **LOLBin analyzer** — `internal/analyzer/lolbin.go`; cmdline pattern matching; shallow parent lookup via `ProcessTreeQueries.GetByPID`; config-driven rule list; fires HIGH

2. **Running process scanner** — `internal/detect/procwalk.go`; walk `/proc/PID/exe` on startup; submit to content pipeline via FindingWriter; dedup against RecentScanTracker

3. **Container tagging** — parse `/proc/PID/cgroup` on execve; `container_id TEXT` and `container_runtime TEXT` on detections; empty for host processes

4. **EventStatistic aggregation job** — hourly ticker; upsert into event_statistics grouped by source and date; needed before dashboard is useful

5. **User profile scanner** — `internal/detect/userprofile.go`; reads passwd/shadow/sudoers/ssh keys/groups/login history; diffs against user_inventory; flags policy violations

## Phase 2: Hardening and Visibility

1. **File integrity monitoring** — fsnotify on critical paths; CRITICAL alert with before/after hash and modifying PID; fim_events table
2. **USB monitoring** — udev netlink; vendor/product/class/serial; USB mass storage → HIGH; usb_events table
3. **Kernel integrity check** — /proc/modules vs /sys/module; detect hidden modules; baseline on first run
4. **Binary changed after exec** — periodic SHA256 comparison of /proc/PID/exe for long-running processes; discrepancy = CRITICAL
5. **Coverage telemetry** — 15-minute health ticker; pool workers, queue depth, events processed, uptime to audit_log
6. **Tamper protection** — watchdog goroutine; chattr +i on binary and config
7. **VirusTotal enrichment** — optional API key; SHA256 lookup on HIGH/CRITICAL; cached in known_bad_hashes

## Phase 3: Remote Sync

1. **Remote server REST API** — receives telemetry, detections, heartbeats; pushes config and rule updates
2. **Agent-to-server delta sync** — sync_state watermarks; compressed; retry; purge after shipping
3. **Hash feed server-side** — server aggregates MalwareBazaar and licensed feeds; pushes Bloom filter to agents; replaces direct abuse.ch dependency
4. **Over-the-air agent updates** — signed binary; rollback on failure
5. **SIEM export** — JSON over syslog; Elasticsearch/Splunk/Loki direct HTTP
6. **STIX/TAXII ingestion** — server-side; populate known_bad_hashes; stix_id column already in schema

## Phase 4: UI

1. **Wails desktop UI** — separate binary, read-only SQLite
2. **Dashboard** — severity trends from event_statistics, agent health from audit_log
3. **Alert list** — detections table, all sources unified
4. **Alert detail** — JOIN detection_artifacts, detection_network, evidence_snapshots
5. **Process tree view** — recursive CTE on process_tree
6. **Autorun viewer**, **User profile view**, **FIM view**, **Evidence viewer**
7. **Secrets ignore workflow** — mark findings as noise in UI, export ignore list with one click

## Phase 5: Response System

1. **File quarantine** — move/lock/restore; quarantined_files table exists
2. **Process termination** — kill by PID; audit logged
3. **Network isolation** — iptables/nftables; reversible; audit logged
4. **Automated response rules** — per severity threshold; audit mode prerequisite
5. **Audit mode vs prevention mode** — global toggle; audit default

## Phase 6: Intelligence

1. **Sigma rule engine** — server-side; cross-endpoint log sequences
2. **systemd journal integration** — journald socket; feeds Sigma; prerequisite for auth correlation
3. **MITRE ATT&CK mapping** — technique IDs on detections
4. **Alert correlation into incidents** — process tree + time window + shared indicators
5. **Behavioral correlation** — download→exec→network chains; requires months of baseline
6. **Compliance report generation** — `vajra report`; CIS Benchmark, PCI-DSS, SOC2

## Dropped or Deferred

- **Password rotation enforcement** — operationally dangerous; belongs in IAM
- **fanotify FAN_OPEN_EXEC** — deferred; three-condition eligibility sufficient for now
- **fentry for finit_module** — bpf_d_path unavailable in tracepoints; deferred
- **Full Windows / macOS support** — deferred until Linux feature set complete
- **ML/AI file scoring** — deferred until YARA+hash false negative rate is measurable
- **SSH brute force** — becomes a Sigma rule in Phase 6
- **known_bad_hashes SQLite table** — replaced by Bloom filter; SQLite lookup too slow for pipeline hot path
