# Vajra EDR — TODO

Priority order within each phase reflects dependency and detection value.

---

## Phase 1 — Detection (Immediate)

### 1. LOLBin Analyzer — `internal/analyzer/lolbin.go`

Config-driven set of living-off-the-land binaries (`AlertPolicy.LOLBins`). On a process event, check if `comm` or `exe_path` basename matches the list. Do a shallow parent lookup via `ProcessTreeQueries.GetByPID` to check whether the parent is a known interpreter or another LOLBin. Fires HIGH. No false positives on bare invocation — only flag when the parent chain is suspicious.

### 2. Container Tagging

On every execve, read `/proc/PID/cgroup` and parse the container ID and runtime (docker, containerd, podman, lxc). Add `container_id TEXT` and `container_runtime TEXT` columns to `detections` and `process_tree`. Empty string for host processes. Required for the Phase 3 server to distinguish host detections from container detections.

### 3. EventStatistic Aggregation Job — `internal/job/statsync.go`

Already wired in service.go. The `StatisticsQueries.Aggregate` method needs to perform the actual upsert: group raw telemetry and detection rows by source and date (Unix epoch day start UTC), write into `event_statistics`. Without this the dashboard is empty.

### 4. User Profile Scanner — `internal/detect/userprofile.go`

Pull-based scanner. Reads `/etc/passwd`, `/etc/shadow` (root only), `/etc/sudoers` and `/etc/sudoers.d/*`, `/etc/group`, `~/.ssh/authorized_keys` for all users. Diffs against a `user_inventory` table (first run: baseline; subsequent runs: alert on changes). Flags: new sudo grants, new SSH keys, UID 0 accounts that aren't root, accounts with no password lock. Medium by default, High for UID 0 changes.

---

## Phase 2 — Hardening and Visibility

### 5. File Integrity Monitoring — `internal/detect/fim.go`

Watch critical paths (`/etc/passwd`, `/etc/shadow`, `/etc/crontab`, `/bin`, `/usr/bin`, `/sbin`, etc.) via fsnotify. On modification: capture before/after SHA256 and the PID from the process_tree. Alert CRITICAL. Schema: `fim_events(id, path, old_hash, new_hash, modified_by_pid, event_time)`.

### 6. USB Monitoring — `internal/detect/usb.go`

Subscribe to udev netlink events. Capture vendor ID, product ID, device class, serial number. USB mass storage class → HIGH. Schema: `usb_events(id, vendor_id, product_id, device_class, serial, action, event_time)`. Read-only media classes (HID, audio) → LOW.

### 7. Binary Changed After Exec

Periodic SHA256 comparison of `/proc/PID/exe` for long-running processes against their baseline hash stored at execve time in `process_tree`. Discrepancy = CRITICAL. Catches in-memory patching and binary replacement attacks. Add a ticker to the process scanner or a dedicated `internal/detect/binarywatch.go`.

### 8. Coverage Telemetry

15-minute health ticker writing to `audit_log`: YARA pool worker count, queue depth, events processed since last tick, dedup rate, FindingWriter metrics (written, deduped, errors), uptime. Enables the server-side health dashboard in Phase 3.

### 9. Tamper Protection

Watchdog goroutine that monitors its own binary path (`/proc/self/exe`) and config path for changes. `chattr +i` on the daemon binary and `/etc/vajra/config.yaml` after startup (requires root). Alert CRITICAL if either is removed or changed while the daemon is running.

### 10. Pool Shrink

`autotune` in `internal/scanner/yara/pool.go` logs "shrink pending" but cannot act — workers are started as goroutines with no individual cancel. Fix: give each worker a cancel function stored in a slice on Pool; shrink removes the last one.

---

## Phase 3 — Remote Sync

### 11. Remote Server REST API

Receive telemetry, detections, and heartbeats from agents. Push config and rule updates. JWT auth. TLS only. Endpoints: `POST /telemetry`, `POST /detections`, `POST /heartbeat`, `GET /config`, `GET /rules/latest`.

### 12. Agent-to-Server Delta Sync

Watermark table (`sync_state`) tracks last synced row ID per table. Sync job compresses and ships rows above the watermark. Retry with exponential backoff. Purge local rows after server ACKs receipt (respecting local retention policy).

### 13. Bloom Filter Server Push

Server aggregates MalwareBazaar and licensed hash feeds, builds a Bloom filter, and pushes it to agents on update. Replaces the direct `abuse.ch` dependency. Agent no longer needs an API key. `HashSyncer` becomes a receiver rather than a downloader.

### 14. Over-the-Air Agent Updates

Server signs binary with Ed25519. Agent verifies signature before replacing itself. Rolls back if the new binary exits within 60 seconds of start. Audit logged.

### 15. SIEM Export

JSON over syslog-compatible TCP/UDP to Elasticsearch, Splunk, or Loki. Configurable format. Fires on every FindingWriter write above a configurable severity threshold.

---

## Phase 4 — UI

The Wails desktop UI binary is separate from the daemon. All queries are read-only against the SQLite WAL.

### 16. Alert Detail View

JOIN `detections` with `detection_artifacts`, `detection_network`, `detection_secrets`, `evidence_snapshots`. Show YARA match strings with hex snapshots, network socket details, and the captured `/proc` state side by side.

### 17. Process Tree View

Recursive CTE on `process_tree` with PID as root. Render as an expandable tree. Highlight PIDs that appear in `detections`.

### 18. Secrets Ignore Workflow

In the Secrets detection detail view, a single "Mark as noise" button calls `GetConfig` → `vajra secrets ignore <id>` → refreshes the list. An "Export ignore list" button triggers `vajra secrets export-ignore`. Removes the need for CLI access for operators.

### 19. Evidence Viewer

Expand an evidence snapshot inline: tabbed view of open file descriptors, memory maps, environment variables, and process status. Hex-decode any SnapshotHex YARA string matches inline.

### 20. Live Reload for Secrets Ignore List

Pass the ignore list file path to a `fsnotify` watcher in the daemon. On change, rebuild the betterleaks scanner with the new fingerprints. Currently requires restart.

---

## Phase 5 — Response System

### 21. File Quarantine

Move detected file to a quarantine directory. Lock with `chattr +i`. Record in `quarantined_files(id, original_path, quarantine_path, sha256, detection_id, quarantined_at)`. `vajra quarantine restore <id>` reverses.

### 22. Process Termination

`kill(pid, SIGKILL)` on operator command. Audit logged. Never automatic — requires explicit operator action or a configured response rule.

### 23. Network Isolation

Drop all outbound traffic except to the server via a temporary nftables/iptables ruleset. Reversible. Audit logged. Prerequisite: enforcement mode.

### 24. Automated Response Rules

Per-severity threshold: `severity >= CRITICAL AND source == 'dup_watcher'` → isolate network. Audit mode is the prerequisite — never enforce without first verifying detection quality over a baseline period.

---

## Phase 6 — Intelligence

### 25. Sigma Rule Engine

Server-side. Consume the telemetry stream from all agents. Evaluate Sigma rules against correlated log sequences. Emit incidents back to agents via the sync channel.

### 26. MITRE ATT&CK Mapping

Populate `detections.mitre_technique` column from a config-driven map of `rule_id → technique_id`. Initial mappings: T1059 (interpreters), T1548 (capability abuse), T1105 (ingress tool transfer via DupWatcher), T1053 (cron autoruns).

### 27. Alert Correlation into Incidents

Group detections sharing a process tree subtree, a time window, or a common indicator (same SHA256 or network address) into an incident. Schema: `incidents(id, first_seen, last_seen, severity, detection_ids JSON)`.

---

## Known Issues (deferred from code review)

- **F1** — `Finding` flat struct with three mutually exclusive payload fields. Should be `ArtifactDetail`, `NetworkDetail`, `SecretDetail` sub-structs. Deferred: high disruption, zero compile risk in current form.
- **F5** — Detection + sub-table writes not in a single transaction. `TODO(F5)` comment in `writer.go`. Deferred until query interface is confirmed stable.
- **Pool shrink** — autotune logs intent but per-worker cancel not implemented. Tracked above as item 10.
- **Module name always empty** — `bpf_d_path` unavailable in tracepoint programs. Requires fentry migration.
- **Bloom filter not reloaded on daemon update** — requires signal-based or fsnotify reload. Deferred to Phase 3.
- **Boot epoch drift** — NTP clock steps after startup skew `EBPFTimestampToUnix`. Rare; defer.
- **Hash.go A10** — `strings.ToLower` per bloom check. Now lowercased at insert time in `hashsync.go`. Remove the `ToLower` call in `hash.go.Analyze` once hashsync is confirmed to have been regenerating the filter.
