# Vajra EDR — Roadmap

## Completed

- eBPF event collection — process, file, network, memory, namespace, module events
- eBPF dispatcher — typed channel fan-out from raw perf events
- YARA file scanner job — eBPF-driven, magic-byte filtering, TTL dedup, backpressure
- YARA process scanner job — /proc/PID/exe resolution, TTL dedup, backpressure
- Autotuning YARA worker pool with exponential moving average
- Autorun scanner — all Linux persistence categories (systemd, cron, shell profiles,
  PAM, LD_PRELOAD, XDG autostart, D-Bus, at jobs, anacron, SysV init)
- SQLite persistence via squirrel query layer (file, process, network, memory,
  security, autorun, quarantine, statistics tables)
- Severity classification shared across scanners
- DB retention cleanup job
- Deb packaging for amd64 and arm64
- End-to-end validation on live Linux system

## In Progress

- Event sink job — network, memory, security, module channels → DB
- Temporary channel drainers in place until sink job is complete

## Phase 1: Detection System (remaining)

*All items in this phase are low-to-medium cost unless noted.*

1. **Event sink job** [low] — consume network/memory/security/module channels → DB;
   no YARA, straight insert; unblocks drainers and gives real data to all five tables

2. **Analyzer interface** [low] — pluggable pipeline in internal/scanner/analyzer.go;
   replaces current inline YARA calls in filescanner and processscanner;
   prerequisite for hash checker, secrets scanner, and LOLBin detection;
   short-circuits on first CRITICAL result so YARA is skipped for known-bad hashes

3. **Hash checker analyzer** [low] — SHA256 lookup against known-malicious table
   before submitting to YARA; own SQLite table separate from main DB for fast lookup;
   seeded initially from MalwareBazaar bulk export

4. **LD_PRELOAD environ check** [low] — on every execve event read /proc/PID/environ
   in Go consumer; check for LD_PRELOAD or LD_LIBRARY_PATH pointing outside standard
   library paths; alert as HIGH; no new eBPF needed, PID already in ProcessEvent;
   closes gap where autorun scanner only checks /etc/ld.so.preload not runtime injection

5. **Reverse shell detection** [low] — on execve events check /proc/PID/fd/0,1,2;
   if stdin/stdout/stderr inodes match an entry in /proc/net/tcp or /proc/net/tcp6
   the process has a network socket as its terminal which is a reverse shell pattern;
   alert as CRITICAL; no new eBPF needed

6. **Alert deduplication at job level** [low] — before inserting any detection record
   check if the same rule+path+severity combination fired in the last N minutes;
   configurable window in config.yaml; store deduplicated count on the record rather
   than N identical rows; prevents analyst alert fatigue from high-churn detections

7. **Evidence snapshot on HIGH/CRITICAL** [medium] — when severity is HIGH or CRITICAL
   automatically collect: full process tree from /proc, open file descriptors from
   /proc/PID/fd, network connections from /proc/net/tcp*, loaded libraries from
   /proc/PID/maps, environment variables from /proc/PID/environ; serialize to JSON
   and store as blob attached to detection record; must be collected immediately as
   process state goes stale within seconds; own column on file_scan_results and
   process_scan_results or separate evidence table

8. **LOLBin pattern matching** [low] — detection rules on args field already captured
   in ProcessEvent; pattern list covers: curl|bash pipe chains, python -c / perl -e /
   ruby -e inline execution, bash /dev/tcp reverse shells, nc -e /bin/sh,
   base64 decode pipes, wget -O- | sh; stored as config-driven rule list not hardcoded;
   fires as HIGH; no new eBPF or architecture needed

9. **Crontab path exception in file scanner** [low] — add /var/spool/cron/,
   /etc/cron.d/, /etc/crontab to a config list of paths that bypass the magic byte
   check and go straight to the secrets + LOLBin analyzers; crontab files are plain
   text and currently invisible to the file scanner; closes the window between
   periodic autorun scans

10. **Running process scanner** [medium] — walk /proc/PID/exe on startup and on
    configurable periodic interval; submit each to YARA pool; catches malware that
    was already running before agent started; dedup against RecentScanTracker so
    long-running clean processes are not rescanned every cycle

11. **Pre-execution autorun scan** [low] — after Diff() finds new autorun entry
    submit ImagePath to YARA pool before inserting; attach matches to autorun record;
    requires YaraMatches field on AutorunEntry and column migration

12. **Capability abuse detection** [low] — on execve events read /proc/PID/status
    in Go consumer; parse CapEff field; flag processes with CAP_SYS_ADMIN,
    CAP_SYS_PTRACE, CAP_NET_RAW, CAP_DAC_OVERRIDE that are not in a configured
    allowlist; alert as HIGH; no new eBPF needed

13. **Process tree tracking** [medium] — build parent-child lineage from PPID fields
    already in ProcessEvent; store as adjacency list in process_tree table;
    prerequisite for behavioral correlation and LOLBin chain detection;
    query layer needs recursive CTE support for tree traversal

14. **Known-good hash registry** [low] — allowlist of approved SHA256 values;
    checked before YARA in the Analyzer pipeline; analyst-managed via CLI or UI;
    hash checker skips known-good entries entirely; separate from known-bad table

15. **EventStatistic aggregation job** [low] — hourly ticker; upsert counts into
    event_statistics table grouped by event_type and date; needed before UI dashboard
    is useful; already have the table, just need the writer

16. **Secrets detection** [medium] — Betterleaks or TruffleHog-style regex scanning;
    store location + category + context_hash only, never the secret value;
    own DB table (secret_findings); second eligibility filter for text files alongside
    existing magic byte filter; primary trigger is CLI scan command, eBPF catches
    new secrets written to disk in real-time; evaluate whether Betterleaks exposes
    Go API or requires subprocess — subprocess adds latency on hot path

17. **CLI scan command** [medium] — `vajra scan` cobra subcommand; blocking full
    filesystem walk with live progress output; feeds file and process scanners;
    primary trigger for secrets detection and initial baseline; runs without daemon

18. **ProcessScanResult.FileHash field** [low] — currently stored in Notes field;
    add proper column to process_scan_results table and update query layer;
    schema migration required

## Phase 2: Hardening and Visibility

*Medium cost across the board unless noted.*

1. **File integrity monitoring** [medium] — fsnotify-based watcher on configurable
   critical paths; Vajra's own paths watched by default (/etc/vajra/, /opt/vajra/,
   /usr/bin/vajra); /etc/passwd, /etc/shadow, /etc/sudoers added as defaults;
   any modification fires CRITICAL alert with before/after hash and modifying PID;
   own table (fim_events); uses inotify not eBPF — targeted path watching is
   exactly inotify's strength and avoids eBPF volume

2. **User inventory and password age** [low] — read /etc/passwd for user list,
   /etc/shadow for last password change (field 3, days since epoch), /etc/login.defs
   for PASS_MAX_DAYS; display only, no rotation; daily scan; flag users exceeding
   policy age as MEDIUM; own table (user_inventory); requires root to read /etc/shadow

3. **USB and peripheral monitoring** [medium] — udev netlink monitor via
   github.com/pilebones/go-udev; not eBPF — USB events come from udev subsystem
   not syscalls; capture connect/disconnect, vendor ID, product ID, device class,
   serial number; USB mass storage → HIGH automatically (exfiltration/malware vector);
   HID devices → MEDIUM (BadUSB risk); own table (usb_events); separate goroutine
   alongside eBPF listener

4. **Kernel integrity check** [medium] — periodic comparison of /proc/modules vs
   /sys/module/ directory to detect hidden modules; compare syscall table addresses
   against known-good baseline; catches rootkits that loaded before agent started
   or that hide from module listings; requires establishing baseline on first run

5. **Binary changed after exec** [medium] — for long-running processes (uptime > N
   minutes) periodically compare SHA256 of /proc/PID/exe against on-disk file;
   discrepancy means binary was replaced while running — strong compromise indicator;
   alert as CRITICAL; configurable check interval and minimum process age

6. **Coverage telemetry** [low] — periodic heartbeat write to DB: timestamp, uptime,
   tracepoint count, events processed in last interval, YARA pool queue depth, worker
   count; Wails UI shows agent health panel; also detects if agent is being starved
   by resource pressure

7. **Tamper protection** [medium] — FIM (item 1 above) covers config and binary files;
   additionally: watchdog goroutine restarts critical jobs if they exit unexpectedly;
   chattr +i on binary and config where filesystem supports it; alert if own PID
   receives SIGKILL or SIGTERM from an unexpected parent

8. **Audit log of agent actions** [low] — every action the agent takes (quarantine,
   process kill, rule update, config change) written to own immutable table
   (agent_audit_log) with timestamp, action, target, and initiator; compliance
   requirement; separate from detection events

## Phase 3: Threat Intelligence

*Medium cost. Requires external service accounts for some items.*

1. **MalwareBazaar hash feed** [medium] — local offline SQLite lookup table separate
   from main DB; hourly sync of bulk hash export; HashAnalyzer checks this before
   YARA; significant detection coverage improvement for known malware families

2. **VirusTotal integration** [medium] — optional, requires API key in config;
   submit unknown hashes for lookup on HIGH/CRITICAL detections only; rate-limited
   to free tier by default; results cached locally; adds context to detections
   without being on the hot path

3. **Threat intel IP/domain feed** [medium] — cross-reference network events against
   known-bad indicators from MISP or plain IOC lists; STIX/TAXII ingestion or simple
   CSV feed; stored in local lookup table; network event sink checks on insert

4. **Detection tuning feedback loop** [medium] — analyst marks detections as true
   positive, false positive, or expected behavior via UI or CLI; feeds back into
   known-good registry and per-rule suppression; requires UI to be useful;
   without this alert fatigue compounds over time

## Phase 4: UI

*Medium cost. Wails is Go-native so most complexity is in the query layer.*

1. **Wails desktop UI** [medium] — separate binary, read-only SQLite via
   OpenReadOnly(); no shared in-process state with agent; schema is stable
   enough to start after Phase 1 is complete

2. **Dashboard** [low once UI exists] — severity trends from event_statistics,
   agent health from telemetry heartbeat, recent detections summary

3. **Event explorer** [low once UI exists] — filterable tables per event type
   with sort, search, and status update (acknowledge, resolve)

4. **Autorun viewer** [low once UI exists] — active persistence entries with
   hash, category, first/last seen, YARA match status

5. **User inventory view** [low once UI exists] — password age, last login,
   shell, home directory, flag for policy violation

6. **USB event log** [low once UI exists] — device history with vendor/product
   identification, connect/disconnect timeline

7. **FIM view** [low once UI exists] — file change history for watched paths,
   before/after hash, modifying process

8. **Evidence viewer** [medium] — render the JSON evidence snapshot attached to
   HIGH/CRITICAL detections; show process tree, open FDs, network connections,
   loaded libraries in structured panels

## Phase 5: Response System

*Medium-to-high cost. Automated actions carry operational risk.*

1. **File quarantine** [medium] — move, lock, restore workflow; schema already
   exists in quarantined_files table; needs file move + permission lock + restore
   path with analyst confirmation

2. **Process termination** [low] — kill by PID on analyst request via CLI or UI;
   log to agent_audit_log; confirmation required

3. **Network isolation** [medium] — iptables/nftables block rules on analyst
   request; configurable as block-by-IP or full isolation; reversible; log to
   agent_audit_log

4. **Automated response rules** [high] — configurable actions per severity
   threshold and event type; e.g. auto-quarantine on CRITICAL file detection;
   requires careful testing to avoid availability impact; audit mode prerequisite

5. **Audit mode vs prevention mode** [low] — global config toggle; audit logs
   everything and takes no automated action; prevention enables automated responses;
   default is audit mode for safety

## Phase 6: Remote Sync

*High cost. Requires server component.*

1. **Remote server REST API** [high] — separate service; receives agent telemetry,
   detections, and heartbeats; pushes config and rule updates; authentication required

2. **Agent-to-server delta sync** [high] — send only rows with ID greater than
   last sync checkpoint; compressed; retry on failure; sync status stored locally

3. **Over-the-air agent updates** [high] — pull signed binary from server; verify
   signature before replacing; rollback on startup failure

4. **SIEM export** [medium] — syslog forwarding or direct HTTP export to
   Elasticsearch/Splunk/Loki; security teams rarely use agent-native UIs for
   investigation; without export Vajra is an island in a multi-tool environment;
   structured JSON over syslog is the lowest common denominator

## Phase 7: Log Monitoring

*Medium-to-high cost. Sigma engine is the major investment.*

1. **Sigma rule engine** [high] — parse Sigma YAML rule format; match against
   structured log events; this is the major investment that unlocks SSH brute
   force detection, auth anomalies, and many other detections as rules rather
   than hardcoded logic; long shot to implement well but high value if done right

2. **systemd journal integration** [medium] — real-time auth and service event
   parsing via journald socket; feeds Sigma engine

3. **MITRE ATT&CK mapping** [medium] — tag detections with technique IDs where
   mappable; improves analyst context and compliance reporting; data enrichment
   on existing detections, not new detection logic

4. **Alert correlation into incidents** [high] — group related alerts into a
   single incident by process tree, time window, and shared indicators; without
   this analysts see noise not attack chains; requires process tree (Phase 1)
   and behavioral correlation (Phase 8) as prerequisites; long shot before
   those foundations exist

5. **Compliance report generation** [medium] — `vajra report` cobra subcommand;
   CIS Benchmark checks, PCI-DSS control mappings, SOC2 evidence; queries DB
   and produces structured output; useful only after Phase 1 and 2 data is
   stable and populated

## Phase 8: Intelligence and Scale

*High cost across the board. Long shots unless project reaches maturity.*

1. **Behavioral correlation engine** [high, long shot] — multi-event chain
   detection using process tree; classic patterns: download → exec → network,
   script interpreter → child process → outbound connection, chmod +x → exec;
   requires process tree (Phase 1) and months of baseline data; significant
   detection logic investment

2. **UEBA baselines** [high, long shot] — per-user and per-process behavioral
   profiles; alert on deviation from baseline; requires weeks of data collection
   before useful; ML or statistical modeling needed for practical accuracy;
   significant false positive tuning required

3. **Data exfiltration detection** [high, long shot] — volume and destination
   anomaly on network events; requires UEBA baselines as strict prerequisite;
   cannot build this before baselines exist

4. **Container awareness** [medium] — tag all events with container ID and image
   name via cgroup namespace data already partially captured in namespace events;
   less of a long shot than the above items, more a matter of parsing cgroup paths

5. **Secrets detection in archives** [high, long shot] — extend secrets scanner
   to compressed archives and git objects; significant complexity in archive
   traversal and git object parsing; diminishing returns vs flat file scanning
   for most environments

## Dropped or Deferred with Rationale

**Password rotation** — display age only, never rotate remotely. Remote rotation
is operationally dangerous and belongs in IAM tooling not an EDR.

**Lynis-style hardening audit** — better as `vajra audit` cobra subcommand than
a running job. Add after Phase 2 hardening visibility is complete. Low cost once
the data collection infrastructure exists.

**SSH brute force detection** — becomes a Sigma rule once Phase 7 log monitoring
exists. No value in hardcoding it before the rule engine exists.

**On-demand malware sample fetch** — dropped. Fetching malware to an endpoint is
a security risk. Rule updates via remote config push solve the same problem safely.

**Full Windows support** — deferred until Linux feature set is complete. ETW is
architecturally unrelated to eBPF. Requires parallel implementation effort of
similar scale to the entire Linux codebase.

**macOS support** — not planned. Requires Apple Developer account and notarization
for Endpoint Security framework access. Out of scope.

**ML/AI file scoring** — deferred. Add after false negative rate on YARA plus
hash lookup is measurable over real data. Optimizing before that baseline exists
is premature.

**Remote firewall management as standalone feature** — absorbed into Phase 5
Response System as local action triggered by detections.

**Dynamic library injection via uprobes** — long shot. Uprobes require attaching
to specific userspace function addresses which vary by binary version and are not
stable interfaces. High maintenance cost for uncertain detection gain given we
already catch new .so files via the file scanner.
