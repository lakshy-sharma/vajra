# Vajra EDR — Architecture and Context Document

# Updated: October 2026

## Repository Layout

workspace/src/
internal/
analyzer/
analyzer.go # Analyzer interface, Pipeline, ResultCache, MergeResults, PID context helpers
yara.go # YARAAnalyzer — wraps pool, blocks until result
ebpf/
c/ebpf_events.c # BPF C program — kernel side
types.go # Event structs, Channels, CStringToGo, EventTypeName
listener.go # BPF load, tracepoint attach, perf read loop
dispatcher.go # RawEvent → typed channels, SecurityEvent translation
db/
db.go # Open, OpenReadOnly, migrate, pragmas
queries/
autoruns.go # Insert, MarkInactive, UpdateLastSeen, LoadActive
cleanup.go # RunCleanup — calls all table DeleteBefore methods
files.go # Insert (populates r.ID), IncrementDedupCount, ListBySeverity
memory.go # Insert, ListByPID, DeleteBefore
network.go # Insert, ListByDstPort, DeleteLowSeverityBefore
processes.go # Insert (populates r.ID), IncrementDedupCount, ListBySeverity
security.go # Insert, UpdateStatus, ListCritical
jobs/
autoruns/
autoruns.go # Scanner, Diff, RunAutorunScan goroutine entry
sources_linux.go # All 12 Linux persistence sources
cleanup.go # RunDBCleanup goroutine entry
eventsink.go # Network/Memory/Security/Module → DB; memory dedup pid+prot 60s window
filescanner.go # filter→eligible→QuickHash→SHA256→pipeline→dedup→insert
processscanner.go # resolve→dedup→runtime pipeline→content pipeline→merge→dedup→insert
rulesync.go # GitHub API tag check→download→zip verify→archive→atomic replace→restart
procanalyzer/
ldpreload.go # /proc/PID/environ; standard + snap + snapd paths
revshell.go # /proc/PID/fd/0,1,2 vs /proc/net/tcp and tcp6
capability.go # /proc/PID/status CapEff bitmask; always runs regardless of ProcessFilter
scanner/
dedup.go # DedupTracker — rule+path+severity key, window-based, RecordInsert
filter.go # ExclusionFilter, ProcessFilter, RecentScanTracker
hasher.go # QuickHash (head+tail+mtime), FullSHA256, HashFile, StatFile
pool.go # Pool, autotune with /proc/loadavg four-zone scaling, Submit/Enqueue
severity.go # ClassifyYARASeverity — APT/MALWARE/MAL/Ransomware → CRITICAL; HKTL/Exploit/EXPL → HIGH; SUSP → MEDIUM
yara.go # RulesCompiler — ExtractRules, CompileRules
utilities/
  clock.go          # SystemInfo, LoadSystemInfo, EBPFTimestampToUnix
  config.go         # Config struct with RulesSettings, LoadConfig, applyDefaults  
  logging.go        # GetLogger, lumberjack rolling file

entrypoint.go # Config load, directory setup, LoadSystemInfo, mode dispatch
service.go # startServiceMode, wireJobs, wirePipelines
shared/models/
models.go # All DB model structs — MachineID, DedupCount, FileHash on all relevant structs
cmd/
root.go # Cobra root, --config flag
rules.go # vajra rules update / vajra rules status

## Schema Summary

All five event tables (`file_scan_results`, `process_scan_results`, `network_events`, `memory_events`, `security_events`) have:

- `machine_id TEXT NOT NULL DEFAULT ''` — endpoint identity from /etc/machine-id
- `event_time INTEGER NOT NULL` — wall clock Unix time converted from eBPF boot-relative timestamp

`file_scan_results` and `process_scan_results` additionally have:

- `dedup_count INTEGER NOT NULL DEFAULT 0` — incremented on duplicate detections within window

`process_scan_results` additionally has:

- `file_hash TEXT` — SHA256 of scanned binary, populated on non-clean results only

`sync_state` table exists for future remote sync watermarking:

- `table_name TEXT PRIMARY KEY`, `last_synced_id INTEGER`, `last_synced_at INTEGER`, `synced_rows INTEGER`

`process_tree` table (to be written next session):

- pid, ppid, comm, exe_path — from ProcessEvent fields already captured
- machine_id — for multi-endpoint server queries
- event_time — kernel wall clock time of execve
- Queried via recursive CTE: WITH RECURSIVE tree AS (SELECT *FROM process_tree WHERE pid=? UNION ALL SELECT p.* FROM process_tree p JOIN tree t ON p.ppid=t.pid)
- Prerequisite for: LOLBin chain detection, behavioral correlation, evidence snapshots, server-side attack reconstruction

`known_bad_hashes` table (to be written next session):

- sha256 TEXT PRIMARY KEY
- family TEXT — malware family name from feed
- source TEXT NOT NULL — 'malwarebazaar', 'virustotal', 'stix', 'manual'
- tags TEXT — JSON array of tags from feed
- added_at INTEGER NOT NULL
- stix_id TEXT — null until STIX engine exists; back-reference for when STIX bundles populate this table

## Key Design Decisions

### SystemInfo — single source of truth

`utilities.LoadSystemInfo()` reads `/etc/machine-id` and computes boot epoch from `/proc/uptime` once at startup. Both `EventSink` and `ProcessScanner` and `FileScanner` receive it as a dependency. `EBPFTimestampToUnix(nsec uint64) int64` converts `bpf_ktime_get_ns()` values to wall clock seconds. No component computes its own boot epoch independently.

### Two-pipeline process scanner

Content pipeline (YARA + future HashAnalyzer) is cached via ResultCache keyed on SHA256 and filter-aware — trusted processes skip it entirely. Runtime pipeline (LDPreload, RevShell, Capability) is never cached and always runs regardless of ProcessFilter. Rationale: a trusted process name exhibiting reverse shell behaviour is more suspicious than an unknown one. `MergeResults()` takes the higher severity across both pipelines and clears `Skip` if the runtime pipeline found anything.

### DedupTracker

Keyed on `rule+path+severity`. `CheckAndRecord()` returns `shouldInsert bool` and `*DedupEntry`. First occurrence: insert to DB, call `RecordInsert(key, record.ID)` to store the row ID. Subsequent occurrences within window: call `IncrementDedupCount(entry.RecordID)` instead of inserting. Severity escalation on the same path always generates a new row since the key changes. Clean results bypass dedup entirely.

`Insert()` on FileQueries and ProcessQueries populates `r.ID` via `LastInsertId()` — this is required for `RecordInsert` to work correctly.

### ResultCache

Keyed on SHA256, no TTL. YARA results are deterministic for a given binary content. Cache cleared on agent restart which coincides with rule recompile at startup. When HashAnalyzer is added it will also consult this cache — a known-bad hash match short-circuits YARA entirely.

### Event sink — no analysis

Raw kernel event recording only. Severity is heuristic: dst port numbers for network, prot flags for memory, event name for security. Detection logic lives exclusively in the file and process scanner pipelines. This keeps the sink on the hot path with minimal latency.

### Memory dedup — per-goroutine map

`consumeMemory` owns its dedup map exclusively. No mutex needed since only one goroutine reads and writes it. Cleanup ticker runs inside the same select loop. This is structurally different from DedupTracker which is shared and mutex-protected.

### Rule syncer — tag-based not hash-based

YARA Forge does not publish a separate SHA256 manifest. The syncer calls the GitHub releases API for `tag_name` (e.g. `20260816`) and compares against a `.rules_version` file stored alongside `rules.zip`. On mismatch: download → verify ZIP magic bytes (PK\x03\x04) → archive current with timestamp name → atomic `os.Rename` → write new tag → prune oldest archives beyond `RulesArchiveCount` → `systemctl restart vajra`.

### Pool autotune — four load zones

Reads `/proc/loadavg` every 10s. Below 0.5×CPU: grow freely on any queue depth. 0.5–0.8×CPU: grow only if queue depth exceeds worker count. 0.8–1.0×CPU: hold current size. Above 1.0×CPU: log shrink intent (actual shrink deferred — requires per-worker cancel contexts).

### Planned architecture for remote pipeline

Vajra (endpoint)
→ Fluentbit (log shipping)
→ OpenSearch / ClickHouse (hot storage)
→ Rule processing engine (Sigma, correlation, STIX enrichment)
→ PostgreSQL (analyst workflow state)
→ UI

Sigma and STIX belong server-side where cross-endpoint log sequences and relationship graphs are available. The `known_bad_hashes` table is the local cache that the STIX engine will populate when built — `stix_id` column is already in the schema for back-reference.

### Process tree as primary correlation primitive

The process tree is not stored for detection purposes alone. It is the
primary data structure the server uses to reconstruct attack chains.
A flat stream of process events with pid/ppid/machine_id is sufficient
for the server to build the full execution forest via recursive CTE.

The agent's responsibility is to write every execve event to the
process_tree table reliably and with accurate timestamps. The server's
responsibility is to traverse that tree when correlating alerts.

This division means the agent stays simple — no in-process tree
traversal, no chain detection logic, no graph queries. All of that
lives on the server where it has cross-endpoint visibility and
historical data depth.

The one exception is LOLBin detection which needs parent process
context available at detection time. For this, the process scanner
reads /proc/PID/status for PPID and does a single parent lookup
in the process_tree table to check if the parent is a script
interpreter or download tool. This is a shallow lookup, not full
tree traversal.

## Known Issues

1. **Pool shrink not implemented** — autotune logs intent but cannot actually shrink without per-worker cancel contexts. Low priority.

2. **DNS bpf_probe_read** — sendmsg reads `msg->msg_name` via `bpf_probe_read_kernel` but it is a userspace pointer. Should be `bpf_probe_read_user`. Low risk since most DNS goes via sendto not sendmsg.

3. **rulesync restart race** — if rule sync triggers systemd restart while a YARA scan is in progress, in-flight results are lost. Acceptable since restart is fast and eBPF resumes immediately. Hot reload would eliminate this but is deferred.

4. **Flatpak false positives in LDPreloadAnalyzer** — `/run/flatpak/` and `~/.local/share/flatpak/` not yet in `standardLibPaths`. Flatpak apps will produce the same false positive that snap did before its fix. Add when a Flatpak false positive is observed.

5. **Module name always empty** — `init_module` syscall does not pass filename in args. `finit_module` does but we don't read it. The module_load event fires correctly; name enrichment via `/proc/PID/fd/N` is a follow-up.

6. **boot epoch drift** — if NTP steps the system clock after agent startup the boot epoch becomes slightly wrong. Re-reading `/proc/uptime` periodically and detecting drift is the fix. Rare enough to defer.

## Next Session Starting Point

Priority order for next work:

1. **HashAnalyzer** — `internal/analyzer/hash.go`; `known_bad_hashes` table in schema; `vajra hashes update` CLI command seeding from MalwareBazaar CSV; slots in before YARAAnalyzer in content pipeline; short-circuits on CRITICAL match

2. **Process tree table** — `process_tree` table as adjacency list; written from ProcessEvent PPID on every execve; prerequisite for LOLBin chain detection and server-side correlation

3. **LOLBin analyzer** — `internal/procanalyzer/lolbin.go`; uses full cmdline (now correctly captured); config-driven pattern list

4. **Running process scanner** — startup walk of `/proc/PID/exe`; catches pre-existing malware before agent started

5. **Container tagging** — `/proc/PID/cgroup` parsing; `container_id` and `container_runtime` on process_scan_results

6. **EventStatistic aggregation job** — hourly ticker; table exists but nothing writes to it
