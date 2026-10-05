# Vajra EDR — Architecture and Context Document

Updated: October 2026

## Repository Layout

workspace/src/
├── internal/
│ ├── analyzer/
│ │ ├── analyzer.go # Analyzer interface, Pipeline, ResultCache, MergeResults, PID context helpers
│ │ └── yara.go # YARAAnalyzer — wraps pool, blocks until result
│ ├── ebpf/
│ │ ├── c/
│ │ │ └── ebpf_events.c # BPF C program — kernel side
│ │ ├── types.go # Event structs, Channels, CStringToGo, EventTypeName
│ │ ├── listener.go # BPF load, tracepoint attach, perf read loop
│ │ └── dispatcher.go # RawEvent → typed channels, SecurityEvent translation
│ ├── db/
│ │ ├── db.go # Open, OpenReadOnly, migrate, pragmas
│ │ └── queries/
│ │ ├── autoruns.go # Insert, MarkInactive, UpdateLastSeen, LoadActive
│ │ ├── cleanup.go # RunCleanup — calls all table DeleteBefore methods
│ │ ├── files.go # Insert (populates r.ID), IncrementDedupCount, ListBySeverity
│ │ ├── memory.go # Insert, ListByPID, DeleteBefore
│ │ ├── network.go # Insert, ListByDstPort, DeleteLowSeverityBefore
│ │ ├── processes.go # Insert (populates r.ID), IncrementDedupCount, ListBySeverity
│ │ ├── processtree.go # Insert, GetByPID
│ │ └── security.go # Insert, UpdateStatus, ListCritical
│ ├── jobs/
│ │ ├── autoruns/
│ │ │ ├── autoruns.go # Scanner, Diff, RunAutorunScan goroutine entry
│ │ │ └── sources_linux.go # All 12 Linux persistence sources
│ │ ├── cleanup.go # RunDBCleanup goroutine entry
│ │ ├── dupwatcher.go # DupEvent consumer — socket check, dedup, CRITICAL to security_events
│ │ ├── eventsink.go # Network/Memory/Security/Module → DB; memory dedup pid+prot 30s window
│ │ ├── filescanner.go # filter→eligible(execbit|magic|interpreter)→QuickHash→SHA256→pipeline→dedup→insert
│ │ ├── fullscanner.go # Blocking walk for vajra scan command; two-pass count+scan with progress bar
│ │ ├── processscanner.go # process_tree write→resolve→dedup→runtime pipeline→content pipeline→merge→dedup→insert
│ │ └── rulesync.go # GitHub API tag check→download→zip verify→archive→atomic replace→restart
│ ├── procanalyzer/
│ │ ├── capability.go # /proc/PID/status CapEff bitmask; always runs regardless of ProcessFilter
│ │ └── ldpreload.go # /proc/PID/environ; standard + snap + snapd paths
│ ├── scanner/
│ │ ├── dedup.go # DedupTracker — rule+path+severity key, window-based, RecordInsert
│ │ ├── filter.go # ExclusionFilter, ProcessFilter, RecentScanTracker
│ │ ├── hasher.go # QuickHash (head+tail+mtime), FullSHA256, HashFile, StatFile
│ │ ├── pool.go # Pool, autotune with /proc/loadavg four-zone scaling, Submit/Enqueue
│ │ ├── severity.go # ClassifyYARASeverity — APT/MALWARE/MAL/Ransomware → CRITICAL; HKTL/Exploit/EXPL → HIGH; SUSP → MEDIUM
│ │ └── yara.go # RulesCompiler — ExtractRules, CompileRules
│ └── utilities/
│ ├── clock.go # SystemInfo, LoadSystemInfo, EBPFTimestampToUnix
│ ├── config.go # Config struct with RulesSettings, LoadConfig, applyDefaults
│ ├── detectionlists.go # KnownInterpreters — used for file scan eligibility only
│ └── logging.go # GetLogger, lumberjack rolling file
├── entrypoint.go # Config load, directory setup, LoadSystemInfo, mode dispatch
├── service.go # startServiceMode, wireJobs, wirePipelines
└── shared/
└── models/
└── models.go # All DB model structs — MachineID, DedupCount, FileHash, ProcessTreeEntry
cmd/
├── root.go # Cobra root, --config persistent flag
├── rules.go # vajra rules update / vajra rules status
└── scan.go # vajra scan [directory] — blocking full scan with progress bar

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

`process_tree` table — written on every execve, never pruned by retention cleanup:

- `pid INTEGER NOT NULL`, `ppid INTEGER NOT NULL`, `comm TEXT NOT NULL`
- `exe_path TEXT NOT NULL DEFAULT ''`, `cmdline TEXT NOT NULL DEFAULT ''`
- `machine_id TEXT NOT NULL DEFAULT ''`, `event_time INTEGER NOT NULL`
- Queried via recursive CTE: `WITH RECURSIVE tree AS (SELECT * FROM process_tree WHERE pid=? UNION ALL SELECT p.* FROM process_tree p JOIN tree t ON p.ppid=t.pid)`
- Composite index on `(machine_id, ppid, pid)` for CTE performance
- Prerequisite for: LOLBin chain detection, behavioral correlation, evidence snapshots, server-side attack reconstruction

`known_bad_hashes` table (to be added with HashAnalyzer):

- `sha256 TEXT PRIMARY KEY`
- `family TEXT` — malware family name from feed
- `source TEXT NOT NULL` — `'malwarebazaar'`, `'virustotal'`, `'stix'`, `'manual'`
- `tags TEXT` — JSON array of tags from feed
- `added_at INTEGER NOT NULL`
- `stix_id TEXT` — null until STIX engine exists; back-reference for when STIX bundles populate this table

## Key Design Decisions

### SystemInfo — single source of truth

`utilities.LoadSystemInfo()` reads `/etc/machine-id` and computes boot epoch from `/proc/uptime` once at startup. Both `EventSink`, `ProcessScanner`, and `FileScanner` receive it as a dependency. `EBPFTimestampToUnix(nsec uint64) int64` converts `bpf_ktime_get_ns()` values to wall clock seconds. No component computes its own boot epoch independently.

### Two-pipeline process scanner

Content pipeline (YARA + future HashAnalyzer) is cached via ResultCache keyed on SHA256 and filter-aware — trusted processes skip it entirely. Runtime pipeline (LDPreload, Capability) is never cached and always runs regardless of ProcessFilter. `MergeResults()` takes the higher severity across both pipelines and clears `Skip` if the runtime pipeline found anything.

### Reverse shell detection — dup-driven, not exec-time

`RevShellAnalyzer` has been removed from the runtime pipeline. Reverse shell detection is now driven by `dup2`/`dup3` tracepoints via `DupWatcher`.

When `dup2(oldfd, newfd)` fires with `newfd <= 2`, the eBPF program emits a `DupEvent`. `DupWatcher` reads from the dedicated `ch.Dup` channel and resolves `/proc/PID/fd/OldFd`. If the symlink is `socket:[inode]` and that inode appears in `/proc/net/tcp*` or `/proc/net/udp*`, a CRITICAL `security_event` is written directly.

This catches `bash -i >& /dev/tcp/...` which exec-time fd inspection could not see, because the socket is opened after exec. No process name filtering is applied — any process redirecting a network socket onto stdio is suspicious regardless of comm.

AF_UNIX sockets are excluded by construction: their inodes appear only in `/proc/net/unix`, which is never read. Pipe inodes never appear in inet tables. Normal `dup2` usage on files, pipes, and terminals produces no DB writes at all.

Dedup is keyed on `pid+inode` with a 30-second window. `bash -i >& /dev/tcp/...` calls `dup2` multiple times for the same socket — without dedup this produces a storm of identical CRITICAL rows.

### File scan eligibility — three conditions

`isEligibleFile(path, triggerComm)` passes if any one of:

1. Execute bit set — `info.Mode()&0111 != 0` — catches `chmod +x` scripts without shebangs
2. Magic bytes match — ELF (`7f 45 4c 46`), shebang (`23 21`), MZ/PE (`4d 5a`), Mach-O fat (`ca fe ba be`)
3. `triggerComm` in `KnownInterpreters` — eBPF-driven path only; catches `python3 malware.py` where the script has no magic bytes

For the full scan walk (`vajra scan`), `triggerComm` is always empty — only conditions 1 and 2 apply since there is no triggering process. The broken fifth magic byte check (`magic[3]==0x0d`) has been removed.

`KnownInterpreters` is used solely for condition 3. `KnownShells` has been removed entirely — revshell detection requires no process name filtering.

### DedupTracker

Keyed on `rule+path+severity`. `CheckAndRecord()` returns `shouldInsert bool` and `*DedupEntry`. First occurrence: insert to DB, call `RecordInsert(key, record.ID)` to store the row ID. Subsequent occurrences within window: call `IncrementDedupCount(entry.RecordID)` instead of inserting. Severity escalation on the same path always generates a new row since the key changes. Clean results bypass dedup entirely.

`Insert()` on `FileQueries` and `ProcessQueries` populates `r.ID` via `LastInsertId()` — this is required for `RecordInsert` to work correctly.

### ResultCache

Keyed on SHA256, no TTL. YARA results are deterministic for a given binary content. Cache cleared on agent restart which coincides with rule recompile at startup. When HashAnalyzer is added it will also consult this cache — a known-bad hash match short-circuits YARA entirely.

### Event sink — no analysis

Raw kernel event recording only. Severity is heuristic: dst port numbers for network, prot flags for memory, event name for security. Detection logic lives exclusively in the file scanner, process scanner pipelines, and DupWatcher. This keeps the sink on the hot path with minimal latency.

### Memory dedup — per-goroutine map

`consumeMemory` owns its dedup map exclusively. No mutex needed since only one goroutine reads and writes it. Cleanup ticker runs inside the same select loop. DupWatcher follows the same pattern for its `pid+inode` dedup map.

### Process tree — written on every execve, before analysis

`ProcessScanner.handle()` writes to `process_tree` as the very first operation, before dedup, before exclusion filtering, before analysis. `cmdline` is read at this point since the process may exit before `persist()` is reached. The write is non-fatal — analysis continues even if the tree write fails.

The tree is never pruned by retention cleanup. The server reconstructs full execution forests via recursive CTE. The agent stays simple — no in-process tree traversal, no chain detection logic, no graph queries.

The one exception is LOLBin detection which needs parent context at detection time. The process scanner does a single shallow lookup in `process_tree` via `GetByPID` — not full tree traversal.

### Rule syncer — tag-based not hash-based

YARA Forge does not publish a separate SHA256 manifest. The syncer calls the GitHub releases API for `tag_name` (e.g. `20260816`) and compares against a `.rules_version` file stored alongside `rules.zip`. On mismatch: download → verify ZIP magic bytes (`PK\x03\x04`) → archive current with timestamp name → atomic `os.Rename` → write new tag → prune oldest archives beyond `RulesArchiveCount` → `systemctl restart vajra`.

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

### eBPF tracepoints — current set

| Tracepoint | Event type | Notes |
|---|---|---|
| `sys_enter_execve` | `ProcessEvent` | Full cmdline read from `/proc/PID/cmdline` in Go |
| `sys_enter_setuid` | `ProcessEvent` | |
| `sys_enter_setgid` | `ProcessEvent` | |
| `sys_enter_memfd_create` | `ProcessEvent` | |
| `sys_enter_ptrace` | `PtraceEvent` → `SecurityEvent` | |
| `sys_enter_mmap` | `MmapEvent` | PROT_EXEC only |
| `sys_enter_mprotect` | `MmapEvent` | PROT_EXEC only |
| `sys_enter_capset` | `CapsetEvent` → `SecurityEvent` | |
| `sys_enter_dup2` | `DupEvent` | newfd <= 2 only, kernel-side filter |
| `sys_enter_dup3` | `DupEvent` | newfd <= 2 only, kernel-side filter |
| `sys_enter_openat` | `FileEvent` | O_CREAT only |
| `sys_enter_unlinkat` | `FileEvent` | |
| `sys_enter_renameat2` | `FileEvent` | |
| `sys_enter_fchmodat` | `FileEvent` | |
| `sys_enter_connect` | `NetworkEvent` | AF_INET/AF_INET6 only |
| `sys_enter_bind` | `NetworkEvent` | AF_INET/AF_INET6 only |
| `sys_enter_socket` | `NetworkEvent` | SOCK_RAW/SOCK_PACKET only |
| `sys_enter_sendto` | `dns_event_raw` | port 53 only |
| `sys_enter_sendmsg` | `dns_event_raw` | port 53 only; uses `bpf_probe_read_user` for msg_name |
| `sys_enter_init_module` | `ModuleEvent` | name always empty |
| `sys_enter_finit_module` | `ModuleEvent` | name always empty — bpf_d_path unavailable in tracepoints |
| `sys_enter_unshare` | `NamespaceEvent` → `SecurityEvent` | |
| `sys_enter_setns` | `NamespaceEvent` → `SecurityEvent` | |

## Known Issues

1. **Pool shrink not implemented** — autotune logs intent but cannot actually shrink without per-worker cancel contexts. Low priority.

2. **rulesync restart race** — if rule sync triggers systemd restart while a YARA scan is in progress, in-flight results are lost. Acceptable since restart is fast and eBPF resumes immediately. Hot reload would eliminate this but is deferred.

3. **Flatpak false positives in LDPreloadAnalyzer** — `/run/flatpak/` and `~/.local/share/flatpak/` not yet in `standardLibPaths`. Flatpak apps will produce the same false positive that snap did before its fix. Add when a Flatpak false positive is observed.

4. **Module name always empty** — `bpf_d_path` is unavailable in tracepoint programs (verifier rejects it). Name enrichment for `finit_module` requires fentry program type or userspace `/proc/PID/fd/N` resolution at event time. Deferred until fentry migration or a userspace enrichment job is added.

5. **boot epoch drift** — if NTP steps the system clock after agent startup the boot epoch becomes slightly wrong. Re-reading `/proc/uptime` periodically and detecting drift is the fix. Rare enough to defer.

6. **KnownInterpreters requires periodic review** — versioned interpreter binaries (e.g. `python3.14`) need to be added as distributions update. Last reviewed October 2026. Track new scripting runtimes and update `utilities/detectionlists.go` when false negatives are observed.

7. **DupWatcher misses pre-exec socket inheritance** — if a process inherits a socket on stdio from its parent without calling `dup2` itself (e.g. inetd-style services), no DupEvent fires. This is acceptable: the exec-time fd check was removed because it produced false positives for exactly this pattern. A future fentry hook on `do_dup2` could close this gap.

## Next Session Starting Point

Priority order:

1. **HashAnalyzer** — `internal/analyzer/hash.go`; `known_bad_hashes` table in schema; `vajra hashes update` CLI command seeding from MalwareBazaar CSV; slots in before YARAAnalyzer in content pipeline; short-circuits on CRITICAL match

2. **LOLBin analyzer** — `internal/procanalyzer/lolbin.go`; uses full cmdline (now correctly captured); uses `ProcessTreeQueries.GetByPID` for shallow parent context; config-driven pattern list; fires HIGH

3. **Running process scanner** — startup walk of `/proc/PID/exe`; catches pre-existing malware before agent started; dedup against RecentScanTracker

4. **Container tagging** — `/proc/PID/cgroup` parsing; `container_id TEXT` and `container_runtime TEXT` on `process_scan_results`; empty for host processes

5. **EventStatistic aggregation job** — hourly ticker; upsert counts into `event_statistics` grouped by `event_type` and date; needed before dashboard is useful
