# Vajra EDR — Architecture and Context

Updated: October 2026

## Interface Design Decisions

### Why three separate abstractions: Watcher, Scanner, Job

The original flat `jobs/` package mixed three fundamentally different execution models:

- **Watcher** — push-based, blocks on a channel, reacts to kernel events. FileScanner, ProcessScanner, DupWatcher, EventSink.
- **Scanner** — pull-based, walks a data source on a timer or at startup. AutorunScanner, SecretsScanner, RunningProcessScanner, UserProfileScanner.
- **Job** — utility goroutine with no detection role. DBCleanup, RuleSyncer, AggregationJob, HashSyncer.

Separating them means `service.go` wires each category uniformly. Adding a new detection component is one constructor call and one `go x.Run(ctx, wg)`. Nothing in service.go needs to know what the component does internally.

EventSink is deliberately not wired through the `Watcher` interface because it consumes multiple channels simultaneously. Forcing it through `Run(ctx, wg)` would require hiding the channel fan-out inside a struct that owns all channels — which would break the principle that each watcher owns its own channel dependency injected at construction time.

### Why Analyzer is separate from Watcher/Scanner

Analyzers are stateless functions: path in, result out. They compose into pipelines, cache on SHA256, and short-circuit on CRITICAL. They have no lifecycle — no goroutine, no channel, no timer.

Watchers and Scanners have lifecycle. They own goroutines. They produce Findings as output.

Mixing them would mean either giving Analyzers artificial lifecycle (wrong) or giving Watchers the pipeline composition logic (wrong). The boundary is: Analyzers are called by Watchers and Scanners, never the reverse.

### Why RuleMatch is an interface in utilities/

Severity classification was originally YARA-specific (`ClassifyYARASeverity` taking `[]YaraMatch`). Moving to a `RuleMatch` interface in `utilities/` means:

- betterleaks findings implement `RuleMatch` via `RuleID()` and `RuleTags()`
- Hash lookup results implement `RuleMatch` via `RuleID()` returning the malware family
- `ClassifySeverity([]RuleMatch)` works for all three without knowing which engine produced them

The YARA naming convention (APT_, MALWARE_, HKTL_, SUSP_) becomes the shared vocabulary. Any engine that follows it gets severity classification for free.

### Why FindingWriter is the single DB insertion point

Before the refactor, FileScanner wrote to `file_scan_results`, ProcessScanner wrote to `process_scan_results`, DupWatcher wrote to `security_events`. Three separate dedup implementations, three separate insert paths, no unified detection record.

FindingWriter enforces:

- One dedup implementation for all sources
- One schema (detections + extension tables) for all sources
- Evidence capture triggered in one place (on HIGH/CRITICAL)
- Metrics tracked in one place

The cost is that all detection sources must produce a `Finding` value. This is correct — it means each source only needs to know what it detected, not how to store it.

### Why detections is unified but extension tables are separate

A single `details TEXT` JSON column becomes a dumping ground. The extension table design instead:

- `detection_artifacts` — file hash + YARA matches (file/process detections only)
- `detection_network` — socket details (reverse shell detections only)
- `detection_secrets` — betterleaks findings (secrets scanner only)
- `detection_extensions` — key/value rows, one per field, indexed on key

The last one is the escape hatch. It exists to avoid schema migrations for source-specific fields that don't warrant a dedicated column. Each key gets its own row so `WHERE key='autorun_category' AND value='systemd_system'` is index-assisted.

### Why the file size floor is 4 bytes, not 100MB ceiling

The original 10-byte floor and 100MB ceiling were engineering shortcuts. The floor is correct in spirit — nothing meaningful executes in under 4 bytes. The ceiling is wrong — a 150MB binary is absolutely a threat. Packed malware and droppers don't respect size limits.

The correct protection against large files stalling the YARA pool is the per-file scan timeout (`single_file_scan_timeout_sec` in config), not a size cap. YARA aborts the scan and returns an error on timeout. The ceiling has been removed. The floor is 4 bytes.

### Why process_tree is never pruned

Process tree completeness matters more than disk space. A single missing execve row creates a hole in the ancestry chain that breaks:

- Server-side recursive CTE traversal
- LOLBin parent context lookup
- Behavioral correlation
- Evidence snapshot context

Retention cleanup touches `detections` (resolved only) and raw telemetry (age-based). It never touches `process_tree`.

### Why DupWatcher writes through FindingWriter, not security_events

Reverse shell is a detection, not raw telemetry. Raw telemetry tables record everything the kernel produces — ptrace, capset, namespace, dns, network connections — without analysis. DupWatcher performs analysis (socket inode lookup, inet table cross-reference) and produces a confirmed finding. That belongs in `detections` alongside YARA hits and capability detections, not mixed into the raw event stream.

### Why EventSink bypasses FindingWriter

EventSink records everything including noise. Network events include every DNS query and outbound connection. Memory events include every mmap with PROT_EXEC. Security events include every ptrace call. These are not findings — they are raw observability data for the Sigma engine and behavioral correlation server-side.

Running them through FindingWriter would create millions of CLEAN detection rows that serve no purpose locally. The distinction is: FindingWriter is for anomalies. EventSink is for forensic completeness.

### Why HashAnalyzer uses a Bloom filter, not SQLite

The content pipeline runs on every file event. A SQLite lookup per file under vajra's single-connection model would create lock contention and disk I/O on the hot path. A Bloom filter with 5M capacity at 1% false positive rate is ~4MB in memory, loaded once at startup, and answers in microseconds with zero disk I/O.

False positives mean YARA runs on a file it didn't need to — acceptable overhead. False negatives are impossible. This matches how production EDR agents handle hash-based detection. The Bloom filter is built offline from the MalwareBazaar CSV by HashSyncer and written to disk; the daemon loads it at startup.

### Why SecretsScanner uses path segment exclusions, not regex

betterleaks' `prefilter.Options.ExcludedPaths` does exact matching after `filepath.Clean` — useless for matching path segments inside longer paths. A custom `sources.PrefilterFunc` using `strings.Contains` per segment is simpler, faster, and correct. The segment list is assembled by `SecretsSettings.AllExcludeSegments()` combining built-in structural excludes, optional browser cache excludes, and operator-supplied entries. No regex required.

### Why the secrets ignore list is file-based, not DB-only

betterleaks' `scan.WithIgnoredFingerprints` must be passed at scanner construction time — there is no way to add fingerprints to a running scanner. The ignore file is loaded once at `NewSecretsScanner`. The operator workflow is: mark detections IGNORED in the DB via `vajra secrets ignore`, export fingerprints to `secrets.ignore` via `vajra secrets export-ignore`, restart the daemon. In the future UI this becomes a single button.

## eBPF Tracepoints

| Tracepoint | Event | Notes |
|---|---|---|
| sys_enter_execve | ProcessEvent | cmdline from /proc/PID/cmdline in Go |
| sys_enter_setuid | ProcessEvent | |
| sys_enter_setgid | ProcessEvent | |
| sys_enter_memfd_create | ProcessEvent | |
| sys_enter_ptrace | PtraceEvent → SecurityEvent | |
| sys_enter_mmap | MmapEvent | PROT_EXEC only |
| sys_enter_mprotect | MmapEvent | PROT_EXEC only |
| sys_enter_capset | CapsetEvent → SecurityEvent | |
| sys_enter_dup2 | DupEvent | newfd <= 2 kernel-side filter |
| sys_enter_dup3 | DupEvent | newfd <= 2 kernel-side filter |
| sys_enter_openat | FileEvent | O_CREAT only |
| sys_enter_unlinkat | FileEvent | |
| sys_enter_renameat2 | FileEvent | |
| sys_enter_fchmodat | FileEvent | |
| sys_enter_connect | NetworkEvent | AF_INET/AF_INET6 only |
| sys_enter_bind | NetworkEvent | AF_INET/AF_INET6 only |
| sys_enter_socket | NetworkEvent | SOCK_RAW/SOCK_PACKET only |
| sys_enter_sendto | dns_event_raw | port 53 only |
| sys_enter_sendmsg | dns_event_raw | port 53 only, bpf_probe_read_user for msg_name |
| sys_enter_init_module | ModuleEvent | name always empty |
| sys_enter_finit_module | ModuleEvent | name always empty — bpf_d_path unavailable in tracepoints |
| sys_enter_unshare | NamespaceEvent → SecurityEvent | |
| sys_enter_setns | NamespaceEvent → SecurityEvent | |

## Schema

### Detection tables (non-clean findings)

detections
├── detection_artifacts FK → detections.id (file hash, YARA matches)
├── detection_network FK → detections.id (socket details)
├── detection_secrets FK → detections.id (betterleaks, sha256(secret) + fingerprint)
├── detection_extensions FK → detections.id (key/value escape hatch, indexed)
└── evidence_snapshots FK → detections.id (live /proc state at detection time)

### Raw telemetry (everything, including noise)

network_events
memory_events
security_events
process_tree (never pruned)

### Inventory

autoruns
user_inventory (planned)

### Threat intelligence

hashes.bloom — Bloom filter on disk, loaded by HashAnalyzer at startup
built by HashSyncer from MalwareBazaar full CSV
replaced by server-side push in Phase 3
secrets.ignore — betterleaks fingerprint ignore file, written by vajra secrets export-ignore

### Operational

audit_log (append-only, never pruned)
event_statistics (hourly aggregation, planned)
quarantined_files (response system, Phase 5)
sync_state (remote sync watermarks, Phase 3)

## Known Issues

1. **Pool shrink not implemented** — autotune logs intent but cannot shrink without per-worker cancel contexts.

2. **rulesync restart race** — in-flight YARA scans are lost on systemd restart triggered by rule update. Acceptable since restart is fast and eBPF resumes immediately.

3. **Flatpak false positives in LDPreloadAnalyzer** — `/run/flatpak/` and `~/.local/share/flatpak/` not in standardLibPaths. Add when observed.

4. **Module name always empty** — bpf_d_path unavailable in tracepoint programs. Requires fentry migration or userspace enrichment.

5. **Boot epoch drift** — NTP clock steps after startup make EBPFTimestampToUnix slightly wrong. Rare enough to defer.

6. **KnownInterpreters requires review** — versioned binaries (python3.14 etc) need adding as distributions update. Last reviewed October 2026.

7. **DupWatcher misses pre-exec socket inheritance** — inetd-style socket handoff produces no DupEvent. Acceptable tradeoff given the false positive it prevented.

8. **Bloom filter not reloaded on update** — HashSyncer writes a new filter file but the daemon must restart to load it. Signal-based reload deferred to Phase 3.

9. **Secrets ignore list requires restart** — betterleaks WithIgnoredFingerprints is set at construction time. Live reload deferred to Phase 4 UI.

## Next Session

Priority order:

1. **LOLBin analyzer** — `internal/analyzer/lolbin.go`; cmdline patterns; parent lookup via process_tree
2. **Running process scanner** — `internal/detect/procwalk.go`; /proc/PID/exe walk on startup
3. **Container tagging** — parse /proc/PID/cgroup on execve; container_id + container_runtime on detections
4. **EventStatistic aggregation job** — hourly ticker; needed before dashboard is useful
5. **User profile scanner** — `internal/detect/userprofile.go`; passwd/shadow/sudoers/ssh keys
