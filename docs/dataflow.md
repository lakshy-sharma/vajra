# Dataflow

## Event Collection

KERNEL
execve openat connect mmap ptrace capset dup2/3 unshare modules
│
│ eBPF tracepoints
▼
internal/ebpf/
Listener → perf ring buffer → RawEvent
Dispatcher → typed channels

Channels: Process File Network Memory Security Module Namespace Dup

## Event Routing

Three consumers read from the typed channels in parallel:
                ┌─────────────────┬──────────────────────┐
                ▼                 ▼                      ▼
          EventSink          FileScanner            DupWatcher
          Network            ProcessScanner
          Memory
          Security
          Module
          Namespace

### EventSink — raw telemetry only

Writes everything to raw telemetry tables without analysis. Bypasses FindingWriter by design — these are not findings, they are forensic data for the Sigma engine.

Network → network_events
Memory → memory_events
Security → security_events
Module → security_events
Namespace → security_events

### FileScanner

File event
→ eligibility check (execute bit | magic bytes | known interpreter)
→ QuickHash + dedup window
→ FullSHA256
→ Content Pipeline
→ Finding → FindingWriter

### ProcessScanner

Process event
→ process_tree write (unconditional — every execve)
→ Runtime Pipeline (always runs — live process state)
→ Content Pipeline (skipped for trusted processes)
→ MergeResults()
→ Finding → FindingWriter

### DupWatcher

Dup event (dup2/dup3 onto stdin/stdout/stderr)
→ readlink oldfd → socket inode?
→ cross-reference /proc/net/tcp
→ confirmed reverse shell?
→ Finding → FindingWriter
(pid+inode dedup, 30s window)

## Analyzer Pipelines

Content Pipeline (internal/analyzer/)
(cached on SHA256 — same binary not re-scanned)

HashAnalyzer ← Bloom filter lookup against MalwareBazaar dataset
│ CRITICAL hit → short-circuit, skip YARA
▼
YARAAnalyzer ← YARA Forge ruleset via autotuning worker pool

Runtime Pipeline
(never cached — reads live /proc state)

LDPreloadAnalyzer ← /proc/PID/environ — LD_PRELOAD injection
CapabilityAnalyzer ← /proc/PID/status — dangerous Linux capabilities
LOLBinAnalyzer ← cmdline patterns + process_tree parent lookup [planned]

## Scanner Layer — periodic, pull-based

internal/detect/

AutorunScanner — all 12 Linux persistence categories, diffs against DB
SecretsScanner — betterleaks v2, path segment prefilter, fingerprint ignore list
RunningProcessScanner — /proc/PID/exe walk on startup [planned]
UserProfileScanner — passwd/shadow/sudoers/ssh keys, diffs against DB [planned]

All scanners produce Finding → FindingWriter

## FindingWriter

Single DB insertion point for all detection sources.

Write(ctx, Finding)
├── DedupTracker.CheckAndRecord(rule + path + severity)
│ duplicate → IncrementDedupCount, return
│ new → continue
├── INSERT detections
├── FileHash/YaraMatches → INSERT detection_artifacts
├── RemoteAddr → INSERT detection_network
├── SecretHash → INSERT detection_secrets
├── Extensions → INSERT detection_extensions
└── severity >= HIGH → captureEvidence()
reads /proc/PID/fd, maps, environ, status
INSERT evidence_snapshots

Metrics: Written, Deduped, Errors, Evidence, EvidFail
LogMetrics() → audit_log every 15 min

## Storage

### Detection tables

detections
├── detection_artifacts — file hash + YARA matches
├── detection_network — reverse shell socket details
├── detection_secrets — betterleaks findings (sha256 + fingerprint, never raw value)
├── detection_extensions — key/value escape hatch, indexed
└── evidence_snapshots — /proc state at detection time

### Raw telemetry

network_events
memory_events
security_events
process_tree (never pruned — holes break ancestry chain)

### Inventory

autoruns ← AutorunScanner
user_inventory ← UserProfileScanner (planned)

### Threat intelligence

hashes.bloom ← HashSyncer builds from MalwareBazaar CSV, loaded at startup
secrets.ignore ← vajra secrets export-ignore, loaded at SecretsScanner construction

### Operational

audit_log (append-only, never pruned)
event_statistics (planned — hourly aggregation)
quarantined_files (Phase 5)
sync_state (Phase 3 — remote sync watermarks)

## Service Wiring — internal/service.go

wireAll()
bootstrap
LoadConfig → OpenDB → CompileRules → LoadBloomFilter
→ BuildPool → FindingWriter

watchers
EventSink.Run(ctx, wg, channels)
go DupWatcher.Run(ctx, wg, ch.Dup)
go FileScanner.Run(ctx, wg, ch.File)
go ProcessScanner.Run(ctx, wg, ch.Process)

scanners
go AutorunScanner.Run(ctx, wg)
go SecretsScanner.Run(ctx, wg)
go RunningProcessScanner.Run(ctx, wg) [planned]

jobs
go DBCleanup.Run(ctx, wg)
go RuleSyncer.Run(ctx, wg)
go HashSyncer.Run(ctx, wg)

## CLI — cmd/

vajra [monitor] → service.go daemon
vajra scan [dir] → detect.RunFullScan() blocking

vajra rules update → job.RuleSyncer.RunOnce()
vajra rules status → read-only file stat

vajra hashes update → job.HashSyncer.RunOnce()
vajra hashes status → read-only file stat

vajra secrets ignore <id> → queries.DetectionQueries.UpdateStatus(IGNORED)
vajra secrets export-ignore → queries.SecretQueries.ListIgnoredFingerprints() → secrets.ignore

## UI — vajra-ui (planned, separate Wails binary)

Read-only SQLite in WAL mode — no write lock contention with the daemon.

Dashboard → event_statistics + audit_log
Alert list → detections
Alert detail → detections JOIN artifacts + network + secrets + evidence
Process tree → process_tree recursive CTE
Autorun view → autoruns
Secret view → detection_secrets JOIN detections

Switched from box-drawing characters to indented prose sections with minimal ASCII for the parts that genuinely need flow arrows. Much easier to read and update — adding a new component is one line, not a box realignment exercise.
