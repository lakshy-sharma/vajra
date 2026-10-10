# Vajra EDR — Data Flow

---

## 1. Event Collection

```
KERNEL SYSCALLS
execve  openat  connect  mmap  ptrace  capset  dup2/dup3  unshare  init_module

       eBPF tracepoints (internal/ebpf/c/ebpf_events.c)
       per-CPU heap maps → perf event array
                │
                ▼
        internal/ebpf/listener.go
        perf.NewReader (ring size from EBPFPerfRingPages)
        deserialize() → RawEvent union struct (no interface{} allocation)
                │
                ▼
        internal/ebpf/dispatcher.go
        Dispatcher.Run() fans out to typed channels
```

**Typed channels** (all buffered at `ScanQueueSize`):

| Channel | Carries | Consumer |
|---|---|---|
| ch.Process | ProcessEvent | ProcessScanner |
| ch.File | FileEvent | FileScanner |
| ch.Network | NetworkEvent | EventSink |
| ch.Memory | MmapEvent | EventSink |
| ch.Security | SecurityEvent | EventSink |
| ch.Module | ModuleEvent | EventSink |
| ch.Namespace | NamespaceEvent | (drained, forwarded as SecurityEvent) |
| ch.Dup | DupEvent | DupWatcher |

---

## 2. Event Routing

Three consumers run in parallel goroutines:

```
                    ┌──────────────────┬───────────────────┐
                    ▼                  ▼                   ▼
              EventSink          FileScanner          DupWatcher
              (raw telemetry)    (content pipeline)   (reverse shell)
              ProcessScanner
```

### EventSink — forensic completeness, no analysis

```
ch.Network   → network_events
ch.Memory    → memory_events  (dedup: pid+prot, 30s window, W^X always)
ch.Security  → security_events
ch.Module    → security_events
ch.Namespace → security_events
```

EventSink bypasses FindingWriter — these are not findings, they are raw data for the Sigma engine. Running them through FindingWriter would create millions of CLEAN rows.

### FileScanner

```
ch.File
  → eligibility (execute bit | magic bytes | known interpreter)
  → ExclusionFilter.ShouldScan()
  → QuickHash → RecentScanTracker.WasRecentlyScanned()
  → FullSHA256
  → Content Pipeline
  → Finding → FindingWriter
```

### ProcessScanner

```
ch.Process
  → process_tree INSERT (unconditional — every execve, never pruned)
  → resolveExePath
  → QuickHash → RecentScanTracker.WasRecentlyScanned()
  → Runtime Pipeline (always — reads live /proc state)
  → Content Pipeline (skipped for trusted processes)
  → MergeResults()
  → Finding → FindingWriter
```

### DupWatcher

```
ch.Dup (dup2/dup3 onto fd 0/1/2)
  → readlink /proc/PID/fd/OldFd → socket inode?
  → pid+inode dedup (30s window)
  → cross-reference /proc/net/tcp*/udp*
  → confirmed reverse shell?
  → Finding → FindingWriter
```

---

## 3. Analyzer Pipelines

Both pipelines are called synchronously inside the watcher goroutine.

### Content Pipeline — cached on SHA256

```
HashAnalyzer
  └── Bloom filter lookup (MalwareBazaar dataset, ~4 MB in memory)
      CRITICAL → return early, skip YARA
      CLEAN   → continue
          ▼
YARAAnalyzer
  └── pool.Enqueue() → YARA worker (autotuning, min–max threads)
      → ConvertMatches() → []YaraStringMatch{Identifier, Offset, SnapshotHex}
      → ClassifySeverity([]RuleMatch)
          ▼
      Result{Severity, YaraMatches, Notes}
```

ResultCache (LRU, capacity from `ResultCacheSize`) stores Results keyed on SHA256. CLEAN hits set `Skip=true`. Non-CLEAN hits still produce a Finding — same binary executing again is worth recording.

### Runtime Pipeline — never cached

```
LDPreloadAnalyzer
  └── /proc/PID/environ → LD_PRELOAD, LD_LIBRARY_PATH
      outside TrustedLDPaths whitelist → HIGH
          ▼
CapabilityAnalyzer
  └── /proc/PID/status → CapEff bitmask
      matches DangerousCapabilities list → HIGH
      (ProcessCapabilityExclusions respected)
          ▼
LOLBinAnalyzer [planned]
  └── comm or exe basename in LOLBins list
      parent via ProcessTreeQueries.GetByPID
      suspicious parent → HIGH
```

---

## 4. Scanner Layer — periodic, pull-based

All scanners run in their own goroutines, produce Findings, and go through FindingWriter.

```
AutorunScanner (internal/detect/autorun/)
  └── 12 sources: systemd, cron, shell profiles, PAM, LD_PRELOAD, XDG, SysV, D-Bus, at, anacron
      errgroup + semaphore (AutorunConcurrency, default 2)
      diff against autoruns table
      new entry → Finding(severity=MEDIUM, source=autorun_scanner)
      removed entry → MarkInactive

SecretsScanner (internal/detect/secrets.go)
  └── betterleaks v2 SDK
      ScanTargets from config
      per-target context.WithTimeout
      path segment prefilter (ExcludedPaths + DBDirectory)
      fingerprint ignore list (SecretsSettings.IgnoreFile)
      sha256(secret) stored, raw value never persisted
      → Finding(source=secrets_scanner)

RunProcWalk (internal/detect/procwalk.go)
  └── runs once at startup after StartupProcwalkDelaySec
      walks /proc/PID/exe for all live processes
      shares RecentScanTracker with ProcessScanner
      submits to Content Pipeline
      → Finding(source=process_scanner)
```

---

## 5. FindingWriter

The single DB insertion point for all detection sources.

```
FindingWriter.Write(ctx, Finding)
  │
  ├── DedupTracker.CheckAndRecord(rule_id + target_path + severity)
  │     duplicate within window → IncrementDedupCount, return 0
  │     new → continue
  │
  ├── INSERT detections (gets row ID)
  │
  ├── FileHash / YaraMatches  → INSERT detection_artifacts
  ├── RemoteAddr              → INSERT detection_network (OldFd, NewFd)
  ├── SecretHash              → INSERT detection_secrets
  ├── Extensions map          → INSERT detection_extensions (key/value rows)
  │
  └── Severity >= HIGH
        → captureEvidence()
            reads /proc/PID/fd   → OpenFDs  (json.RawMessage)
            reads /proc/PID/maps → Maps     (json.RawMessage, plain text in JSON string)
            reads /proc/PID/environ → Environ (json.RawMessage)
            reads /proc/PID/status  → Status  (string)
            INSERT evidence_snapshots

Metrics (atomic, unexported): Written, Deduped, Errors, Evidence, EvidFail
LogMetrics() called by health ticker → audit_log
```

---

## 6. Storage

### Detection tables

```
detections
├── detection_artifacts   — file hash + YARA matches with SnapshotHex
├── detection_network     — socket: RemoteAddr, RemotePort, OldFd, NewFd
├── detection_secrets     — sha256(secret) + betterleaks fingerprint (raw value never stored)
├── detection_extensions  — key/value escape hatch, indexed on (detection_id, key)
└── evidence_snapshots    — /proc state captured at detection time (HIGH/CRITICAL only)
```

### Raw telemetry

```
network_events   — all connect/bind/raw socket events
memory_events    — PROT_EXEC mmap/mprotect (deduped by pid+prot)
security_events  — ptrace, capset, namespace, module, DNS
process_tree     — every execve; never pruned; recursive CTE for ancestry
```

### Inventory

```
autoruns         — active persistence entries, diffs maintained by AutorunScanner
user_inventory   — planned: passwd/sudoers/ssh key baseline
```

### Threat intelligence

```
hashes.bloom     — built by HashSyncer from MalwareBazaar CSV; loaded at startup
                   ~4 MB in memory; false negatives impossible; ~1% FP rate
secrets.ignore   — betterleaks fingerprints; written by vajra secrets export-ignore
                   loaded at SecretsScanner construction; requires restart to reload
```

### Operational

```
audit_log        — append-only; component lifecycle, health ticks, WriteConfig calls
event_statistics — hourly aggregation of raw telemetry (planned: StatSyncer)
app_config       — stored config blob with schema version; daemon merges on startup
quarantined_files — Phase 5 response system
sync_state       — Phase 3 remote sync watermarks
```

---

## 7. Jobs — Utility Goroutines

```
DBCleanup (job/cleanup.go)
  └── immediate run at startup, then on CleanupIntervalHour
      deletes resolved detections and raw telemetry older than EventRetentionDays
      WAL checkpoint after delete (PRAGMA wal_checkpoint(TRUNCATE))

RuleSyncer (job/rulesync.go)
  └── checks YARA Forge GitHub API for new tag
      downloads if tag differs from local .rules_version
      verifies ZIP central directory (not just magic bytes)
      archives current rules (up to RulesArchiveCount generations)
      restarts daemon via systemctl on successful update

HashSyncer (job/hashsync.go)
  └── downloads MalwareBazaar full CSV export
      auth key in Auth-Key header (never in URL)
      csv.Reader.Comment = '#' (no goroutine/pipe needed)
      lowercases SHA256 at insert time (companion to hash.go A10)
      writes Bloom filter atomically (tmp + rename)
      deletes zip after successful build (forces fresh download next cycle)

StatSyncer (job/statsync.go)
  └── runs on StatsSyncIntervalMin
      calls StatisticsQueries.Aggregate(ctx)
      upserts into event_statistics grouped by source + day (UTC epoch)
```

---

## 8. Service Wiring — internal/service.go

```
wireAll() returns error — never calls Fatal after goroutines have started

Bootstrap
  LoadConfig → OpenDB → CompileRules(MaxFileSizeBytes) → LoadBloomFilter
  → NewResultCache(ResultCacheSize) → NewPool(yaraSnapshotBytes)
  → FindingWriter

eBPF
  go Listener.Stop on ctx done
  go Dispatcher.Run(ctx, rawCh, channels)
  go drain channels.Namespace

Watchers
  EventSink.Run(ctx, wg, channels)        — 4 goroutines inside
  go FileScanner.Run(ctx, wg, ch.File)
  go ProcessScanner.Run(ctx, wg, ch.Process)
  go DupWatcher.Run(ctx, wg, ch.Dup)

Startup scanners (with delay from config)
  go sleepWithCtx(StartupProcwalkDelaySec) → RunProcWalk
  go sleepWithCtx(StartupAutorunDelaySec) → AutorunScanner.Run
  go sleepWithCtx(StartupSecretsDelayMin) → SecretsScanner.Run

Jobs
  go Cleanup.Run(ctx, wg)
  go RuleSyncer.Run(ctx, wg)
  go HashSyncer.Run(ctx, wg)
  go StatSyncer.Run(ctx, wg)

Signal handling
  signal.Notify(sigChan, SIGINT, SIGTERM)
  defer signal.Stop(sigChan)
  <-sigChan → cancel() → wg.Wait() or 30s timeout
```

---

## 9. CLI — cmd/

```
vajra                          → service.go (daemon mode)
vajra scan [dir]               → detect.RunFullScan() blocking
                                  pre-counts eligible files for progress bar
                                  walks dir → Content Pipeline → FindingWriter
                                  then RunProcWalk (shares tracker)

vajra rules update             → job.RuleSyncer.RunOnce()
vajra rules status             → read-only file stat + local hash

vajra hashes update            → job.HashSyncer.RunOnce()
vajra hashes status            → read-only file stat + key mask

vajra secrets ignore <id>      → DetectionQueries.UpdateStatus(ctx, id, IGNORED, now)
vajra secrets export-ignore    → SecretQueries.ListIgnoredFingerprints(ctx)
                                  → writes SecretsSettings.IgnoreFile atomically

vajra config-write             → hidden; called by UI via pkexec
                                  reads full Config from disk
                                  merges stdin (JSON) onto it
                                  preserves DBDirectory, DBFilename
                                  writes YAML back atomically
```

---

## 10. UI — vajra-ui (Wails v2)

Separate binary. Read-only SQLite in WAL mode — no write lock contention with daemon.

```
User opens vajra-ui
  │
  ├── NewApp(cfgPath)
  │     LoadConfig → cfg cached in App struct
  │     OpenReadOnly(dbPath) → shared/db.DB
  │     queries.New(db)
  │
  ├── Wails runtime binds exported App methods to JS
  │
  └── React frontend (Vite, TypeScript, Tailwind)
        index.html blocking <script>
          reads localStorage('vajra-theme') or OS preference
          sets document.documentElement.data-theme BEFORE bundle loads
          (prevents flash-of-wrong-theme)
        App.tsx
          [theme, setTheme] — single source of truth for theme
          OS change listener → setTheme (not direct DOM mutation)
          Sidebar receives theme + onThemeChange props

Frontend pages → wailsjs bindings → App exported methods:

GetTotals()                    → queries.Totals()           → event_statistics
GetStatsByDateRange(s, e)      → queries.StatsByDateRange()  → event_statistics (int64 epochs)
GetDetections(page, pp, f)     → queries.Detections()        → detections (BeginTx pagination)
GetSecurityEvents(page, pp)    → queries.SecurityEvents()     → security_events
GetNetworkEvents(page, pp)     → queries.NetworkEvents()      → network_events
GetMemoryEvents(page, pp)      → queries.MemoryEvents()       → memory_events
GetAutoruns()                  → queries.Autoruns()           → autoruns
GetConfig()                    → configToUI(cached cfg)       → UIConfig (sensitive fields excluded)
WriteConfig(json)              → merge UIConfig onto full config
                                  → pkexec /opt/vajra/vajra config-write --config <path>
                                  → invalidate cfg cache
```

**Security boundary for config writes:**

```
vajra-ui (unprivileged)
  WriteConfig(json)
    │ exec
    ▼
pkexec (polkit auth dialog shown to user)
    │ runs as root if user authenticates
    ▼
vajra config-write (stdin = JSON)
  reads existing YAML
  merges incoming JSON (DBDirectory, DBFilename always from YAML)
  writes YAML atomically (mode 0o600)
```

The UI binary never runs as root. It never writes to the database. It never reads sensitive config fields (APIKey, DBDirectory, DBFilename are excluded from UIConfig).
