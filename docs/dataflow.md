╔══════════════════════════════════════════════════════════════════════════════════╗
║                           KERNEL / SYSTEM LAYER                                  ║
║                                                                                  ║
║   execve  dup2  openat  connect  mmap  ptrace  capset  unshare  modules          ║
╚══════════════════════╦═══════════════════════════════════════════════════════════╝
                       │ eBPF tracepoints
                       ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                         EBPF LAYER  (internal/ebpf/)                             ║
║                                                                                  ║
║   Listener                                                                       ║
║   └── perf ring buffer read loop                                                 ║
║       └── deserialize() → RawEvent{Type, Data}                                  ║
║                                                                                  ║
║   Dispatcher                                                                     ║
║   └── route() → typed channels                                                   ║
║                                                                                  ║
║   Channels                                                                       ║
║   ├── Process  chan ProcessEvent                                                  ║
║   ├── File     chan FileEvent                                                     ║
║   ├── Network  chan NetworkEvent                                                  ║
║   ├── Memory   chan MmapEvent                                                     ║
║   ├── Security chan SecurityEvent                                                 ║
║   ├── Module   chan ModuleEvent                                                   ║
║   ├── Namespace chan NamespaceEvent                                               ║
║   └── Dup      chan DupEvent                                                      ║
╚══════════════════════╦═══════════════════════════════════════════════════════════╝
                       │
        ┌──────────────┼──────────────────────────────────┐
        │              │                                   │
        ▼              ▼                                   ▼
╔═══════════════╗ ╔═══════════════════════════╗ ╔════════════════════╗
║   WATCHER     ║ ║        WATCHER            ║ ║      WATCHER       ║
║   LAYER       ║ ║        LAYER              ║ ║      LAYER         ║
║               ║ ║                           ║ ║                    ║
║  EventSink    ║ ║  FileScanner   Process    ║ ║   DupWatcher       ║
║               ║ ║                Scanner    ║ ║                    ║
║  Consumes:    ║ ║  Consumes:     Consumes:  ║ ║  Consumes:         ║
║  Network      ║ ║  File chan     Process    ║ ║  Dup chan          ║
║  Memory       ║ ║               chan        ║ ║                    ║
║  Security     ║ ║                           ║ ║  For each event:   ║
║  Module       ║ ║  For each event:          ║ ║  readlink oldfd    ║
║  Namespace    ║ ║  filter→eligible          ║ ║  → socket inode?   ║
║               ║ ║  →QuickHash              ║ ║  → /proc/net lookup║
║  Raw record   ║ ║  →SHA256                 ║ ║  → confirmed?      ║
║  only. No     ║ ║  → Analyzer              ║ ║                    ║
║  analysis.    ║ ║    Pipeline              ║ ║  pid+inode dedup   ║
║  Heuristic    ║ ║  → dedup                 ║ ║  30s window        ║
║  severity.    ║ ║  → Finding               ║ ║  → Finding         ║
╚═══════════════╝ ╚═══════════╦═══════════════╝ ╚═════════╦══════════╝
        │                     │                            │
        │                     ▼                            │
        │         ╔═══════════════════════════╗            │
        │         ║    ANALYZER LAYER         ║            │
        │         ║    (internal/analyzer/)   ║            │
        │         ║                           ║            │
        │         ║  Content Pipeline         ║            │
        │         ║  (cached on SHA256)       ║            │
        │         ║  ┌─────────────────────┐  ║            │
        │         ║  │ HashAnalyzer        │  ║            │
        │         ║  │ (known_bad_hashes)  │  ║            │
        │         ║  │ short-circuits on   │  ║            │
        │         ║  │ CRITICAL match      │  ║            │
        │         ║  ├─────────────────────┤  ║            │
        │         ║  │ YARAAnalyzer        │  ║            │
        │         ║  │ (pool → rules)      │  ║            │
        │         ║  └─────────────────────┘  ║            │
        │         ║                           ║            │
        │         ║  Runtime Pipeline         ║            │
        │         ║  (never cached,           ║            │
        │         ║   always runs)            ║            │
        │         ║  ┌─────────────────────┐  ║            │
        │         ║  │ LDPreloadAnalyzer   │  ║            │
        │         ║  ├─────────────────────┤  ║            │
        │         ║  │ CapabilityAnalyzer  │  ║            │
        │         ║  ├─────────────────────┤  ║            │
        │         ║  │ LOLBinAnalyzer      │  ║            │
        │         ║  │ (process tree       │  ║            │
        │         ║  │  parent lookup)     │  ║            │
        │         ║  └─────────────────────┘  ║            │
        │         ║                           ║            │
        │         ║  → MergeResults()         ║            │
        │         ║  → Finding                ║            │
        │         ╚═══════════════════════════╝            │
        │                     │                            │
        │              ┌──────┘                            │
        │              │                                   │
        │              ▼                                   │
        │  ╔═══════════════════════════════════════════╗   │
        │  ║         SCANNER LAYER                     ║   │
        │  ║         (internal/scanner/)               ║   │
        │  ║                                           ║   │
        │  ║  Pull-based, timer or startup triggered   ║   │
        │  ║                                           ║   │
        │  ║  AutorunScanner                           ║   │
        │  ║  ├── walks 12 persistence locations       ║   │
        │  ║  ├── diffs against DB state               ║   │
        │  ║  └── → Finding (new/changed entries)      ║   │
        │  ║                                           ║   │
        │  ║  SecretsScanner                           ║   │
        │  ║  ├── walks filesystem (text files)        ║   │
        │  ║  ├── betterleaks v2 SDK per file          ║   │
        │  ║  ├── sha256(secret) — never store raw     ║   │
        │  ║  └── → Finding                            ║   │
        │  ║                                           ║   │
        │  ║  RunningProcessScanner                    ║   │
        │  ║  ├── walks /proc/PID/exe on startup       ║   │
        │  ║  ├── submits to Analyzer pipeline         ║   │
        │  ║  └── → Finding                            ║   │
        │  ║                                           ║   │
        │  ║  UserProfileScanner                       ║   │
        │  ║  ├── reads passwd/shadow/sudoers/ssh keys ║   │
        │  ║  ├── diffs against user_inventory         ║   │
        │  ║  └── → Finding (policy violations)        ║   │
        │  ╚═══════════════════════════════════════════╝   │
        │                     │                            │
        └──────────┬───────────┘────────────────────────── ┘
                   │ all sources produce Finding
                   ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║                      FINDING WRITER  (internal/findings/)                        ║
║                                                                                  ║
║  FindingWriter.Write(ctx, Finding)                                               ║
║  │                                                                               ║
║  ├── DedupTracker.CheckAndRecord(source+rule_id+target_path+severity)            ║
║  │   ├── duplicate within window → IncrementDedupCount, return                  ║
║  │   └── new → continue                                                          ║
║  │                                                                               ║
║  ├── INSERT detections (core fields)                                             ║
║  │                                                                               ║
║  ├── if YaraMatches or FileHash present                                          ║
║  │   └── INSERT detection_artifacts (detection_id FK)                           ║
║  │                                                                               ║
║  ├── if network socket details present                                           ║
║  │   └── INSERT detection_network (detection_id FK)                             ║
║  │                                                                               ║
║  ├── if secrets details present                                                  ║
║  │   └── INSERT detection_secrets (detection_id FK)                             ║
║  │                                                                               ║
║  ├── if extra fields present                                                     ║
║  │   └── INSERT detection_extensions key/value (detection_id FK)                ║
║  │                                                                               ║
║  └── if severity >= HIGH                                                         ║
║      └── trigger EvidenceCollector                                               ║
╚══════════════════════╦═══════════════════════════════════════════════════════════╝
                       │
        ┌──────────────┼──────────────────────────┐
        │              │                          │
        ▼              ▼                          ▼
╔══════════════╗ ╔════════════════╗  ╔════════════════════════════╗
║  DETECTIONS  ║ ║    EVIDENCE    ║  ║       RAW TELEMETRY        ║
║  DB TABLES   ║ ║   COLLECTOR    ║  ║       DB TABLES            ║
║              ║ ║                ║  ║                            ║
║  detections  ║ ║  On HIGH/CRIT  ║  ║  network_events            ║
║  detection   ║ ║  immediately   ║  ║  memory_events             ║
║_artifacts  ║ ║  reads:        ║  ║  security_events           ║
║  detection   ║ ║  /proc/PID/    ║  ║  process_tree              ║
║  _network    ║ ║  ├── fd/       ║  ║                            ║
║  detection   ║ ║  ├── maps      ║  ║  (written by EventSink     ║
║_secrets    ║ ║  ├── environ   ║  ║   directly, not via        ║
║  detection   ║ ║  └── status    ║  ║   FindingWriter)           ║
║  _extensions ║ ║                ║  ╚════════════════════════════╝
║              ║ ║  Serializes    ║
║              ║ ║  to JSON blob  ║
║              ║ ║                ║
║              ║ ║  INSERT        ║
║              ║ ║  evidence_     ║
║              ║ ║  snapshots     ║
║              ║ ║  (FK →         ║
║              ║ ║  detection_id) ║
╚══════════════╝ ╚════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║                    AUDIT LOG  (written by all components)                        ║
║                                                                                  ║
║  Every component writes to audit_log on:                                         ║
║  ├── startup / shutdown                                                          ║
║  ├── scan completion (files scanned, duration, hits)                             ║
║  ├── rule/signature update                                                       ║
║  ├── health check (every 15 min — pool workers, queue depth, uptime)            ║
║  └── error conditions                                                            ║
║                                                                                  ║
║  audit_log is append-only. Never updated, never deleted by retention cleanup.   ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║               INVENTORY TABLES  (written by scanners)                            ║
║                                                                                  ║
║  autoruns        ← AutorunScanner                                                ║
║  user_inventory  ← UserProfileScanner                                           ║
║  known_bad_hashes ← vajra hashes update CLI + VirusTotal enrichment             ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║                    OPERATIONAL TABLES                                            ║
║                                                                                  ║
║  quarantined_files  ← Response system (Phase 5)                                  ║
║  event_statistics   ← Aggregation job (hourly ticker)                            ║
║  sync_state         ← Remote sync watermarks (Phase 3)                          ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║                         SERVICE LAYER  (internal/service.go)                     ║
║                                                                                  ║
║  wireJobs()                                                                      ║
║  │                                                                               ║
║  ├── bootstrap: LoadConfig → OpenDB → CompileRules → BuildPool                  ║
║  │                                                                               ║
║  ├── watchers := []watcher.Watcher{                                              ║
║  │     EventSink, FileScanner, ProcessScanner, DupWatcher                       ║
║  │   }                                                                           ║
║  │   for w := range watchers { go w.Run(ctx, wg) }                              ║
║  │                                                                               ║
║  ├── scanners := []scanner.Scanner{                                              ║
║  │     AutorunScanner, SecretsScanner,                                           ║
║  │     RunningProcessScanner, UserProfileScanner                                 ║
║  │   }                                                                           ║
║  │   for s := range scanners { go s.Run(ctx, wg) }                              ║
║  │                                                                               ║
║  └── jobs := []job.Job{                                                          ║
║        DBCleanup, RuleSyncer, AggregationJob, HealthTicker                      ║
║      }                                                                           ║
║      for j := range jobs { go j.Run(ctx, wg) }                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║                         CLI LAYER  (cmd/)                                        ║
║                                                                                  ║
║  vajra                → service.go (daemon, all watchers+scanners+jobs)          ║
║  vajra scan [dir]     → RunFullScan (blocking, file scanner only)                ║
║  vajra rules update   → RuleSyncer.RunOnce()                                    ║
║  vajra rules status   → read-only DB query                                       ║
║  vajra hashes update  → HashUpdater.RunOnce()  (planned)                        ║
║  vajra audit          → AuditRunner.Run()      (planned)                        ║
║  vajra profile        → UserProfileScanner.RunOnce() (planned)                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║                         UI LAYER  (vajra-ui, separate binary)                    ║
║                                                                                  ║
║  Read-only SQLite (WAL mode, no write lock contention)                           ║
║                                                                                  ║
║  Dashboard     → event_statistics + audit_log                                    ║
║  Alert list    → detections (single table, all sources)                          ║
║  Alert detail  → detections JOIN detection_artifacts                             ║
║                           JOIN detection_network                                 ║
║                           JOIN evidence_snapshots                                ║
║  Process tree  → process_tree recursive CTE                                      ║
║  Autorun view  → autoruns                                                        ║
║  User profile  → user_inventory                                                  ║
║  Secret view   → detection_secrets JOIN detections                               ║
╚══════════════════════════════════════════════════════════════════════════════════╝
