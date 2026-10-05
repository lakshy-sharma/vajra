# Dataflow

╔══════════════════════════════════════════════════════════════════════════════════╗
║                           KERNEL / SYSTEM LAYER                                  ║
║                                                                                  ║
║   execve  dup2/3  openat  connect  mmap  ptrace  capset  unshare  modules        ║
╚══════════════════════╦═══════════════════════════════════════════════════════════╝
                       │ eBPF tracepoints
                       ▼
╔══════════════════════════════════════════════════════════════════════════════════╗
║  EBPF LAYER  (internal/ebpf/)                                                    ║
║                                                                                  ║
║  Listener → perf ring buffer → deserialize() → RawEvent                         ║
║  Dispatcher → typed channels                                                     ║
║                                                                                  ║
║  Process  File  Network  Memory  Security  Module  Namespace  Dup                ║
╚══════════════════════╦═══════════════════════════════════════════════════════════╝
                       │
        ┌──────────────┼─────────────────────────────────┐
        ▼              ▼                                  ▼
╔══════════════╗  ╔════════════════════════════╗  ╔══════════════════╗
║  EVENTSINK   ║  ║  WATCHER LAYER             ║  ║  DUP WATCHER     ║
║              ║  ║  (internal/watcher/)       ║  ║                  ║
║  Consumes:   ║  ║                            ║  ║  Dup chan         ║
║  Network     ║  ║  FileScanner               ║  ║                  ║
║  Memory      ║  ║  File chan → eligible?      ║  ║  readlink oldfd  ║
║  Security    ║  ║  → QuickHash → SHA256       ║  ║  → socket inode? ║
║  Module      ║  ║  → Analyzer Pipeline        ║  ║  → /proc/net     ║
║  Namespace   ║  ║  → Finding                  ║  ║  → confirmed?    ║
║              ║  ║                            ║  ║  → Finding       ║
║  Raw record  ║  ║  ProcessScanner             ║  ║                  ║
║  only.       ║  ║  Process chan               ║  ║  pid+inode dedup ║
║  Bypasses    ║  ║  → process_tree write        ║  ║  30s window      ║
║  FindingWriter║  ║  → Content Pipeline         ║  ╚══════════════════╝
║              ║  ║  → Runtime Pipeline         ║          │
╚══════╦═══════╝  ║  → MergeResults()           ║          │
       │          ║  → Finding                  ║          │
       │          ╚═══════════╦════════════════╝          │
       │                      │                            │
       │          ╔═══════════╩════════════════╗          │
       │          ║  ANALYZER LAYER            ║          │
       │          ║  (internal/analyzer/)      ║          │
       │          ║                            ║          │
       │          ║  Content Pipeline          ║          │
       │          ║  (cached on SHA256)        ║          │
       │          ║  ┌──────────────────────┐  ║          │
       │          ║  │ HashAnalyzer (planned)│  ║          │
       │          ║  │ short-circuits CRIT  │  ║          │
       │          ║  ├──────────────────────┤  ║          │
       │          ║  │ YARAAnalyzer         │  ║          │
       │          ║  └──────────────────────┘  ║          │
       │          ║                            ║          │
       │          ║  Runtime Pipeline          ║          │
       │          ║  (never cached)            ║          │
       │          ║  ┌──────────────────────┐  ║          │
       │          ║  │ LDPreloadAnalyzer    │  ║          │
       │          ║  ├──────────────────────┤  ║          │
       │          ║  │ CapabilityAnalyzer   │  ║          │
       │          ║  ├──────────────────────┤  ║          │
       │          ║  │ LOLBinAnalyzer       │  ║          │
       │          ║  │ (process tree lookup)│  ║          │
       │          ║  └──────────────────────┘  ║          │
       │          ╚═══════════╦════════════════╝          │
       │                      │                            │
       │          ╔═══════════╩════════════════╗          │
       │          ║  SCANNER LAYER             ║          │
       │          ║  (internal/detect/)        ║          │
       │          ║                            ║          │
       │          ║  AutorunScanner            ║          │
       │          ║  SecretsScanner (planned)  ║          │
       │          ║  RunningProcessScanner     ║          │
       │          ║  (planned)                 ║          │
       │          ║  UserProfileScanner        ║          │
       │          ║  (planned)                 ║          │
       │          ╚═══════════╦════════════════╝          │
       │                      │                            │
       │              ┌───────┘        ────────────────────┘
       │              │       all watchers and scanners
       │              │       produce Finding
       │              ▼
       │  ╔═══════════════════════════════════════════════════════════╗
       │  ║  FINDING WRITER  (internal/findings/)                     ║
       │  ║                                                           ║
       │  ║  Write(ctx, Finding)                                      ║
       │  ║  ├── DedupTracker.CheckAndRecord(rule+path+severity)      ║
       │  ║  │   ├── duplicate → IncrementDedupCount, return 0        ║
       │  ║  │   └── new → continue                                   ║
       │  ║  ├── INSERT detections                                    ║
       │  ║  ├── if FileHash/YaraMatches → INSERT detection_artifacts ║
       │  ║  ├── if RemoteAddr → INSERT detection_network             ║
       │  ║  ├── if SecretHash → INSERT detection_secrets             ║
       │  ║  ├── if Extensions → INSERT detection_extensions (rows)   ║
       │  ║  └── if severity >= HIGH → captureEvidence()              ║
       │  ║       reads /proc/PID/fd, maps, environ, status           ║
       │  ║       INSERT evidence_snapshots                           ║
       │  ║                                                           ║
       │  ║  Metrics: Written, Deduped, Errors, Evidence, EvidFail    ║
       │  ║  LogMetrics() called by health ticker every 15 min        ║
       │  ╚═══════════════════════════════════════════════════════════╝
       │                      │
       ▼                      ▼
╔════════════════╗   ╔═════════════════════════════════════╗
║  RAW TELEMETRY ║   ║  DETECTION TABLES                   ║
║                ║   ║                                     ║
║  network_events║   ║  detections                         ║
║  memory_events ║   ║  detection_artifacts                ║
║  security_events║  ║  detection_network                  ║
║  process_tree  ║   ║  detection_secrets                  ║
║  (never pruned)║   ║  detection_extensions               ║
║                ║   ║  evidence_snapshots                 ║
╚════════════════╝   ╚═════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║  AUDIT LOG  (internal/db/queries/auditlog.go)                                    ║
║  Append-only. Every component writes on startup, shutdown, scan completion,      ║
║  rule update, health check, error. Never pruned by retention cleanup.            ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║  INVENTORY TABLES                                                                ║
║  autoruns ← AutorunScanner                                                       ║
║  user_inventory ← UserProfileScanner (planned)                                  ║
║  known_bad_hashes ← vajra hashes update + VirusTotal enrichment (planned)       ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║  SERVICE LAYER  (internal/service.go)                                            ║
║                                                                                  ║
║  wireAll()                                                                       ║
║  ├── bootstrap: LoadConfig → OpenDB → CompileRules → BuildPool → FindingWriter  ║
║  │                                                                               ║
║  ├── EventSink.Run(ctx, wg, channels)   [multi-channel, wired separately]       ║
║  ├── go DupWatcher.Run(ctx, wg, ch.Dup)                                         ║
║  ├── go FileScanner.Run(ctx, wg, ch.File)                                       ║
║  ├── go ProcessScanner.Run(ctx, wg, ch.Process)                                 ║
║  │                                                                               ║
║  ├── go AutorunScanner.Run(ctx, wg)                                             ║
║  │                                                                               ║
║  ├── go DBCleanup.Run(ctx, wg)                                                  ║
║  └── go RuleSyncer.Run(ctx, wg)                                                 ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║  CLI LAYER  (cmd/)                                                               ║
║                                                                                  ║
║  vajra [monitor]       → service.go daemon                                       ║
║  vajra scan [dir]      → detect.RunFullScan() blocking                           ║
║  vajra rules update    → job.RuleSyncer.RunOnce()                               ║
║  vajra rules status    → read-only DB query                                      ║
║  vajra hashes update   → planned                                                 ║
╚══════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════════╗
║  UI LAYER  (vajra-ui, separate Wails binary)                                     ║
║                                                                                  ║
║  Read-only SQLite (WAL mode, no write lock contention with daemon)               ║
║                                                                                  ║
║  Dashboard     → event_statistics + audit_log                                    ║
║  Alert list    → detections (all sources unified)                                ║
║  Alert detail  → detections JOIN artifacts + network + evidence                  ║
║  Process tree  → process_tree recursive CTE                                      ║
║  Autorun view  → autoruns                                                        ║
║  Secret view   → detection_secrets JOIN detections                               ║
╚══════════════════════════════════════════════════════════════════════════════════╝
