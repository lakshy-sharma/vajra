# Project Layout

workspace/src/
├── internal/
│   │
│   ├── utilities/                    Generic infrastructure, no detection logic
│   │   ├── clock.go                  SystemInfo, LoadSystemInfo, EBPFTimestampToUnix
│   │   ├── config.go                 Config struct, LoadConfig, applyDefaults
│   │   ├── logging.go                GetLogger, lumberjack rolling file
│   │   ├── detectionlists.go         KnownInterpreters — file scan eligibility only
│   │   ├── dedup.go                  DedupTracker — generic TTL cache
│   │   ├── filter.go                 ExclusionFilter, ProcessFilter, RecentScanTracker
│   │   ├── hasher.go                 QuickHash, FullSHA256, HashFile, StatFile
│   │   └── severity.go               RuleMatch interface, ClassifySeverity
│   │
│   ├── scanner/
│   │   └── yara/                     YARA engine — not generic, lives here not utilities/
│   │       ├── pool.go               Worker pool, load-aware autotune
│   │       ├── compiler.go           ExtractRules, CompileRules
│   │       └── match.go              YaraMatch implements RuleMatch
│   │
│   ├── analyzer/                     Stateless path→result stages, composable into pipelines
│   │   ├── analyzer.go               Analyzer interface, Pipeline, ResultCache, MergeResults
│   │   ├── yara.go                   YARAAnalyzer — wraps pool
│   │   ├── ldpreload.go              LDPreloadAnalyzer — /proc/PID/environ
│   │   └── capability.go             CapabilityAnalyzer — /proc/PID/status CapEff
│   │
│   ├── watcher/                      Push-based, consume eBPF channels, produce Findings
│   │   ├── watcher.go                Watcher interface — Name() + Run(ctx, wg)
│   │   ├── eventsink.go              Raw telemetry only — bypasses FindingWriter by design
│   │   ├── filescanner.go            eBPF file events → analyzer pipeline → FindingWriter
│   │   ├── processscanner.go         eBPF process events → pipelines → FindingWriter
│   │   └── dupwatcher.go             dup2/dup3 → socket check → FindingWriter
│   │
│   ├── detect/                       Pull-based, walk data sources, produce Findings
│   │   ├── scanner.go                Scanner interface — Name() + Run(ctx, wg)
│   │   ├── fullscan.go               Blocking walk for vajra scan CLI
│   │   └── autorun/
│   │       ├── autorun.go            Scanner, Diff, persistence state management
│   │       └── sources_linux.go      All 12 Linux persistence sources
│   │
│   ├── job/                          Utility goroutines — no detection role
│   │   ├── job.go                    Job interface — Name() + Run(ctx, wg)
│   │   ├── cleanup.go                DB retention cleanup
│   │   └── rulesync.go               YARA Forge tag check and update
│   │
│   ├── findings/                     Unified detection output and persistence
│   │   ├── finding.go                Finding struct — produced by all watchers and scanners
│   │   └── writer.go                 FindingWriter — dedup, DB routing, evidence capture
│   │
│   ├── ebpf/                         Kernel interface — never imported by detection logic
│   │   ├── c/ebpf_events.c           BPF C program
│   │   ├── types.go                  Event structs, Channels, constants
│   │   ├── listener.go               BPF load, tracepoint attach, perf read loop
│   │   └── dispatcher.go             RawEvent → typed channels
│   │
│   └── db/
│       ├── db.go                     Open, OpenReadOnly, migrate, pragmas
│       └── queries/
│           ├── detections.go         Insert, IncrementDedup, ListBySeverity, DeleteResolvedBefore
│           ├── artifacts.go          Insert, GetByDetectionID
│           ├── network_detection.go  Insert, GetByDetectionID
│           ├── secrets.go            Insert, ListBySecretHash
│           ├── extensions.go         Insert, InsertAll, GetByDetectionID
│           ├── evidence.go           Insert, GetByDetectionID
│           ├── auditlog.go           Insert, ListByComponent
│           ├── autoruns.go           Insert, MarkInactive, UpdateLastSeen, LoadActive
│           ├── cleanup.go            RunCleanup — detections + network + memory
│           ├── processtree.go        Insert, GetByPID
│           ├── network.go            Insert, ListByDstPort — raw telemetry
│           ├── memory.go             Insert, ListByPID — raw telemetry
│           └── security.go           Insert, ListCritical — raw telemetry
│
├── entrypoint.go                     Config load, directory setup, mode dispatch
├── service.go                        wireAll — bootstrap + watcher + scanner + job wiring
│
└── shared/
    └── models/
        └── models.go                 All DB structs — Detection, Finding, ProcessTreeEntry etc

cmd/
├── root.go                           Cobra root, --config persistent flag
├── rules.go                          vajra rules update / vajra rules status
└── scan.go                           vajra scan [directory]
