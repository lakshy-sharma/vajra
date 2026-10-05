# Project Layout

internal/
├── utilities/
│   ├── clock.go              # SystemInfo, LoadSystemInfo, EBPFTimestampToUnix
│   ├── config.go             # Config struct, LoadConfig, applyDefaults
│   ├── logging.go            # GetLogger, lumberjack rolling file
│   ├── detectionlists.go     # KnownInterpreters
│   ├── dedup.go              # DedupTracker — generic TTL cache, no scanner dependency
│   ├── filter.go             # ExclusionFilter, ProcessFilter, RecentScanTracker
│   ├── hasher.go             # QuickHash, FullSHA256, HashFile, StatFile
│   └── severity.go           # RuleMatch interface, ClassifySeverity
│
├── scanner/
│   └── yara/
│       ├── pool.go           # YARA worker pool, autotune, ScanFunc
│       ├── compiler.go       # ExtractRules, CompileRules — was scanner/yara.go
│       └── match.go          # YaraMatch implements RuleMatch, convertMatches
│
├── analyzer/
│   ├── analyzer.go           # Analyzer interface, Pipeline, ResultCache, MergeResults, PID context
│   ├── yara.go               # YARAAnalyzer — wraps pool, implements Analyzer
│   ├── ldpreload.go          # LDPreloadAnalyzer — was procanalyzer/ldpreload.go
│   └── capability.go         # CapabilityAnalyzer — was procanalyzer/capability.go
│
├── watcher/
│   ├── watcher.go            # Watcher interface
│   ├── eventsink.go          # EventSink — network/memory/security/module → DB
│   ├── filescanner.go        # FileScanner — eBPF file events → analyzer pipeline
│   ├── processscanner.go     # ProcessScanner — eBPF process events → pipelines
│   └── dupwatcher.go         # DupWatcher — dup2/dup3 events → socket check → DB
│
├── detect/
│   ├── scanner.go            # Scanner interface
│   ├── autorun/
│   │   ├── autorun.go        # Scanner, Diff, RunAutorunScan
│   │   └── sources_linux.go  # All 12 Linux persistence sources
│   └── fullscan.go           # RunFullScan — blocking walk for vajra scan CLI
│
├── job/
│   ├── job.go                # Job interface
│   ├── cleanup.go            # DBCleanup — retention job
│   └── rulesync.go           # RuleSyncer — YARA Forge tag check and update
│
├── findings/
│   ├── finding.go            # Finding struct — unified detection output
│   └── writer.go             # FindingWriter — dedup, DB insert, evidence trigger
│
├── ebpf/
│   ├── c/ebpf_events.c
│   ├── types.go
│   ├── listener.go
│   └── dispatcher.go
│
└── db/
    ├── db.go
    └── queries/
        ├── autoruns.go
        ├── cleanup.go
        ├── detections.go     # new
        ├── artifacts.go      # new
        ├── secrets.go        # new
        ├── extensions.go     # new
        ├── evidence.go       # new
        ├── auditlog.go       # new
        ├── files.go          # kept — raw telemetry
        ├── memory.go         # kept — raw telemetry
        ├── network.go        # kept — raw telemetry
        ├── processes.go      # kept — raw telemetry
        ├── processtree.go    # kept
        └── security.go       # kept — raw telemetry
