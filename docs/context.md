# Vajra EDR — Architecture and Context

Updated: October 2026

---

## What Vajra Is

Vajra is a Linux endpoint detection and response agent. It has three independent binaries:

- **`vajra`** (daemon) — Go binary that loads eBPF programs, consumes kernel events, runs detection pipelines, and writes to SQLite.
- **`vajra-ui`** (desktop UI) — Wails v2 binary that opens the SQLite database read-only and presents detection data in a React/TypeScript interface.
- **`vajra`** (CLI mode) — same binary as the daemon; subcommands (`scan`, `rules`, `hashes`, `secrets`) are CLI entry points.

The daemon and UI are separate processes sharing one WAL-mode SQLite database. The UI never writes event data — config writes go through `pkexec → vajra config-write` so the UI does not need root.

---

## Directory Structure

```
vajra/
├── daemon/                    Go module — the daemon
│   ├── cmd/                   Cobra CLI subcommands
│   │   ├── root.go            persistent --config flag
│   │   ├── scan.go            vajra scan [dir]
│   │   ├── rules.go           vajra rules update/status
│   │   ├── hashes.go          vajra hashes update/status
│   │   └── secrets.go         vajra secrets ignore/export-ignore
│   ├── internal/
│   │   ├── analyzer/          stateless detection functions
│   │   │   ├── analyzer.go    Pipeline, ResultCache, context helpers
│   │   │   ├── capability.go  Linux capability analysis
│   │   │   ├── hash.go        Bloom filter lookup
│   │   │   ├── ldpreload.go   LD_PRELOAD injection detection
│   │   │   └── yara.go        YARA worker pool submission
│   │   ├── db/
│   │   │   ├── open.go        schema migration, WAL setup
│   │   │   └── queries/       one file per table group
│   │   ├── detect/            pull-based scanners
│   │   │   ├── autorun/       12 persistence categories
│   │   │   ├── fullscan.go    CLI full filesystem scan
│   │   │   ├── procwalk.go    /proc walk on startup
│   │   │   └── secrets.go     betterleaks integration
│   │   ├── ebpf/              eBPF loader and dispatcher
│   │   │   ├── c/             C source (ebpf_events.c, vmlinux.h)
│   │   │   ├── types.go       Go mirrors of C structs, Channels
│   │   │   ├── listener.go    loads BPF objects, attaches tracepoints
│   │   │   └── dispatcher.go  RawEvent → typed channels
│   │   ├── findings/          unified detection output
│   │   │   ├── finding.go     Finding struct
│   │   │   └── writer.go      FindingWriter, dedup, evidence capture
│   │   ├── job/               utility goroutines (no detection role)
│   │   │   ├── cleanup.go     DB retention
│   │   │   ├── hashsync.go    MalwareBazaar Bloom filter build
│   │   │   ├── rulesync.go    YARA Forge rule update
│   │   │   └── statsync.go    event_statistics aggregation
│   │   ├── scanner/yara/      YARA pool, compiler, match conversion
│   │   │   ├── pool.go        bounded worker pool with autotune
│   │   │   ├── compiler.go    zip extract + rule compilation
│   │   │   └── match.go       RuleMatch adapter, ConvertMatches
│   │   ├── utilities/         shared helpers, no detection logic
│   │   │   ├── clock.go       SystemInfo, BootEpoch, EBPF→Unix
│   │   │   ├── dedup.go       DedupTracker
│   │   │   ├── exec.go        HasExecutableMagic
│   │   │   ├── filter.go      ExclusionFilter, ProcessFilter, RecentScanTracker
│   │   │   ├── hasher.go      QuickHash, FullSHA256, StatFile
│   │   │   ├── logging.go     GetLogger, rolling file writer
│   │   │   ├── procfs.go      ReadProcStatus, ReadCmdline
│   │   │   ├── severity.go    ClassifySeverity, SeverityRank, RuleMatch interface
│   │   │   └── split.go       NullScanner bufio.SplitFunc
│   │   └── watcher/           push-based event consumers
│   │       ├── dupwatcher.go  dup2/dup3 reverse shell detection
│   │       ├── eventsink.go   raw telemetry → DB
│   │       ├── filescanner.go file events → content pipeline
│   │       └── processscanner.go  execve → process tree + pipelines
│   ├── internal/              service wiring
│   │   ├── service.go         wireAll(), startServiceMode()
│   │   └── entrypoint.go      config load, DB open, app_config seed
│   └── main.go
├── shared/                    shared Go types (importable by daemon + ui)
│   ├── config/                Config struct, LoadConfig, SaveConfig
│   ├── db/                    DB wrapper, DBConn interface
│   └── models/                all DB row structs
└── ui/                        Wails desktop UI
    ├── app.go                 Wails backend, all exported methods
    ├── main.go                Wails window config
    ├── internal/queries/      read-only query layer for UI
    └── frontend/src/
        ├── App.tsx            theme state (single source of truth)
        ├── components/        Sidebar, Pagination, SeverityBadge
        └── pages/             Dashboard, Detections, Events, Autoruns, Settings
```

---

## Execution Models — Why Three Abstractions

The daemon has three distinct kinds of goroutines. Conflating them was the root cause of most structural problems in the original codebase.

### Watcher — push-based, channel-driven

Blocks on a channel until `ctx` is cancelled. Reacts to events the eBPF dispatcher pushes.

```
FileScanner     — ch.File   → content pipeline → FindingWriter
ProcessScanner  — ch.Process → process_tree + pipelines → FindingWriter
DupWatcher      — ch.Dup    → socket lookup → FindingWriter
EventSink       — ch.Network + ch.Memory + ch.Security + ch.Module → raw telemetry tables
```

`EventSink` is not wired through the `Watcher` interface because it consumes multiple channels simultaneously. Forcing it through a single `Run(ctx, wg)` would hide a four-way channel fan-out inside a struct, breaking the principle that each watcher has its channel dependency injected at construction time.

### Scanner — pull-based, timer or startup

Walks a data source on a configurable interval or once at startup.

```
AutorunScanner       — walks 12 persistence categories, diffs against DB
SecretsScanner       — betterleaks v2, path segment prefilter
RunProcWalk          — /proc walk, runs once at startup then on demand
```

All scanners produce `Finding → FindingWriter`. They have no eBPF dependency.

### Job — utility goroutine, no detection role

```
Cleanup     — prunes stale DB rows
RuleSyncer  — checks YARA Forge for new releases
HashSyncer  — rebuilds Bloom filter from MalwareBazaar CSV
StatSyncer  — aggregates raw telemetry into event_statistics
```

Jobs write only to their own tables. They never produce Findings.

---

## Why Analyzer Is Separate from Watcher/Scanner

Analyzers are stateless functions: path in, result out. They compose into pipelines, cache on SHA256, and short-circuit on CRITICAL. They have no lifecycle — no goroutine, no channel, no timer.

Watchers and Scanners have lifecycle. They own goroutines. They produce Findings.

Mixing them would mean either giving Analyzers artificial lifecycle or giving Watchers the pipeline composition logic. The boundary: Analyzers are called by Watchers and Scanners, never the reverse.

### Pipeline composition

```
Content Pipeline (cached on SHA256 — same binary not re-scanned)
HashAnalyzer → CRITICAL hit short-circuits, YARA skipped
YARAAnalyzer → YARA Forge ruleset via autotuning worker pool

Runtime Pipeline (never cached — reads live /proc state)
LDPreloadAnalyzer → /proc/PID/environ — LD_PRELOAD outside trusted paths
CapabilityAnalyzer → /proc/PID/status — dangerous capability bits
LOLBinAnalyzer [planned] → cmdline patterns + process_tree parent lookup
```

### Why RuleMatch is an interface in utilities/

Severity classification was originally YARA-specific. Moving to a `RuleMatch` interface means betterleaks findings, hash lookup results, and YARA matches all implement it via `RuleID()` and `RuleTags()`. The YARA Forge naming convention (APT_, MALWARE_, HKTL_, SUSP_) becomes the shared vocabulary. Any engine following it gets `ClassifySeverity` for free.

---

## Why FindingWriter Is the Single DB Insertion Point

Before the refactor, each scanner had its own insert path and dedup logic. FindingWriter enforces:

- One dedup implementation (`DedupTracker`, keyed on `rule_id + target_path + severity`)
- One schema for all sources (detections + extension tables)
- Evidence capture triggered in one place (HIGH/CRITICAL → `/proc` snapshot)
- Metrics tracked in one place

The cost: every detection source must produce a `Finding`. This is correct — it means each source only knows what it detected, not how to store it.

---

## Why EventSink Bypasses FindingWriter

EventSink records everything including noise: every DNS query, every outbound connection, every ptrace call. Running them through FindingWriter would create millions of CLEAN detection rows. The distinction:

- **FindingWriter** — anomalies only. Never writes CLEAN rows.
- **EventSink** — forensic completeness. Writes everything.

---

## Why the Schema Has Extension Tables, Not a `details JSON` Column

A single `details TEXT` JSON column becomes a dumping ground. Extension tables instead:

- `detection_artifacts` — file hash + YARA matches (file/process detections only)
- `detection_network` — socket details (reverse shell detections only)
- `detection_secrets` — betterleaks findings (secrets scanner only)
- `detection_extensions` — key/value rows, one per field, indexed on key

The last is the escape hatch for source-specific fields that don't warrant a dedicated column. Each key gets its own row so `WHERE key='autorun_category' AND value='systemd_system'` is index-assisted.

---

## Why process_tree Is Never Pruned

A single missing execve row creates a hole in the ancestry chain that breaks recursive CTE traversal, LOLBin parent context lookup, and behavioral correlation. Retention cleanup touches `detections` (resolved only) and raw telemetry (age-based). It never touches `process_tree`.

---

## Why HashAnalyzer Uses a Bloom Filter

A SQLite lookup per file under vajra's single-connection model would create lock contention and disk I/O on the hot path. A Bloom filter at 5M capacity / 1% FP rate is ~4 MB in memory, loaded once at startup, and answers in microseconds with zero I/O.

False positives mean YARA runs on a clean file — acceptable overhead. False negatives are impossible. The filter is built offline by HashSyncer from the MalwareBazaar CSV and written to disk. The daemon loads it at startup and never writes to it.

---

## Why the LDPreload Analyzer Uses a Whitelist

The set of legitimate library directories is small and stable: `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/usr/local/lib`, `/usr/local/lib64`. The set of attacker-controlled paths is unbounded. A whitelist (TrustedLDPaths) is correct. A blacklist (SuspiciousLDPaths) was wrong and included `/snap/` — a FUSE mount any user can write into.

---

## Why the Secrets Ignore List Is File-Based

betterleaks' `scan.WithIgnoredFingerprints` must be passed at scanner construction time — there is no way to add fingerprints to a running scanner. The file is loaded once at `NewSecretsScanner`. Live reload is deferred to Phase 4.

---

## DBConn Interface

Every query function in the daemon and UI query layers accepts `shareddb.DBConn`, not `*sql.DB`. This is the single most enforced invariant:

```go
type DBConn interface {
    ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
    QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
    QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
    BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}
```

`*sql.DB`, `*sql.Tx`, and test doubles all satisfy it. No query function calls `time.Now()` — `now int64` is always passed by the caller.

---

## eBPF Tracepoints

| Tracepoint | Go type | Notes |
|---|---|---|
| sys_enter_execve | ProcessEvent | cmdline read from /proc in Go |
| sys_enter_setuid/setgid | ProcessEvent | |
| sys_enter_memfd_create | ProcessEvent | |
| sys_enter_ptrace | PtraceEvent → SecurityEvent | |
| sys_enter_mmap/mprotect | MmapEvent | PROT_EXEC only |
| sys_enter_capset | CapsetEvent → SecurityEvent | |
| sys_enter_dup2/dup3 | DupEvent | newfd ≤ 2, kernel-side filter |
| sys_enter_openat | FileEvent | O_CREAT only |
| sys_enter_unlinkat/renameat2/fchmodat | FileEvent | |
| sys_enter_connect/bind | NetworkEvent | AF_INET/AF_INET6 only |
| sys_enter_socket | NetworkEvent | SOCK_RAW/SOCK_PACKET only |
| sys_enter_sendto/sendmsg | dnsEventRaw | port 53 only |
| sys_enter_init_module/finit_module | ModuleEvent | name always empty (bpf_d_path unavailable) |
| sys_enter_unshare/setns | NamespaceEvent → SecurityEvent | |

RawEvent is a union struct (one field per event type) — no `interface{}` boxing, no heap allocation per event in the perf buffer loop.

---

## Config-Driven Detection Policy

All tunable detection lists live in `AlertPolicySettings`. Nothing is hardcoded in Go source:

- `Interpreters` — shell/scripting runtimes that trigger file scanning
- `LOLBins` — living-off-the-land binaries
- `DangerousCapabilities` — Linux capability names that warrant HIGH/CRITICAL
- `ProcessCapabilityExclusions` — per-comm exclusions (e.g. openvpn: CAP_NET_ADMIN)
- `HighValueInboundPorts` / `HighValueOutboundPorts` — network severity triggers
- `TrustedLDPaths` — whitelist for LD_PRELOAD/LD_LIBRARY_PATH

---

## UI Architecture

The Wails desktop app is a separate binary. It reads the SQLite database in WAL read-only mode — no write lock contention with the daemon.

```
vajra-ui
├── app.go           backend — all exported methods become JS-callable bindings
├── main.go          Wails window config (size, MinWidth/MinHeight, BackgroundColour from config)
└── ui/internal/queries/   read-only query layer
    ├── queries.go         DBConn wrapper, bg() helper
    ├── dashboard.go       Totals(), StatsByDateRange(startUnix, endUnix int64)
    ├── detections.go      Detections() with BeginTx pagination
    ├── events.go          SecurityEvents, NetworkEvents, MemoryEvents
    └── autoruns.go        Autoruns() — table: autoruns
```

Theme is managed as a single source of truth in `App.tsx` — `[theme, setTheme]` state, applied to `document.documentElement.setAttribute('data-theme', ...)` via useEffect, persisted to localStorage. Sidebar receives `theme` + `onThemeChange` as props. A blocking `<script>` in `index.html` reads localStorage before the React bundle loads to prevent the flash-of-wrong-theme.

Config writes: `WriteConfig(json)` → merge UIConfig onto full on-disk config → pipe to `pkexec /opt/vajra/vajra config-write`. The UI never needs root itself.
