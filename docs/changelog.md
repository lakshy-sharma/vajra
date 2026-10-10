# Vajra EDR — Changelog

## [0.0.2] — 2026-10-10

### Architecture & Shared Layer

- **DBConn interface** (`shared/db`) — removed `SQL()` method; all callers receive `DBConn` only, never `*sql.DB`. Prevents leaking the full `database/sql` surface to query packages.
- **WAL verification** — `ping()` now checks that `PRAGMA journal_mode` actually returned `wal`; fails loud on network filesystems.
- **DSN path encoding** — `url.PathEscape` applied to all SQLite DSN paths; fixes open failures on directories with spaces or brackets.
- **Write pool constraints** — `SetMaxOpenConns(1)`, `SetMaxIdleConns(1)` enforced on write connections to prevent WAL writer contention.
- **`busy_timeout=5000`** — serialises concurrent writers for up to 5 seconds before returning `SQLITE_BUSY`.
- **`OpenReadOnly`** — now applies the same pragma set as `Open`; was previously missing `foreign_keys`, `busy_timeout`, and `synchronous`.

### Config (`shared/config`)

- **`APIServerSettings` removed** — was exposing a management HTTP API on the LAN with no auth; removed entirely.
- **`AlertPolicySettings` added** — all previously hardcoded detection lists (`KnownInterpreters`, `dangerousCapabilities`, `highValuePorts`, `standardLibPaths`) moved here; operators can tune without recompiling.
- **`TrustedLDPaths` replaces `SuspiciousLDPaths`** — whitelist model is correct; blacklist model was wrong and had `/snap/` as a trusted path which is attacker-writable. Snap paths removed from defaults.
- **`ResultCacheSize`** added to `PerformanceSettings`; backed by `hashicorp/golang-lru/v2` LRU in the analyzer.
- **`AutorunConcurrency`** added to `PerformanceSettings`; default 2; controls errgroup semaphore in autorun scanner.
- **`UISettings`** added — `DefaultTheme`, `WindowWidth`, `WindowHeight`, `MinWindowWidth`, `MinWindowHeight`, `PageSize`.
- **Validation** (`Validate()`) — returns a joined error listing all violations in one pass; was missing entirely.
- **`IsDefault()`** — compares via YAML marshal, not field-by-field; avoids order-dependent false negatives.
- **`checkOwnership`** — rejects config files not owned by uid 0 on Linux; prevents privilege escalation via config poisoning.
- **`SaveConfig`** — now writes mode `0o600`; was `0o644` (world-readable).
- **Log directory** — created `0o700`; was `0o744`.
- **`DefaultConfigPath`** — returns `/etc/vajra/config.yaml` (absolute); was returning a relative path that breaks under systemd.
- **yaml.v3** — migrated from yaml.v2.
- **`StartupProcwalkDelaySec`**, **`StartupSecretsDelayMin`**, **`StartupAutorunDelaySec`** — startup delay fields wired in `service.go`; prevent CPU spike during system boot.

### Models (`shared/models`)

- **`YaraStringMatch`** — `Strings []string` replaced with `[]YaraStringMatch{Identifier, Offset, SnapshotHex}`; preserves forensic context per match.
- **`DetectionNetwork`** — added `OldFd int32` and `NewFd int32`; typed `int32` to match signed kernel syscall ABI.
- **`EvidenceSnapshot`** — `OpenFDs`, `Maps`, `Environ` changed from untyped `string` to `json.RawMessage`.
- **`AutorunEntry.UniqueKey()`** — now SHA256 of a null-separated tuple; was string concatenation (separator collision possible).
- **`EventStatistic.Date`** — changed from `TEXT` to `int64` Unix epoch of day start UTC.
- **`AppConfig.SchemaVersion`** added.
- **`created_at`/`updated_at`** added to all structs missing them.
- **`SecurityEvent.YaraMatches`** removed — field was never populated (EventSink never runs YARA).
- **Missing `AutorunCategory` constants** added: `CategorySystemdTimer`, `CategoryDBus`, `CategoryAtJob`, `CategoryAnacron`.

### Database Schema

- All timestamp columns changed from `DATETIME DEFAULT CURRENT_TIMESTAMP` to `INTEGER NOT NULL`.
- `event_statistics.date` changed from `TEXT` to `INTEGER NOT NULL`.
- `security_events.yara_matches` column removed — was never populated.
- `VACUUM` at end of migration replaced with `PRAGMA wal_checkpoint(TRUNCATE)`.
- `migrate()` now accepts `DBConn` instead of `*sql.DB`.

### Query Packages

- All query structs converted from `db.SQL()` to `DBConn` interface methods (`QueryContext`, `QueryRowContext`, `ExecContext`, `BeginTx`).
- All write methods now accept `now int64` from caller; `time.Now()` never called inside query functions.
- `created_at`/`updated_at` scanned into struct fields instead of `_` throwaway variables.
- `ListIgnoredFingerprints` — converted from raw SQL to squirrel JOIN.
- `CleanupQueries.RunCleanup` — wrapped in single `BeginTx`.
- `statistics.go:Totals()` — converted from raw SQL to squirrel.
- `ListByDateRange` — int64 epoch range comparison; was unvalidated string date comparison.
- `ProcessTreeQueries.GetByPID` — added (required by LOLBinAnalyzer).
- `autoruns.go` — table name corrected from `autorun_entries` to `autoruns`; was a runtime panic.
- COUNT(*) + SELECT paginated queries — wrapped in `BeginTx(ReadOnly)` to eliminate pagination race.

### Utilities

- **`readBootEpoch`** — replaced `/proc/uptime` text parsing with `syscall.Sysinfo`; eliminates string allocation and float conversion.
- **`EBPFTimestampToUnixNano`** — new method preserving sub-second precision; `EBPFTimestampToUnix` retained for DB storage.
- **`DedupTracker.Stop()`** — added `done chan struct{}` and `Stop()` method; cleanup goroutine no longer leaks.
- **`RuleFromMatch`** — `strings.Cut` replaces manual loop searching for `:`.
- **`filter.go` path matching** — `HasPathPrefix` (exported) checks component boundary; `strings.Contains` was matching `/foo/bar` against prefix `/foo/b`.
- **`filter.go` cleanup** — `RecentScanTracker` cleanup interval derived from TTL; was hardcoded 5 minutes. `Stop()` added.
- **`QuickHash`** — mtime removed from hash input; was bypassable with `touch -t` and caused false cache misses on benign package-manager updates.
- **`GetLogger`** — returns `(*zerolog.Logger, error)`; was returning `*zerolog.Logger` with silent nil on failure. Uses `.Level()` on instance; no longer mutates `zerolog.SetGlobalLevel`.
- **`HasExecutableMagic(*os.File)`** — new shared helper using `ReadAt`; replaces three independent copies in filescanner, fullscan, processscanner.
- **`ReadProcStatus(pid)`** — reads `/proc/PID/status` once and returns struct; was read 3 separate times per PID.
- **`ReadCmdline(pid)`** — shared; removes `cmdlineForPID` / `readCmdline` duplicates across procwalk and processscanner.
- **`NullScanner`** — shared bufio.SplitFunc for null-delimited `/proc/PID/environ`; removes duplicate in ldpreload.
- **`SeverityRank`** — exported from utilities; local copy in analyzer removed.
- **`detectionlists.go`** — deleted; mutable exported vars were a security risk; contents moved to `AlertPolicySettings` defaults.

### Findings

- **`Finding.MachineID`** removed — dead field; set from sysInfo at write time.
- **`Finding.OldFd`/`NewFd`** added as `int32`.
- **`metricsCounters`** unexported; `MetricsSnapshot` read-only type exposed; `Snapshot()` method added.
- **`LogMetrics`** now goes through `Snapshot()`.
- **`json.Marshal` errors** in evidence capture — handled with safe fallback.
- **`readFDs`/`readEnviron`** return `json.RawMessage`; `readMaps` wraps plain text in JSON string.
- **Extension write failures** now logged and counted.

### Analyzer

- **Context keys** — `ctxKeyType` unexported struct; was `type ctxKey int` (collision risk with other packages).
- **`ResultCache`** — backed by `hashicorp/golang-lru/v2`; was unbounded map.
- **Pipeline error logging** — `WithLogger` option; errors from individual stages logged and continued; were silently swallowed (false negative risk).
- **Notes accumulation** — `strings.Builder` in `run` and `MergeResults`; was `+=` in hot path.
- **`CapabilityAnalyzer`** — `DangerousCapabilities` and `ProcessCapabilityExclusions` from `AlertPolicySettings`; was hardcoded map. `found` sorted before join for deterministic Notes. `CAP_BPF`, `CAP_PERFMON`, `CAP_CHECKPOINT_RESTORE` added to defaults.
- **`LDPreloadAnalyzer`** — whitelist model via `TrustedLDPaths`; was blacklist. `/snap/` removed. Uses `utilities.NullScanner`.
- **`YARAAnalyzer`** — `sync.Pool` for result channels with drain-on-cancel; was allocating per call. `classifyFromMatches` dead code removed.
- **`HashAnalyzer`** — `os.Stat` before `os.Open` TOCTOU fixed; `os.IsNotExist` checked on open error. Thread safety documented.
- **`ConvertMatches`** — populates `[]YaraStringMatch{Identifier, Offset, SnapshotHex}` with per-match snapshot capped at `YaraSnapshotBytes`; was building `[]string` (lost identifier and offset, compile error after M1 fix).

### Watcher / Detect

- **Unicode `→`** in DupWatcher Notes replaced with ASCII `->`.
- **`OldFd`/`NewFd`** copied from `DupEvent` to `Finding`.
- **`readNetSockets`** error propagation fixed; was always returning `nil` error.
- **`highValuePorts`** hardcoded map replaced with `AlertPolicySettings.HighValueInboundPorts` / `HighValueOutboundPorts` injected at construction.
- **`formatIP`** — returns error on unknown address family; was silently defaulting to IPv4.
- **`handleModule`** — `encoding/json` struct; was `fmt.Sprintf` JSON.
- **`filescanner.go`** — `MaxFileSizeBytes` from config; `HasExecutableMagic` shared helper; TOCTOU fixed (single `os.Open` → `f.Stat()` → `HasExecutableMagic(f)`); `KnownInterpreters` replaced with `AlertPolicy.Interpreters`.
- **`processscanner.go`** — SHA256 computed once, reused for pipeline and finding; tracker keyed on QuickHash not empty string.
- **`procwalk.go`** — `ReadProcStatus` once per PID; `ReadCmdline` shared; `MachineID` removed from Finding.
- **`secrets.go`** — `MinimumConfidence`, `IgnoreFile`, `SecretsScanIntervalMin`, `SingleTargetSecretsTimeoutMin` all from config; per-target `context.WithTimeout`; `IgnoreFileName` const removed.
- **`fullscan.go`** — pre-count kept for progress bar; criteria aligned with scan walk; interpreter check added to `isEligibleForWalk`; `HasExecutableMagic` shared.
- **Autorun** — errgroup + semaphore of `AutorunConcurrency` (default 2); `reDesktopExecTokens` compiled once at package level; `allUsers()` reads `/etc/passwd`.

### Jobs

- **`cleanup.go`** — immediate run at startup before first ticker.
- **`hashsync.go`** — zip deleted after successful bloom build; goroutine+pipe removed (`reader.Comment = '#'` handles comments natively); auth key moved from URL query param to `Auth-Key` header; dedicated HTTP client with 15-minute timeout; bloom parameters from config; lowercases SHA256 at insert time (companion fix for hash.go A10).
- **`rulesync.go`** — `download` takes `ctx`; `verifyZip` uses `zip.OpenReader` (validates central directory, not just magic bytes); `hashFile` replaced with `utilities.FullSHA256`; package-level HTTP client for `fetchLatestTag`.
- **`statsync.go`** — interval from `StatsSyncIntervalMin`; was hardcoded `time.Hour`.
- **`service.go`** — `wireAll` returns error; `logger.Fatal` after goroutines started replaced with `return fmt.Errorf`; `defer signal.Stop(sigChan)` added; `sleepWithCtx` helper for startup delays; all constructor signatures updated.
- **`entrypoint.go`** — `database.SQL()` replaced with `DBConn`; `SchemaVersion` checked; schema mismatch re-seeds from YAML; `GetLogger` error handled.

### eBPF / YARA Scanner

- **`EventTypeName`** — package-level map; was allocating a new map on every call.
- **`RawEvent.Data interface{}`** — replaced with union struct; eliminates heap allocation per event in perf buffer read loop.
- **`Listener.Start`** — `perfRingPages int` parameter from `PerformanceSettings.EBPFPerfRingPages`; was hardcoded `os.Getpagesize()*64`.
- **`dnsDetails`** and all Details fields — `encoding/json` structs; were `fmt.Sprintf` JSON building.
- **Drop counter** — `atomic.Int64` on Dispatcher; `Drops()` accessor.
- **Pool execute** — opens file and passes fd to `rules.ScanFileDescriptor`; eliminates `os.Stat` + `ScanFile(path)` TOCTOU.
- **Autotune shrink log** — `atomic.Bool` tracks state; fires once on entry, not every tick.
- **`loadAverageFormatted`** dead code removed.
- **`ExtractRules`** — `os.RemoveAll` before extract (after zip verified); stale rule files can no longer survive a bundle update.
- **`writeZipEntry`** — `io.LimitReader` at `MaxFileSizeBytes`; zip bomb protection.
- **`string(content)` conversion** — single conversion; was called twice per rule file.

### UI (Wails)

- **`GetConfig`** — cached after first load; was re-reading YAML on every frontend call.
- **`WriteConfig`** — 1 MiB size limit; merges UIConfig onto full config before piping to pkexec (preserves fields the UI doesn't expose).
- **`perPage`** out-of-range — returns error to frontend; was silently resetting to default.
- **`UIConfig`** — all JSON tags camelCase; was mixed camelCase/snake_case. `APIServerSettings` removed. Wrapper types with explicit json tags replace embedded structs.
- **`main.go`** — `BackgroundColour` derived from `UISettings.DefaultTheme`; `MinWidth`/`MinHeight` from `UISettings`.
- **Theme flash** — blocking `<script>` in `index.html` sets `data-theme` before bundle loads.
- **Theme state** — single source of truth in `App.tsx`; `Sidebar` receives `theme` + `onThemeChange` props. Was split between App (OS listener writing to DOM directly) and Sidebar (toggle state), causing inversion bug on OS preference change.
- **`SOURCES` array** — corrected to actual daemon source strings (`file_scanner`, `process_scanner`, `dup_watcher`, `autorun_scanner`, `secrets_scanner`, `full_scan`).
- **UI query layer** — all `q.db.SQL()` calls replaced with `DBConn` interface methods. COUNT+SELECT pagination wrapped in `BeginTx`. Date range query uses int64 epoch. `autorun_entries` → `autoruns` table name fix.
- **`GetStatsByDateRange`** — signature changed to `(startUnix, endUnix int64)`; dashboard passes Unix epoch integers.

---

## [0.0.1] — 2025-11-09

### Added

- Service mode with eBPF-based listeners for scanning files and processes
- Debian amd64 builds
- Logging metrics module
- Autorun detection and scanning

### Removed

- Partial removal of full file scanning system — replaced with eBPF-driven periodic and efficient scans
