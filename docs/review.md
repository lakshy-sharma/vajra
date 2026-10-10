# Vajra EDR — Code Review Standards and Open Issues

---

## Coding Rules

These are non-negotiable. Every PR is reviewed against all of them.

1. **Comments explain WHY, not HOW.** The code explains itself. Comments justify existence, document non-obvious constraints, or warn about footguns. One line maximum. No "this loops over all entries".

2. **No dead code.** Remove it. Version control is the history.

3. **No hardcoded policy lists.** Detection tuning (interpreters, LOLBins, capabilities, ports, trusted paths) belongs in `AlertPolicySettings` so operators can adjust without recompiling. If you're writing a `var x = []string{"bash", "python", ...}` at package level, it belongs in config.

4. **No raw SQL outside query packages.** Use squirrel builders. Exception: schema migrations in `db/open.go`.

5. **No `time.Now()` inside query functions.** Accept `now int64` from the caller. Query functions that generate their own timestamps cannot be tested deterministically and produce audit trails that lie about when something happened.

6. **No `db.SQL()` or raw `*sql.DB`.** All callers use `shareddb.DBConn`. The interface exposes exactly four methods: `ExecContext`, `QueryContext`, `QueryRowContext`, `BeginTx`. Nothing else.

7. **File permissions: config 0o600, log dir 0o700.** World-readable config or logs is a security finding, not a style issue.

8. **Errors are never silently dropped.** `_, _ = someFunc()` is rejected. `b, _ := json.Marshal(x)` is rejected. Log or propagate; pick one.

9. **Every goroutine subsystem must have a clean shutdown path.** Context + WaitGroup, or a done channel with `Stop()`. A goroutine that only exits when the process dies is a leak.

10. **No string building for JSON.** Use `encoding/json` with a typed struct. `fmt.Sprintf(`{"key":%q}`, val)` is rejected — it is unescaped for nested strings and impossible to extend safely.

11. **Timestamps are `int64` Unix epoch everywhere.** No `time.Time` in DB structs. No `DATETIME` columns. No `TEXT` dates. No `DEFAULT CURRENT_TIMESTAMP`. The query layer accepts `now int64` and uses it.

12. **No TOCTOU.** Open the file once. Stat the open fd. Pass the fd. Never `os.Stat(path)` followed by `os.Open(path)` — the file can be replaced between the two calls.

13. **ASCII only in machine-written strings.** No Unicode arrows (`→`), em-dashes, or decorative characters in Notes, Details, or log messages that will be parsed or indexed.

---

## Open Issues

Issues still open after the October 2026 review. Each has a reference to the original issue number.

### F1 — Finding flat struct with mutually exclusive payload fields

`Finding` has `FileHash`/`YaraMatches`, `RemoteAddr`/`RemotePort`, and `SecretHash` all in one flat struct. At most one group is populated per Finding. This makes the type system say nothing useful about which payload is present.

**Intended fix:** Sub-structs `ArtifactDetail`, `NetworkDetail`, `SecretDetail` as pointer fields — nil means absent.

**Why deferred:** High disruption to all call sites (all watchers, scanners, and tests). Zero compile-time risk in the current form since FindingWriter checks the fields before writing. Revisit when adding a new source type.

### F5 — Sub-table writes not in a single transaction

`FindingWriter.Write` inserts into `detections` then writes to `detection_artifacts`, `detection_network`, `detection_secrets`, `detection_extensions` in separate calls. A crash between them leaves orphaned rows.

**Intended fix:** Begin a transaction before the `detections` insert, commit after all sub-table writes.

**Why deferred:** Requires query structs to accept a `*sql.Tx` as their `DBConn` — the interface already supports this (`*sql.Tx` satisfies `DBConn`), but the wiring in `wireAll` creates query structs at startup before any transaction exists. The fix is to pass `DBConn` per-call rather than per-constructor. Tracked as `TODO(F5)` in writer.go.

### Pool shrink not implemented

`autotune` in `pool.go` detects the idle-should-shrink state but cannot act. Workers are plain goroutines with no individual cancel context.

**Intended fix:** Store a cancel function per worker in a slice on Pool. Shrink removes and calls the last cancel.

### Module name always empty

`sys_enter_init_module` and `sys_enter_finit_module` emit `ModuleEvent` with an empty Name field. `bpf_d_path` is unavailable in tracepoint programs. Name enrichment requires either an fentry program or userspace `/proc/PID/fd/N` resolution after the fact.

### Bloom filter not reloaded on update

`HashSyncer` writes a new filter file but the daemon must restart to load it. `HashAnalyzer` reads the file once at construction. Signal-based or fsnotify reload is deferred to Phase 3.

### Secrets ignore list requires restart

`betterleaks.WithIgnoredFingerprints` is set at `NewSecretsScanner` construction time. Live reload deferred to Phase 4.

### Hash.go A10 (partial)

`hash.go.Analyze` still calls `strings.ToLower(sha256)` per lookup. This is safe (hashsync now lowercases at insert time) but wasteful. Remove the `ToLower` call once the Bloom filter has been regenerated at least once by the updated hashsync.

### Boot epoch drift

NTP clock steps after daemon startup make `EBPFTimestampToUnix` slightly wrong for events timestamped after the step. Rare enough to defer; the error is bounded by the step size.

---

## What This Review Found — Common Mistake Patterns

These are the patterns that appeared repeatedly across the codebase. They are listed here so the next review catches them faster.

### 1. DBConn violation (most widespread)

`db.SQL()` was called in every query package, both UI query packages, the entrypoint, and the CLI. This exposed `*sql.DB` to every subsystem and allowed callers to bypass the interface contract.

**Signal:** Any import of `database/sql` in a file that is not `shared/db/db.go` or `db/open.go` is suspicious. Any call to `.SQL()` is always wrong.

### 2. `time.Now()` inside query functions

Found in statistics, cleanup, detections, and several others. Makes test time uncontrollable and creates audit trails where the "happened at" time is actually the "written at" time.

**Signal:** Any `time.Now()` in a function whose name ends in `Insert`, `Update`, `Upsert`, or `Aggregate`.

### 3. Hardcoded policy lists at package level

`var dangerousCapabilities = map[uint]string{...}`, `var standardLibPaths = []string{...}`, `var highValuePorts = map[uint16]bool{...}` — all were mutable exported or unexported package-level vars baked into the binary.

**Signal:** Any `var x = []string{...}` or `var x = map[...]...{...}` containing process names, port numbers, capability names, or file paths is a candidate for config.

### 4. `fmt.Sprintf` for JSON building

`fmt.Sprintf(`{"request":%d}`, e.Request)`, `fmt.Sprintf(`{"module_name":%q}`, name)` — found in the dispatcher and event sink. `%q` escapes inner quotes but not all edge cases; `%d` is fine but the pattern invites unescaped strings later.

**Signal:** Any `fmt.Sprintf` producing a string that starts with `{` or contains `:` followed by a value.

### 5. Silent error drops

`b, _ := json.Marshal(fds)`, `os.Remove(tmp)` without logging, `_ = w.Flush()` in write paths. The `_` assignment for errors in non-trivial operations was found in evidence capture, the log writer, and the bloom filter writer.

**Signal:** Any `_, _ =` or `_ =` on a function that can meaningfully fail (I/O, marshaling with non-trivial types, exec).

### 6. TOCTOU — stat then open

`os.Stat(filePath)` followed by `os.Open(filePath)` in the file scanner, process scanner, fullscan, pool, and hash analyzer. The file can be replaced, deleted, or swapped for a symlink between the two calls.

**Signal:** `os.Stat` and `os.Open` on the same variable within the same function, where the stat result influences whether the open proceeds.

### 7. Goroutine leaks — no Stop()

`DedupTracker`, `RecentScanTracker` both started cleanup goroutines that ran until process exit. Adding a watcher or tracker meant adding a permanent goroutine leak.

**Signal:** Any `go func()` in a constructor that runs `for range ticker.C` without a `done` channel or context.

### 8. Global logger state mutation

`zerolog.SetGlobalLevel(level)` and `zerolog.TimeFieldFormat = ...` were called in `GetLogger`. Any other logger in the process — tests, library code, embedded tools — would be silently affected.

**Signal:** Any call to a `zerolog.Set*` or assignment to `zerolog.*Format` at package level or in a non-init function.

### 9. Typed context keys as integers

`type ctxKey int; const pidKey ctxKey = 0` — any other package using the same pattern with the same integer value produces a key collision. The `context.WithValue` lookup is by interface equality: same type AND same value.

**Signal:** Context key types defined as numeric underlying types.

### 10. Code duplication across packages

The same function appeared three or more times: `cmdlineForPID` / `readCmdline` in procwalk + processscanner; `hasExecutableMagic` / `hasExecutableMagicBytes` in filescanner + fullscan + pool; `splitOnNull` / `splitOnNullByte` in ldpreload + writer; `severityRank` in analyzer + utilities.

**Signal:** Any function reading `/proc/PID/cmdline`, checking executable magic bytes, or splitting null-delimited byte slices should be in `utilities/`.

### 11. Wrong field names surviving across config refactors

`cfg.Logging` (was `cfg.LogSettings`), `cfg.ThreatIntelSettings.MalwareBazaarAuthKey` (was `cfg.ThreatIntelSettings.APIKey`), `cfg.TimingSettings.AutorunScanTimeMin` (was `cfg.TimingSettings.AutorunScanIntervalMin`), `cfg.TimingSettings.DatabaseCleanupTimeHour` (was `cfg.TimingSettings.CleanupIntervalHour`). These were scattered across service.go, entrypoint.go, and cmd/. None were caught by the compiler because the config struct itself had been updated but the call sites hadn't.

**Signal:** After any config struct field rename, run `grep -r OldFieldName .` across the whole repo before committing.

### 12. `interface{}` boxing in hot paths

`RawEvent.Data interface{}` caused one heap allocation per eBPF event through the perf ring. At high event rates this drives GC pressure.

**Signal:** `interface{}` or `any` fields on structs that pass through channels at high frequency. The fix is a union struct or a fixed-size byte buffer.

### 13. Mixed or missing JSON tags

`UIConfig` had some fields with `json:"camelCase"` and some with `json:"snake_case"`. Config structs (`TimingSettings` etc.) had only `yaml` tags — when embedded directly in `UIConfig`, the Go field names (PascalCase) became the JSON keys, which don't match what the TypeScript frontend expected.

**Signal:** Any struct that crosses a Go/TypeScript boundary must have explicit `json` tags with camelCase values. Structs with only `yaml` tags must never be embedded directly in API response types.
