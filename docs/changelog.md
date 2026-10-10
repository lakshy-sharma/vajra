# Changelog

## [0.0.2] - 2026-10-10

### Added

- HashAnalyzer — Bloom filter based malware hash detection; slots before YARA in content pipeline; short-circuits on CRITICAL; gracefully disabled when filter file is absent
- HashSyncer job — downloads MalwareBazaar full CSV, builds bits-and-blooms Bloom filter, writes to disk; runs on configurable interval
- `vajra hashes update` — triggers immediate hash database rebuild
- `vajra hashes status` — shows Bloom filter path, size, and last update time
- Secrets scanner — betterleaks v2 SDK integration; scans configured directories for credentials, API keys, and tokens; sha256(secret) stored, raw value never persisted
- Secrets prefilter — path segment exclusions for caches, vendored code, and browser data; configurable via `scan_settings.secrets.exclude_segments`
- Secrets ignore list — betterleaks fingerprint-based suppression; `vajra secrets ignore <id>` marks a detection as noise; `vajra secrets export-ignore` writes the ignore file for the next scan
- `threat_intel_settings` config block — `malware_bazaar_auth_key`, `bloom_filter_path`, `hash_sync_interval_hour`
- SHA256 context helpers in analyzer package — `CtxWithSHA256` / `SHA256FromCtx` for passing file hash through the pipeline without re-reading the file

### Changed

- Content pipeline now runs HashAnalyzer before YARAAnalyzer — known-bad files skip YARA entirely
- `detection_secrets` schema adds `fingerprint` column for betterleaks match fingerprints

## [0.0.1] - 2025-11-09

### Added

- Service mode with eBPF based listeners for scanning files and processes
- Debian amd64 builds
- Logging metrics module
- Autorun detection and scanning

### Removed

- Partial removal of full file scanning system — replaced with eBPF-driven periodic and efficient scans

