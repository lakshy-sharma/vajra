// internal/jobs/filescanner.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

//go:build linux

package jobs

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"vajra/internal/db/queries"
	"vajra/internal/ebpf"
	"vajra/internal/scanner"
	"vajra/shared/models"
)

// FileScanner consumes FileEvents from the eBPF dispatcher,
// applies filtering and deduplication, submits files to the
// YARA pool, and persists results via FileQueries.
//
// Pipeline per event:
//
//	FileEvent
//	  → ExclusionFilter.ShouldScan()   — path/ext/pattern rules
//	  → isEligibleFile()               — size + magic byte check
//	  → RecentScanTracker              — TTL dedup by quick hash
//	  → scanner.Pool.Enqueue()         — blocking submit to YARA
//	  → result → severity classify
//	  → FileQueries.Insert()
type FileScanner struct {
	logger  *zerolog.Logger
	pool    *scanner.Pool
	queries *queries.FileQueries
	filter  *scanner.ExclusionFilter
	tracker *scanner.RecentScanTracker
}

// NewFileScanner constructs a FileScanner. The pool and filter
// are shared with other jobs — FileScanner does not own them.
func NewFileScanner(
	logger *zerolog.Logger,
	pool *scanner.Pool,
	fq *queries.FileQueries,
	filter *scanner.ExclusionFilter,
) *FileScanner {
	return &FileScanner{
		logger:  logger,
		pool:    pool,
		queries: fq,
		filter:  filter,
		// 5 minute TTL: a file seen again within 5 minutes is
		// assumed unchanged and skipped.
		tracker: scanner.NewRecentScanTracker(5 * time.Minute),
	}
}

// Run consumes from fileCh until ctx is cancelled.
// Intended to be launched as a goroutine via service.go.
// wg.Done() is called on return.
func (fs *FileScanner) Run(
	ctx context.Context,
	wg *sync.WaitGroup,
	fileCh <-chan ebpf.FileEvent,
) {
	defer wg.Done()

	fs.logger.Info().Msg("file scanner started")

	for {
		select {
		case <-ctx.Done():
			fs.logger.Info().Msg("file scanner stopped")
			return

		case event, ok := <-fileCh:
			if !ok {
				return
			}
			fs.handle(ctx, event)
		}
	}
}

// handle processes a single FileEvent through the full pipeline.
func (fs *FileScanner) handle(ctx context.Context, event ebpf.FileEvent) {
	filePath := ebpf.CStringToGo(event.Filename[:])
	if filePath == "" {
		return
	}

	comm := ebpf.CStringToGo(event.Comm[:])

	// ── Stage 1: exclusion filter ─────────────────────────────
	if !fs.filter.ShouldScan(filePath) {
		fs.logger.Debug().
			Str("file", filePath).
			Msg("file scanner: excluded by filter")
		return
	}

	// ── Stage 2: file eligibility ─────────────────────────────
	eligible, reason := isEligibleFile(filePath)
	if !eligible {
		fs.logger.Debug().
			Str("file", filePath).
			Str("reason", reason).
			Msg("file scanner: ineligible")
		return
	}

	// ── Stage 3: recent scan dedup ────────────────────────────
	// QuickHash reads only the first 8 KB — fast enough for
	// the hot path. If hashing fails we fall back to path as key.
	quickHash, err := scanner.QuickHash(filePath)
	if err != nil {
		quickHash = ""
	}

	if fs.tracker.WasRecentlyScanned(filePath, quickHash) {
		fs.logger.Debug().
			Str("file", filePath).
			Msg("file scanner: recently scanned, skipping")
		return
	}

	// Mark scanned before submitting to avoid duplicate submissions
	// if a burst of events arrives for the same file.
	fs.tracker.MarkScanned(filePath, quickHash)

	// ── Stage 4: submit to YARA pool (blocking) ───────────────
	resultCh := make(chan scanner.ScanResult, 1)

	if !fs.pool.Enqueue(ctx, filePath, resultCh) {
		// ctx was cancelled while waiting for queue space.
		return
	}

	// ── Stage 5: collect result and persist ───────────────────
	// We wait for the result in the same goroutine. The file
	// scanner goroutine blocks here which is intentional —
	// back-pressure propagates naturally up to the eBPF channel.
	select {
	case <-ctx.Done():
		return

	case result := <-resultCh:
		fs.persist(result, event, comm)
	}
}

// persist writes a scan result to the database.
func (fs *FileScanner) persist(
	result scanner.ScanResult,
	event ebpf.FileEvent,
	comm string,
) {
	if result.Error != nil {
		fs.logger.Error().
			Err(result.Error).
			Str("file", result.FilePath).
			Msg("file scanner: YARA scan error")
		return
	}

	severity := scanner.ClassifyYARASeverity(result.Matches)

	// Compute full hash only for files that matched something
	// or are flagged at medium or above — avoids hashing every
	// clean file on a busy system.
	fileHash := ""
	if severity != models.SeverityClean {
		if h, err := scanner.FullSHA256(result.FilePath); err == nil {
			fileHash = h
		}
	}

	fileSize := int64(0)
	if info, err := os.Stat(result.FilePath); err == nil {
		fileSize = info.Size()
	}

	record := &models.FileScanResult{
		ScanTime:    time.Now().Unix(),
		FilePath:    result.FilePath,
		FileSize:    fileSize,
		FileHash:    fileHash,
		YaraMatches: result.Matches,
		Severity:    severity,
		Status:      models.StatusNew,
		EventType:   event.Type,
		TriggerPID:  event.PID,
		TriggerUID:  event.UID,
		TriggerComm: comm,
	}

	if err := fs.queries.Insert(record); err != nil {
		fs.logger.Error().
			Err(err).
			Str("file", result.FilePath).
			Msg("file scanner: DB insert failed")
		return
	}

	if severity != models.SeverityClean {
		fs.logger.Warn().
			Str("file", result.FilePath).
			Str("severity", string(severity)).
			Uint32("pid", event.PID).
			Str("comm", comm).
			Int("yara_matches", len(result.Matches)).
			Dur("scan_duration", result.Duration).
			Msg("FILE SCAN DETECTION")
	} else {
		fs.logger.Debug().
			Str("file", result.FilePath).
			Dur("scan_duration", result.Duration).
			Msg("file scanner: clean")
	}
}

// ── Helpers ───────────────────────────────────────────────────

// isEligibleFile checks whether a file is worth scanning.
// Returns false with a reason string when the file should be
// skipped. Checks happen cheapest-first.
func isEligibleFile(filePath string) (bool, string) {
	info, err := os.Stat(filePath)
	if err != nil {
		return false, "stat_failed"
	}

	if info.IsDir() {
		return false, "is_directory"
	}

	// Skip empty files and very small files (< 10 bytes).
	if info.Size() < 10 {
		return false, "too_small"
	}

	// Skip files larger than 100 MB — YARA on huge files is
	// expensive and these are rarely malware payloads.
	// This threshold is configurable in a future pass.
	if info.Size() > 100*1024*1024 {
		return false, "too_large"
	}

	// Check magic bytes — only scan files that look executable
	// or script-like. This is the most effective noise filter
	// for file-create events on a busy system.
	if !hasExecutableMagic(filePath) {
		return false, "not_executable_magic"
	}

	return true, ""
}

// hasExecutableMagic reads the first 4 bytes of a file and
// returns true if they match a known executable format.
// We check magic bytes rather than extensions because malware
// routinely uses misleading extensions.
func hasExecutableMagic(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	magic := make([]byte, 4)
	n, err := f.Read(magic)
	if err != nil || n < 2 {
		return false
	}

	// ELF: 7f 45 4c 46
	if n >= 4 && magic[0] == 0x7f && magic[1] == 0x45 &&
		magic[2] == 0x4c && magic[3] == 0x46 {
		return true
	}

	// Shebang: #!
	if magic[0] == '#' && magic[1] == '!' {
		return true
	}

	// PE (Windows): MZ — included for completeness even on Linux
	if magic[0] == 0x4d && magic[1] == 0x5a {
		return true
	}

	// Java class: ca fe ba be
	if n >= 4 && magic[0] == 0xca && magic[1] == 0xfe &&
		magic[2] == 0xba && magic[3] == 0xbe {
		return true
	}

	// Python bytecode: various magic numbers all start 0x0d
	if n >= 4 && magic[3] == 0x0d {
		return true
	}

	return false
}
