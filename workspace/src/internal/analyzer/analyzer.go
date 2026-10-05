// internal/analyzer/analyzer.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package analyzer

import (
	"context"
	"sync"

	"vajra/shared/models"
)

// Analyzer is the interface every detection stage implements.
// Stateless — safe to reuse across scans and goroutines.
// Path is the file or exe path being analysed. PID context
// is available via CtxWithPID for process-specific analyzers.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, path string) (Result, error)
}

// Result is returned by every Analyzer implementation.
type Result struct {
	Severity    models.EventSeverity
	YaraMatches []models.YaraMatch
	Notes       string
	// Skip signals the caller should not insert a DB record.
	// Set only by the cache on a previously seen CLEAN binary.
	Skip bool
}

// ── PID context ───────────────────────────────────────────────

type ctxKey int

const pidKey ctxKey = 0

// CtxWithPID stores a PID for process analyzers to read.
func CtxWithPID(ctx context.Context, pid uint32) context.Context {
	return context.WithValue(ctx, pidKey, pid)
}

// PIDFromCtx retrieves the PID stored by CtxWithPID.
func PIDFromCtx(ctx context.Context) (uint32, bool) {
	pid, ok := ctx.Value(pidKey).(uint32)
	return pid, ok
}

// ── Result cache ──────────────────────────────────────────────

// ResultCache stores content-analysis results keyed on SHA256.
// Only used for file-content analyzers (YARA, hash lookup).
// Runtime analyzers are never cached — their findings depend on
// live process state, not file content.
type ResultCache struct {
	mu    sync.RWMutex
	items map[string]Result
}

func NewResultCache() *ResultCache {
	return &ResultCache{items: make(map[string]Result)}
}

func (c *ResultCache) Get(sha256 string) (Result, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.items[sha256]
	return r, ok
}

func (c *ResultCache) Set(sha256 string, r Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[sha256] = r
}

func (c *ResultCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// ── Pipeline ──────────────────────────────────────────────────

// Pipeline runs a list of Analyzers in order, short-circuiting on CRITICAL.
type Pipeline struct {
	analyzers []Analyzer
	cache     *ResultCache
}

type PipelineOption func(*Pipeline)

func WithCache(c *ResultCache) PipelineOption {
	return func(p *Pipeline) { p.cache = c }
}

func NewPipeline(analyzers []Analyzer, opts ...PipelineOption) *Pipeline {
	p := &Pipeline{analyzers: analyzers}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Run executes the pipeline with cache support.
// CLEAN cache hit → Skip=true, caller skips DB insert.
// Non-CLEAN cache hit → cached result returned, caller still inserts
// because a new execution of a known-bad binary is always worth recording.
func (p *Pipeline) Run(ctx context.Context, path, sha256 string) (Result, error) {
	if p.cache != nil && sha256 != "" {
		if cached, ok := p.cache.Get(sha256); ok {
			if cached.Severity == models.SeverityClean {
				cached.Skip = true
			}
			return cached, nil
		}
	}

	result := p.run(ctx, path)

	if p.cache != nil && sha256 != "" {
		p.cache.Set(sha256, result)
	}
	return result, nil
}

// RunUncached executes the pipeline without consulting the cache.
// Used for runtime analyzers whose findings depend on live process state.
func (p *Pipeline) RunUncached(ctx context.Context, path string) (Result, error) {
	return p.run(ctx, path), nil
}

func (p *Pipeline) run(ctx context.Context, path string) Result {
	merged := Result{Severity: models.SeverityClean}
	for _, a := range p.analyzers {
		result, err := a.Analyze(ctx, path)
		if err != nil {
			continue
		}
		if severityRank(result.Severity) > severityRank(merged.Severity) {
			merged.Severity = result.Severity
		}
		merged.YaraMatches = append(merged.YaraMatches, result.YaraMatches...)
		if result.Notes != "" {
			if merged.Notes != "" {
				merged.Notes += "; "
			}
			merged.Notes += result.Notes
		}
		if result.Severity == models.SeverityCritical {
			break
		}
	}
	return merged
}

// MergeResults merges b into a, taking the higher severity.
// Used by ProcessScanner to combine content and runtime results.
// Runtime findings clear Skip — a clean content cache result is
// overridden if runtime analysis finds something.
func MergeResults(a, b Result) Result {
	merged := a
	if severityRank(b.Severity) > severityRank(merged.Severity) {
		merged.Severity = b.Severity
	}
	merged.YaraMatches = append(merged.YaraMatches, b.YaraMatches...)
	if b.Notes != "" {
		if merged.Notes != "" {
			merged.Notes += "; "
		}
		merged.Notes += b.Notes
	}
	if b.Severity != models.SeverityClean {
		merged.Skip = false
	}
	return merged
}

func severityRank(s models.EventSeverity) int {
	switch s {
	case models.SeverityClean:
		return 0
	case models.SeverityLow:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityHigh:
		return 3
	case models.SeverityCritical:
		return 4
	default:
		return 0
	}
}
