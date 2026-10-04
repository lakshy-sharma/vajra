// internal/analyzer/analyzer.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package analyzer

import (
	"context"
	"sync"

	"vajra/shared/models"
)

// AnalysisResult is returned by every Analyzer implementation.
type AnalysisResult struct {
	Severity    models.EventSeverity
	YaraMatches []models.YaraMatch
	Notes       string
	// Skip signals the caller should not insert a DB record.
	// Set only by the cache for previously seen CLEAN binaries.
	Skip bool
}

// Analyzer is the interface every analysis step implements.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, path string) (AnalysisResult, error)
}

// ── Context helpers ───────────────────────────────────────────

type ctxKey int

const pidKey ctxKey = 0

// CtxWithPID stores a PID in ctx for process analyzers to read.
func CtxWithPID(ctx context.Context, pid uint32) context.Context {
	return context.WithValue(ctx, pidKey, pid)
}

// PIDFromCtx retrieves the PID stored by CtxWithPID.
// Returns 0 and false if no PID is present.
func PIDFromCtx(ctx context.Context) (uint32, bool) {
	pid, ok := ctx.Value(pidKey).(uint32)
	return pid, ok
}

// ── Result cache ──────────────────────────────────────────────

// ResultCache stores content-analysis results keyed on SHA256.
// Only used for file-content analyzers (YARA, hash lookup).
// Runtime analyzers (LD_PRELOAD, reverse shell, capability) are
// never cached — their findings depend on process state, not
// file content.
type ResultCache struct {
	mu    sync.RWMutex
	items map[string]AnalysisResult
}

func NewResultCache() *ResultCache {
	return &ResultCache{items: make(map[string]AnalysisResult)}
}

func (c *ResultCache) Get(sha256 string) (AnalysisResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.items[sha256]
	return r, ok
}

func (c *ResultCache) Set(sha256 string, r AnalysisResult) {
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

// Pipeline runs a list of Analyzers in order.
// Short-circuits on the first CRITICAL result.
// Optionally checks a ResultCache before running analyzers.
type Pipeline struct {
	analyzers []Analyzer
	cache     *ResultCache
}

type PipelineOption func(*Pipeline)

// WithCache attaches a ResultCache to the pipeline.
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
// On a CLEAN cache hit returns Skip=true — caller skips DB insert.
// On a non-CLEAN cache hit returns the cached result without
// re-running analyzers — caller still inserts (new execution of
// a known-bad binary is always worth recording).
func (p *Pipeline) Run(ctx context.Context, path, sha256 string) (AnalysisResult, error) {
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

// RunUncached executes the pipeline without consulting or
// populating the cache. Used for runtime analyzers whose
// findings depend on live process state, not file content.
func (p *Pipeline) RunUncached(ctx context.Context, path string) (AnalysisResult, error) {
	return p.run(ctx, path), nil
}

// run is the shared execution core used by both Run and RunUncached.
func (p *Pipeline) run(ctx context.Context, path string) AnalysisResult {
	merged := AnalysisResult{Severity: models.SeverityClean}

	for _, a := range p.analyzers {
		result, err := a.Analyze(ctx, path)
		if err != nil {
			// Error from one analyzer does not stop the chain.
			// The caller logs errors using the analyzer Name().
			continue
		}

		if severityRank(result.Severity) > severityRank(merged.Severity) {
			merged.Severity = result.Severity
		}
		if len(result.YaraMatches) > 0 {
			merged.YaraMatches = append(merged.YaraMatches, result.YaraMatches...)
		}
		if result.Notes != "" {
			if merged.Notes != "" {
				merged.Notes += "; "
			}
			merged.Notes += result.Notes
		}

		// Short-circuit on CRITICAL.
		if result.Severity == models.SeverityCritical {
			break
		}
	}

	return merged
}

// mergeResults merges b into a, taking the higher severity.
// Used by ProcessScanner to combine content and runtime results.
func MergeResults(a, b AnalysisResult) AnalysisResult {
	merged := a
	if severityRank(b.Severity) > severityRank(merged.Severity) {
		merged.Severity = b.Severity
	}
	if len(b.YaraMatches) > 0 {
		merged.YaraMatches = append(merged.YaraMatches, b.YaraMatches...)
	}
	if b.Notes != "" {
		if merged.Notes != "" {
			merged.Notes += "; "
		}
		merged.Notes += b.Notes
	}
	// Runtime results never set Skip — only content cache does.
	// If either result says Skip, the merge clears it because
	// a runtime finding overrides a clean content result.
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
