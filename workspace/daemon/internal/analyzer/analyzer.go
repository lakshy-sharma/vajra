// internal/analyzer/analyzer.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package analyzer

import (
	"context"
	"fmt"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
	"vajra/internal/utilities"
	"vajra/shared/models"
)

// Analyzer is the interface every detection stage implements.
// Stateless — safe to reuse across scans and goroutines.
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

// ── Context keys ──────────────────────────────────────────────────────────────

// ctxKeyType is an unexported struct used as a context key type.
// A struct type prevents key collisions with other packages that might
// independently define integer or string keys with the same underlying value.
type ctxKeyType struct{ name string }

var (
	pidKey    = ctxKeyType{"pid"}
	sha256Key = ctxKeyType{"sha256"}
)

func CtxWithPID(ctx context.Context, pid uint32) context.Context {
	return context.WithValue(ctx, pidKey, pid)
}

func PIDFromCtx(ctx context.Context) (uint32, bool) {
	pid, ok := ctx.Value(pidKey).(uint32)
	return pid, ok
}

func CtxWithSHA256(ctx context.Context, sha256 string) context.Context {
	return context.WithValue(ctx, sha256Key, sha256)
}

func SHA256FromCtx(ctx context.Context) (string, bool) {
	sha256, ok := ctx.Value(sha256Key).(string)
	return sha256, ok
}

// ── Result cache ──────────────────────────────────────────────────────────────

// ResultCache stores content-analysis results keyed on SHA256.
// Only used for file-content analyzers (YARA, hash lookup).
// Runtime analyzers are never cached — their findings depend on live
// process state, not file content.
//
// The underlying LRU is thread-safe; no additional locking is needed.
type ResultCache struct {
	cache *lru.Cache[string, Result]
}

// NewResultCache creates a cache bounded to capacity entries.
// capacity should come from cfg.PerformanceSettings.ResultCacheSize.
func NewResultCache(capacity int) (*ResultCache, error) {
	c, err := lru.New[string, Result](capacity)
	if err != nil {
		return nil, fmt.Errorf("analyzer: result cache: %w", err)
	}
	return &ResultCache{cache: c}, nil
}

func (c *ResultCache) Get(sha256 string) (Result, bool) {
	return c.cache.Get(sha256)
}

func (c *ResultCache) Set(sha256 string, r Result) {
	c.cache.Add(sha256, r)
}

func (c *ResultCache) Len() int {
	return c.cache.Len()
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

// Pipeline runs a list of Analyzers in order, short-circuiting on CRITICAL.
type Pipeline struct {
	analyzers []Analyzer
	cache     *ResultCache
	logger    *zerolog.Logger
}

type PipelineOption func(*Pipeline)

func WithCache(c *ResultCache) PipelineOption {
	return func(p *Pipeline) { p.cache = c }
}

// WithLogger attaches a logger so failed analyzer stages are recorded rather
// than silently skipped.
func WithLogger(l *zerolog.Logger) PipelineOption {
	return func(p *Pipeline) { p.logger = l }
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
	var notes strings.Builder
	for _, a := range p.analyzers {
		result, err := a.Analyze(ctx, path)
		if err != nil {
			// Log and continue — one failed stage must not void the others.
			if p.logger != nil {
				p.logger.Error().Err(err).Str("analyzer", a.Name()).Str("path", path).Msg("analyzer: stage failed")
			}
			continue
		}
		if utilities.SeverityRank(result.Severity) > utilities.SeverityRank(merged.Severity) {
			merged.Severity = result.Severity
		}
		merged.YaraMatches = append(merged.YaraMatches, result.YaraMatches...)
		if result.Notes != "" {
			if notes.Len() > 0 {
				notes.WriteString("; ")
			}
			notes.WriteString(result.Notes)
		}
		if result.Severity == models.SeverityCritical {
			break
		}
	}
	merged.Notes = notes.String()
	return merged
}

// MergeResults merges b into a, taking the higher severity.
// Used by ProcessScanner to combine content and runtime results.
// Runtime findings clear Skip — a clean content cache result is
// overridden if runtime analysis finds something.
func MergeResults(a, b Result) Result {
	merged := a
	if utilities.SeverityRank(b.Severity) > utilities.SeverityRank(merged.Severity) {
		merged.Severity = b.Severity
	}
	merged.YaraMatches = append(merged.YaraMatches, b.YaraMatches...)
	if b.Notes != "" {
		var notes strings.Builder
		notes.WriteString(merged.Notes)
		if notes.Len() > 0 {
			notes.WriteString("; ")
		}
		notes.WriteString(b.Notes)
		merged.Notes = notes.String()
	}
	if b.Severity != models.SeverityClean {
		merged.Skip = false
	}
	return merged
}
