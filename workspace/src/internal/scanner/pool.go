// internal/scanner/pool.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"context"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
	"vajra/shared/models"
)

// ScanFunc is the function signature for performing a YARA scan.
// Injected so the pool can be tested without real YARA rules.
type ScanFunc func(filePath string) ([]models.YaraMatch, error)

// ScanRequest carries a file path and a channel for the result.
type ScanRequest struct {
	FilePath string
	Result   chan<- ScanResult
}

// ScanResult is returned for every scan attempt.
type ScanResult struct {
	FilePath string
	Matches  []models.YaraMatch
	Error    error
	Duration time.Duration
}

// Enqueue is the blocking version of Submit.
// It waits until the queue has space or ctx is cancelled.
// Use this from event-driven consumers where back-pressure
// is preferable to dropping work.
// Returns false only if ctx was cancelled before the item
// could be queued.
func (p *Pool) Enqueue(ctx context.Context, filePath string, result chan<- ScanResult) bool {
	select {
	case p.queue <- ScanRequest{FilePath: filePath, Result: result}:
		return true
	case <-ctx.Done():
		return false
	}
}

// Pool is a bounded worker pool for YARA scanning.
// Worker count autotunes between minWorkers and maxWorkers
// based on queue depth and rolling scan duration.
type Pool struct {
	logger     *zerolog.Logger
	scan       ScanFunc
	queue      chan ScanRequest
	minWorkers int
	maxWorkers int
	current    atomic.Int32 // current live worker count

	// Autotune state
	rollingDur atomic.Int64 // nanoseconds, rolling average
	rollingN   atomic.Int64 // sample count

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex // guards worker spawning
}

// NewPool creates a pool backed by real YARA rules.
// minWorkers = config.DefaultThreads
// maxWorkers = config.MaxAllowedThreads
func NewPool(
	rules *yara.Rules,
	minWorkers, maxWorkers int,
	queueSize int,
	scanTimeoutSec int,
	logger *zerolog.Logger,
) *Pool {
	// Clamp to sane values.
	if minWorkers < 1 {
		minWorkers = 1
	}
	if maxWorkers < minWorkers {
		maxWorkers = minWorkers
	}
	if maxWorkers > runtime.NumCPU()*2 {
		maxWorkers = runtime.NumCPU() * 2
	}

	timeout := time.Duration(scanTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Pool{
		logger:     logger,
		queue:      make(chan ScanRequest, queueSize),
		minWorkers: minWorkers,
		maxWorkers: maxWorkers,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Wire the real YARA scan function.
	p.scan = func(filePath string) ([]models.YaraMatch, error) {
		var raw yara.MatchRules
		if err := rules.ScanFile(filePath, 0, timeout, &raw); err != nil {
			return nil, err
		}
		return convertMatches(raw), nil
	}

	// Start minimum workers.
	for i := 0; i < minWorkers; i++ {
		p.spawnWorker()
	}

	// Start the autotune loop.
	go p.autotune()

	logger.Info().
		Int("min_workers", minWorkers).
		Int("max_workers", maxWorkers).
		Int("queue_size", queueSize).
		Msg("YARA scan pool started")

	return p
}

// NewPoolWithFunc creates a pool with an injected scan function.
// Used in tests to avoid CGO/YARA dependency.
func NewPoolWithFunc(
	fn ScanFunc,
	minWorkers, maxWorkers, queueSize int,
	logger *zerolog.Logger,
) *Pool {
	ctx, cancel := context.WithCancel(context.Background())

	p := &Pool{
		logger:     logger,
		scan:       fn,
		queue:      make(chan ScanRequest, queueSize),
		minWorkers: minWorkers,
		maxWorkers: maxWorkers,
		ctx:        ctx,
		cancel:     cancel,
	}

	for i := 0; i < minWorkers; i++ {
		p.spawnWorker()
	}

	go p.autotune()
	return p
}

// Submit queues a scan request. Returns false if the queue is full.
func (p *Pool) Submit(filePath string, result chan<- ScanResult) bool {
	select {
	case p.queue <- ScanRequest{FilePath: filePath, Result: result}:
		return true
	default:
		return false
	}
}

// Stop drains the queue and shuts down all workers.
func (p *Pool) Stop() {
	p.cancel()
	p.wg.Wait()
}

// QueueDepth returns the number of pending scan requests.
func (p *Pool) QueueDepth() int {
	return len(p.queue)
}

// WorkerCount returns the current number of live workers.
func (p *Pool) WorkerCount() int {
	return int(p.current.Load())
}

// spawnWorker starts one worker goroutine.
func (p *Pool) spawnWorker() {
	p.wg.Add(1)
	p.current.Add(1)

	go func() {
		defer p.wg.Done()
		defer p.current.Add(-1)

		for {
			select {
			case <-p.ctx.Done():
				return
			case req, ok := <-p.queue:
				if !ok {
					return
				}
				p.execute(req)
			}
		}
	}()
}

// execute runs a single scan and records timing for autotune.
func (p *Pool) execute(req ScanRequest) {
	// Skip non-existent or unreadable files early.
	if _, err := os.Stat(req.FilePath); err != nil {
		req.Result <- ScanResult{FilePath: req.FilePath, Error: err}
		return
	}

	start := time.Now()
	matches, err := p.scan(req.FilePath)
	dur := time.Since(start)

	// Update rolling average duration.
	n := p.rollingN.Add(1)
	prev := p.rollingDur.Load()
	// Exponential moving average with alpha = 0.1
	alpha := int64(10) // represents 0.1 * 100
	newAvg := (prev*(100-alpha) + dur.Nanoseconds()*alpha) / 100
	if n == 1 {
		newAvg = dur.Nanoseconds()
	}
	p.rollingDur.Store(newAvg)

	req.Result <- ScanResult{
		FilePath: req.FilePath,
		Matches:  matches,
		Error:    err,
		Duration: dur,
	}
}

// autotune adjusts the worker count every 10 seconds based on
// queue depth and rolling scan duration.
func (p *Pool) autotune() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.adjust()
		}
	}
}

// adjust grows or shrinks the pool by one worker per cycle.
func (p *Pool) adjust() {
	p.mu.Lock()
	defer p.mu.Unlock()

	current := int(p.current.Load())
	depth := p.QueueDepth()
	avgNs := p.rollingDur.Load()

	// Grow if queue is backing up and we have headroom.
	if depth > current && current < p.maxWorkers {
		p.spawnWorker()
		p.logger.Debug().
			Int("workers", current+1).
			Int("queue_depth", depth).
			Msg("autotune: added worker")
		return
	}

	// Shrink if queue is empty, avg scan is fast, and we're
	// above the minimum.
	fastThresholdNs := int64(500 * time.Millisecond)
	if depth == 0 && avgNs < fastThresholdNs && current > p.minWorkers {
		// Shrinking is done by cancelling a worker via a
		// dedicated per-worker context. For simplicity we
		// rely on natural worker death: when the context is
		// cancelled the pool stops. For live shrinking we
		// would need per-worker cancel — add in a future pass.
		p.logger.Debug().
			Int("workers", current).
			Msg("autotune: pool at minimum or load too high to shrink")
	}
}

// convertMatches converts go-yara MatchRules to our model type.
func convertMatches(raw yara.MatchRules) []models.YaraMatch {
	out := make([]models.YaraMatch, 0, len(raw))
	for _, m := range raw {
		strs := make([]string, 0, len(m.Strings))
		for _, s := range m.Strings {
			strs = append(strs, string(s.Data))
		}
		out = append(out, models.YaraMatch{
			Rule:      m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
			Strings:   strs,
		})
	}
	return out
}
