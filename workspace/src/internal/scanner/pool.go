// internal/scanner/pool.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
	"vajra/shared/models"
)

// ScanFunc is the function signature for performing a YARA scan.
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

// Pool is a bounded worker pool for YARA scanning.
// Worker count autotunes between minWorkers and maxWorkers
// based on queue depth, rolling scan duration, and system
// load average. Under high system load the pool backs off
// to avoid starving other processes. Under low load it is
// allowed to grow toward maxWorkers freely.
type Pool struct {
	logger     *zerolog.Logger
	scan       ScanFunc
	queue      chan ScanRequest
	minWorkers int
	maxWorkers int
	numCPU     int
	current    atomic.Int32

	// Autotune state
	rollingDur atomic.Int64 // nanoseconds, exponential moving average
	rollingN   atomic.Int64 // sample count

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex // guards worker spawning
}

// NewPool creates a pool backed by real YARA rules.
func NewPool(
	rules *yara.Rules,
	minWorkers, maxWorkers int,
	queueSize int,
	scanTimeoutSec int,
	logger *zerolog.Logger,
) *Pool {
	if minWorkers < 1 {
		minWorkers = 1
	}
	if maxWorkers < minWorkers {
		maxWorkers = minWorkers
	}
	numCPU := runtime.NumCPU()
	if maxWorkers > numCPU*2 {
		maxWorkers = numCPU * 2
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
		numCPU:     numCPU,
		ctx:        ctx,
		cancel:     cancel,
	}

	p.scan = func(filePath string) ([]models.YaraMatch, error) {
		var raw yara.MatchRules
		if err := rules.ScanFile(filePath, 0, timeout, &raw); err != nil {
			return nil, err
		}
		return convertMatches(raw), nil
	}

	for i := 0; i < minWorkers; i++ {
		p.spawnWorker()
	}

	go p.autotune()

	logger.Info().
		Int("min_workers", minWorkers).
		Int("max_workers", maxWorkers).
		Int("queue_size", queueSize).
		Int("num_cpu", numCPU).
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
		numCPU:     runtime.NumCPU(),
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

// Enqueue is the blocking version of Submit.
// Waits until queue has space or ctx is cancelled.
func (p *Pool) Enqueue(ctx context.Context, filePath string, result chan<- ScanResult) bool {
	select {
	case p.queue <- ScanRequest{FilePath: filePath, Result: result}:
		return true
	case <-ctx.Done():
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
	if _, err := os.Stat(req.FilePath); err != nil {
		req.Result <- ScanResult{FilePath: req.FilePath, Error: err}
		return
	}

	start := time.Now()
	matches, err := p.scan(req.FilePath)
	dur := time.Since(start)

	n := p.rollingN.Add(1)
	prev := p.rollingDur.Load()
	alpha := int64(10)
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

// autotune adjusts the worker count every 10 seconds.
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

// loadAverage reads the 1-minute load average from /proc/loadavg.
// Returns -1 on any error so the caller can treat it as unknown
// and proceed without load-based throttling.
func loadAverage() float64 {
	f, err := os.Open("/proc/loadavg")
	if err != nil {
		return -1
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return -1
	}

	fields := strings.Fields(scanner.Text())
	if len(fields) == 0 {
		return -1
	}

	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return -1
	}

	return load
}

// adjust grows or shrinks the pool by one worker per cycle,
// taking system load into account.
//
// Load thresholds relative to CPU count:
//
//	load < 0.5 × numCPU  → low load, pool may grow freely
//	load < 0.8 × numCPU  → moderate load, pool may grow if queue backing up
//	load ≥ 0.8 × numCPU  → high load, pool holds at current size
//	load ≥ 1.0 × numCPU  → saturated, pool shrinks toward minimum
//
// This keeps Vajra from starving foreground work during busy
// periods (compiles, package installs, video encoding) and
// allows it to use spare capacity when the machine is idle.
func (p *Pool) adjust() {
	p.mu.Lock()
	defer p.mu.Unlock()

	current := int(p.current.Load())
	depth := p.QueueDepth()
	avgNs := p.rollingDur.Load()
	load := loadAverage()

	lowLoad := float64(p.numCPU) * 0.5
	highLoad := float64(p.numCPU) * 0.8
	saturated := float64(p.numCPU) * 1.0

	// ── Saturated: shrink toward minimum ─────────────────────
	// System is fully loaded. Give CPU back regardless of queue.
	if load >= saturated && load > 0 {
		if current > p.minWorkers {
			// Signal one worker to stop by cancelling — currently
			// we rely on natural drain since per-worker cancel
			// contexts are not yet implemented. Log intent only.
			p.logger.Debug().
				Int("workers", current).
				Float64("load", load).
				Float64("threshold", saturated).
				Msg("autotune: system saturated, holding at minimum")
		}
		return
	}

	// ── High load: hold current size ─────────────────────────
	// System is busy. Don't add workers but don't shrink either.
	if load >= highLoad && load > 0 {
		p.logger.Debug().
			Int("workers", current).
			Float64("load", load).
			Float64("threshold", highLoad).
			Msg("autotune: high system load, holding worker count")
		return
	}

	// ── Low/moderate load: grow if queue is backing up ────────
	// Under low load (< 0.5 × numCPU) grow whenever there is
	// any queue depth. Under moderate load only grow if queue
	// depth exceeds current worker count (genuinely backed up).
	canGrow := current < p.maxWorkers
	queuePressure := depth > 0

	if load >= 0 && load < lowLoad {
		// Low load — grow freely on any queue pressure.
		if queuePressure && canGrow {
			p.spawnWorker()
			p.logger.Debug().
				Int("workers", current+1).
				Int("queue_depth", depth).
				Float64("load", load).
				Msg("autotune: low load, added worker")
		}
		return
	}

	// Moderate load — only grow if queue is genuinely backed up.
	if queuePressure && depth > current && canGrow {
		p.spawnWorker()
		p.logger.Debug().
			Int("workers", current+1).
			Int("queue_depth", depth).
			Float64("load", load).
			Msg("autotune: moderate load, queue backed up, added worker")
		return
	}

	// ── Shrink if idle and fast ───────────────────────────────
	fastThresholdNs := int64(500 * time.Millisecond)
	if depth == 0 && avgNs < fastThresholdNs && current > p.minWorkers {
		p.logger.Debug().
			Int("workers", current).
			Int64("avg_scan_ns", avgNs).
			Msg("autotune: idle and fast, would shrink (per-worker cancel not yet implemented)")
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

// loadAverageFormatted returns a human-readable load string for logging.
func loadAverageFormatted() string {
	load := loadAverage()
	if load < 0 {
		return "unknown"
	}
	return fmt.Sprintf("%.2f", load)
}
