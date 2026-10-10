// internal/scanner/yara/pool.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package yara

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	goyara "github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
)

// ScanRequest carries a file path and a result channel.
type ScanRequest struct {
	FilePath string
	Result   chan<- ScanResult
}

// ScanResult is returned for every scan attempt.
type ScanResult struct {
	FilePath string
	Matches  []Match
	Error    error
	Duration time.Duration
}

// Pool is a bounded worker pool for YARA scanning with load-aware autotune.
type Pool struct {
	logger     *zerolog.Logger
	scan       func(f *os.File) ([]Match, error)
	queue      chan ScanRequest
	minWorkers int
	maxWorkers int
	numCPU     int
	current    atomic.Int32
	rollingDur atomic.Int64
	rollingN   atomic.Int64
	// E7: track whether we've already logged the "should shrink" state so
	// the message fires once on entry rather than on every autotune tick.
	shrinkLogged atomic.Bool
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.Mutex
}

func NewPool(
	rules *goyara.Rules,
	minWorkers, maxWorkers, queueSize, scanTimeoutSec, yaraSnapshotBytes int,
	logger *zerolog.Logger,
) *Pool {
	if minWorkers < 1 {
		minWorkers = 1
	}
	numCPU := runtime.NumCPU()
	if maxWorkers < minWorkers {
		maxWorkers = minWorkers
	}
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

	snapshotBytes := yaraSnapshotBytes

	// E6: scan via file descriptor opened by execute() so the fd used for
	// stat and the fd used for scanning are the same — eliminates the TOCTOU
	// window between os.Stat and the previous rules.ScanFile(path) call.
	p.scan = func(f *os.File) ([]Match, error) {
		var raw goyara.MatchRules
		if err := rules.ScanFileDescriptor(uintptr(f.Fd()), 0, timeout, &raw); err != nil {
			return nil, err
		}
		return ConvertMatches(raw, snapshotBytes), nil
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

func (p *Pool) Submit(filePath string, result chan<- ScanResult) bool {
	select {
	case p.queue <- ScanRequest{FilePath: filePath, Result: result}:
		return true
	default:
		return false
	}
}

func (p *Pool) Enqueue(ctx context.Context, filePath string, result chan<- ScanResult) bool {
	select {
	case p.queue <- ScanRequest{FilePath: filePath, Result: result}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *Pool) Stop() {
	p.cancel()
	p.wg.Wait()
}

func (p *Pool) QueueDepth() int  { return len(p.queue) }
func (p *Pool) WorkerCount() int { return int(p.current.Load()) }

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

// execute opens the target file once and passes the fd to YARA.
// E6: opening here rather than in scan() ensures we hold the fd across
// both the stat-equivalent check (Open returning an error) and the actual
// scan, eliminating the TOCTOU race of stat-then-ScanFile(path).
func (p *Pool) execute(req ScanRequest) {
	f, err := os.Open(req.FilePath)
	if err != nil {
		req.Result <- ScanResult{FilePath: req.FilePath, Error: err}
		return
	}
	defer f.Close()

	start := time.Now()
	matches, err := p.scan(f)
	dur := time.Since(start)

	n := p.rollingN.Add(1)
	prev := p.rollingDur.Load()
	const alpha = int64(10)
	newAvg := (prev*(100-alpha) + dur.Nanoseconds()*alpha) / 100
	if n == 1 {
		newAvg = dur.Nanoseconds()
	}
	p.rollingDur.Store(newAvg)

	req.Result <- ScanResult{FilePath: req.FilePath, Matches: matches, Error: err, Duration: dur}
}

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

func (p *Pool) adjust() {
	p.mu.Lock()
	defer p.mu.Unlock()

	current := int(p.current.Load())
	depth := p.QueueDepth()
	avgNs := p.rollingDur.Load()
	load := loadAverage()

	low := float64(p.numCPU) * 0.5
	high := float64(p.numCPU) * 0.8
	sat := float64(p.numCPU) * 1.0

	if load >= sat && load > 0 {
		p.logger.Debug().Int("workers", current).Float64("load", load).Msg("autotune: saturated, holding")
		p.shrinkLogged.Store(false)
		return
	}
	if load >= high && load > 0 {
		p.logger.Debug().Int("workers", current).Float64("load", load).Msg("autotune: high load, holding")
		p.shrinkLogged.Store(false)
		return
	}

	canGrow := current < p.maxWorkers
	if load >= 0 && load < low {
		if depth > 0 && canGrow {
			p.spawnWorker()
			p.logger.Debug().Int("workers", current+1).Int("queue_depth", depth).Msg("autotune: low load, added worker")
		}
		p.shrinkLogged.Store(false)
		return
	}
	if depth > current && canGrow {
		p.spawnWorker()
		p.logger.Debug().Int("workers", current+1).Int("queue_depth", depth).Msg("autotune: queue backed up, added worker")
		p.shrinkLogged.Store(false)
		return
	}

	const fastThresholdNs = int64(500 * time.Millisecond)
	if depth == 0 && avgNs < fastThresholdNs && current > p.minWorkers {
		// E7: log once when entering the idle-should-shrink state, not every tick.
		if p.shrinkLogged.CompareAndSwap(false, true) {
			p.logger.Debug().Int("workers", current).Msg("autotune: idle, shrink pending (per-worker cancel not yet implemented)")
		}
	} else {
		p.shrinkLogged.Store(false)
	}
}

func loadAverage() float64 {
	f, err := os.Open("/proc/loadavg")
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return -1
	}
	fields := strings.Fields(sc.Text())
	if len(fields) == 0 {
		return -1
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return -1
	}
	return load
}

// loadAverageFormatted was defined but never called — removed (dead code).
