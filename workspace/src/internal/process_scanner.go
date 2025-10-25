package internal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hillu/go-yara/v4"
	"github.com/shirou/gopsutil/v3/process"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf process_monitor.c

type ProcessScanner struct {
	rules       *yara.Rules
	scannedPIDs map[int32]time.Time
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

type ProcessEvent struct {
	PID       uint32
	PPID      uint32
	Comm      [16]byte
	EventType uint32 // 0=fork, 1=exec, 2=exit
}

type ProcessScanResult struct {
	PID     int32
	Name    string
	Matches []yara.MatchRule
	Error   error
}

// NewProcessScanner generates a Yara rules object containing compiled yara rules and returns an instance of a scanner.
func NewProcessScanner(rulesPath string) (*ProcessScanner, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create YARA compiler: %w", err)
	}

	file, err := os.Open(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open rules file: %w", err)
	}
	defer file.Close()

	if err := compiler.AddFile(file, ""); err != nil {
		return nil, fmt.Errorf("failed to add rules: %w", err)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("failed to compile rules: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ProcessScanner{
		rules:       rules,
		scannedPIDs: make(map[int32]time.Time),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// This function takes a PID and scans the process with compiled yara rules.
func (ps *ProcessScanner) scanProcess(pid int32) *ProcessScanResult {
	result := &ProcessScanResult{PID: pid}

	proc, err := process.NewProcess(pid)
	if err != nil {
		result.Error = fmt.Errorf("failed to access process: %w", err)
		return result
	}

	name, _ := proc.Name()
	result.Name = name

	var matches yara.MatchRules
	err = ps.rules.ScanProc(int(pid), 0, 0, &matches)
	if err != nil {
		result.Error = fmt.Errorf("scan failed: %w", err)
		return result
	}

	result.Matches = matches
	return result
}

func (ps *ProcessScanner) markScanned(pid int32) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.scannedPIDs[pid] = time.Now()
}

func (ps *ProcessScanner) cleanupOldEntries() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for pid, scanTime := range ps.scannedPIDs {
		if scanTime.Before(cutoff) {
			delete(ps.scannedPIDs, pid)
		}
	}
}

// eBPF-based monitoring for Linux
func (ps *ProcessScanner) ProcessMonitoringEBPF(callback func(*ProcessScanResult)) error {
	logger.Info().Msg("starting process monitor")

	// Remove resource limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load eBPF program
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	defer objs.Close()

	// Attach to tracepoints
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TracepointSchedSchedProcessFork, nil)
	if err != nil {
		return fmt.Errorf("failed to attach fork tracepoint: %w", err)
	}
	defer tpFork.Close()

	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TracepointSchedSchedProcessExec, nil)
	if err != nil {
		return fmt.Errorf("failed to attach exec tracepoint: %w", err)
	}
	defer tpExec.Close()
	logger.Info().Msg("attached to kernel successfully")

	// Scan existing processes first
	logger.Info().Msg("finding existing processes")
	ps.scanExistingProcesses(callback)

	// Read events from perf buffer
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*16)
	if err != nil {
		return fmt.Errorf("failed to create perf reader: %w", err)
	}
	defer rd.Close()

	logger.Info().Msg("started monitoring for new processes")

	// Cleanup ticker
	cleanupTicker := time.NewTicker(1 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ps.ctx.Done():
			return nil
		case <-cleanupTicker.C:
			ps.cleanupOldEntries()
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return nil
				}
				log.Printf("Error reading from perf buffer: %v", err)
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("Warning: Lost %d samples", record.LostSamples)
				continue
			}

			var event ProcessEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

			switch event.EventType {
			case 0: // fork
				log.Printf("[FORK] PID: %d, PPID: %d, Comm: %s", event.PID, event.PPID, comm)
			case 1: // exec
				log.Printf("[EXEC] PID: %d, PPID: %d, Comm: %s", event.PID, event.PPID, comm)
				// Scan the process after exec
				go func(pid int32) {
					time.Sleep(100 * time.Millisecond) // Give process time to initialize
					result := ps.scanProcess(pid)
					ps.markScanned(pid)
					if len(result.Matches) > 0 || shouldReportError(result.Error) {
						callback(result)
					}
				}(int32(event.PID))
			}
		}
	}
}

func (ps *ProcessScanner) scanExistingProcesses(callback func(*ProcessScanResult)) {
	pids, err := process.Pids()
	if err != nil {
		log.Printf("Failed to get process list: %v", err)
		return
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, pid := range pids {
		wg.Add(1)
		go func(p int32) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := ps.scanProcess(p)
			ps.markScanned(p)

			if len(result.Matches) > 0 || shouldReportError(result.Error) {
				callback(result)
			}
		}(pid)
	}

	wg.Wait()
	log.Printf("Initial scan complete. Scanned %d processes.", len(pids))
}

func shouldReportError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return errStr != "failed to access process: process does not exist" &&
		errStr != "scan failed: could not attach to process"
}

// Fallback polling for non-Linux systems
func (ps *ProcessScanner) ProcessMonitoringPolling(interval time.Duration, callback func(*ProcessScanResult)) {
	log.Printf("Starting poll-based process monitoring (interval: %v)", interval)

	// Initial scan
	log.Println("Performing initial scan of all processes...")
	ps.scanExistingProcesses(callback)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(1 * time.Minute)
	defer cleanupTicker.Stop()

	seenPIDs := make(map[int32]bool)

	for {
		select {
		case <-ps.ctx.Done():
			log.Println("Stopping process monitoring")
			return
		case <-ticker.C:
			currentPIDs, err := process.Pids()
			if err != nil {
				log.Printf("Failed to get process list: %v", err)
				continue
			}

			for _, pid := range currentPIDs {
				if !seenPIDs[pid] {
					seenPIDs[pid] = true
					go func(p int32) {
						result := ps.scanProcess(p)
						ps.markScanned(p)
						if len(result.Matches) > 0 || shouldReportError(result.Error) {
							callback(result)
						}
					}(pid)
				}
			}
		case <-cleanupTicker.C:
			ps.cleanupOldEntries()
		}
	}
}

func (ps *ProcessScanner) Stop() {
	ps.cancel()
}

func (ps *ProcessScanner) Close() {
	ps.rules.Destroy()
}

func printResult(result *ProcessScanResult) {
	if result.Error != nil {
		log.Printf("[ERROR] PID %d (%s): %v", result.PID, result.Name, result.Error)
		return
	}

	if len(result.Matches) > 0 {
		fmt.Printf("\n[ALERT] Match found in process: %s (PID: %d)\n", result.Name, result.PID)
		for _, match := range result.Matches {
			fmt.Printf("  Rule: %s\n", match.Rule)
			fmt.Printf("  Namespace: %s\n", match.Namespace)
			if len(match.Strings) > 0 {
				fmt.Println("  Matched strings:")
				for _, str := range match.Strings {
					fmt.Printf("    - %s at offset %d\n", str.Name, str.Offset)
				}
			}
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: scanner <yara_rules_file> [mode]")
		fmt.Println("Modes:")
		fmt.Println("  ebpf   - Use eBPF-based monitoring (Linux only, default)")
		fmt.Println("  poll   - Use polling-based monitoring (fallback)")
		fmt.Println("\nExample: scanner rules.yar ebpf")
		os.Exit(1)
	}

	rulesPath := os.Args[1]
	mode := "ebpf"
	if len(os.Args) > 2 {
		mode = os.Args[2]
	}

	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		log.Println("WARNING: Running without root privileges. eBPF and full process access require root.")
	}

	scanner, err := NewProcessScanner(rulesPath)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\nReceived interrupt signal, shutting down...")
		scanner.Stop()
	}()

	// Start monitoring based on mode
	switch mode {
	case "ebpf":
		if runtime.GOOS != "linux" {
			log.Fatalf("eBPF monitoring is only available on Linux")
		}
		if err := scanner.ProcessMonitoringEBPF(printResult); err != nil {
			log.Fatalf("eBPF monitoring failed: %v", err)
		}
	case "poll":
		scanner.ProcessMonitoringPolling(2*time.Second, printResult)
	default:
		log.Fatalf("Unknown mode: %s", mode)
	}
}
