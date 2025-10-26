/*
Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package internal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog"
)

const (
	// Process monitoring configuration
	monitorScanWorkers = 2
	processEventBuffer = 200
	cleanupInterval    = 1 * time.Minute

	// Delay before scanning newly spawned processes
	processInitDelay = 100 * time.Millisecond
)

// ProcessEvent represents a process lifecycle event from eBPF.
type ProcessEvent struct {
	PID       uint32
	PPID      uint32
	Comm      [16]byte
	EventType uint32 // 0=fork, 1=exec, 2=exit
}

// ProcessMonitor manages real-time process monitoring using eBPF.
type ProcessMonitor struct {
	scanner *ProcessScanner
	logger  *zerolog.Logger

	// eBPF objects
	objs   *bpfObjects
	links  []link.Link
	reader *perf.Reader

	// Event processing
	eventQueue chan ProcessEvent
	workerWG   sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc
}

// NewProcessMonitor creates a new eBPF-based process monitor.
func NewProcessMonitor(scanner *ProcessScanner, logger *zerolog.Logger) (*ProcessMonitor, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("eBPF process monitoring only supported on Linux")
	}

	ctx, cancel := context.WithCancel(context.Background())

	pm := &ProcessMonitor{
		scanner:    scanner,
		logger:     logger,
		eventQueue: make(chan ProcessEvent, processEventBuffer),
		ctx:        ctx,
		cancel:     cancel,
	}

	return pm, nil
}

// loadEBPFPrograms loads and attaches eBPF programs to kernel tracepoints.
func (pm *ProcessMonitor) loadEBPFPrograms() error {
	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		pm.logger.Warn().Err(err).Msg("failed to remove memlock limit, may need root")
	}

	// Load eBPF program spec
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	// Load eBPF objects into kernel
	objs := &bpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	pm.objs = objs

	// Attach to sched_process_fork tracepoint
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TracepointSchedSchedProcessFork, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("failed to attach fork tracepoint: %w", err)
	}
	pm.links = append(pm.links, tpFork)

	// Attach to sched_process_exec tracepoint
	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TracepointSchedSchedProcessExec, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("failed to attach exec tracepoint: %w", err)
	}
	pm.links = append(pm.links, tpExec)

	// Create perf event reader
	reader, err := perf.NewReader(objs.Events, os.Getpagesize()*16)
	if err != nil {
		objs.Close()
		return fmt.Errorf("failed to create perf reader: %w", err)
	}
	pm.reader = reader

	pm.logger.Info().Msg("eBPF programs loaded and attached successfully")
	return nil
}

// processEvent handles a single process event from eBPF.
func (pm *ProcessMonitor) processEvent(event ProcessEvent) {
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	switch event.EventType {
	case 0: // fork
		pm.logger.Debug().
			Uint32("pid", event.PID).
			Uint32("ppid", event.PPID).
			Str("comm", comm).
			Msg("process forked")

	case 1: // exec
		pm.logger.Info().
			Uint32("pid", event.PID).
			Uint32("ppid", event.PPID).
			Str("comm", comm).
			Msg("process executed")

		// Give process time to initialize before scanning
		time.Sleep(processInitDelay)

		// Scan the process
		result := pm.scanner.scanProcess(pm.ctx, int32(event.PID))

		if result.Error != nil {
			if !isExpectedError(result.Error) {
				pm.logger.Debug().
					Err(result.Error).
					Int32("pid", result.PID).
					Str("name", result.Name).
					Msg("process scan error")
			}
			return
		}

		if len(result.Matches) > 0 {
			// THREAT DETECTED!
			pm.logger.Warn().
				Int32("pid", result.PID).
				Str("name", result.Name).
				Str("cmdline", result.Cmdline).
				Int("matches", len(result.Matches)).
				Msg("THREAT DETECTED - YARA matches in process memory")

			// Log each match
			for _, match := range result.Matches {
				pm.logger.Warn().
					Int32("pid", result.PID).
					Str("rule", match.Rule).
					Str("namespace", match.Namespace).
					Msg("YARA rule matched in process")
			}

			// Save to database
			if err := pm.scanner.saveProcessScanResults([]ProcessScanResult{result}); err != nil {
				pm.logger.Error().Err(err).Msg("failed to save process scan result")
			}

			// TODO: Trigger alert/action here
			// pm.handleThreat(result)

		} else {
			pm.logger.Debug().
				Int32("pid", result.PID).
				Str("name", result.Name).
				Msg("process clean - no threats detected")
		}
	}
}

// isExpectedError checks if an error is expected and should not be logged.
func isExpectedError(err error) bool {
	errStr := err.Error()
	return errStr == "failed to access process: process does not exist" ||
		errStr == "scan failed: could not attach to process" ||
		errStr == "skipped: kernel thread"
}

// eventWorker processes events from the queue.
func (pm *ProcessMonitor) eventWorker() {
	defer pm.workerWG.Done()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case event, ok := <-pm.eventQueue:
			if !ok {
				return
			}
			pm.processEvent(event)
		}
	}
}

// readEBPFEvents reads events from the eBPF perf buffer.
func (pm *ProcessMonitor) readEBPFEvents() {
	for {
		select {
		case <-pm.ctx.Done():
			return
		default:
			record, err := pm.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				pm.logger.Error().Err(err).Msg("error reading from perf buffer")
				continue
			}

			if record.LostSamples > 0 {
				pm.logger.Warn().
					Uint64("lost_samples", record.LostSamples).
					Msg("lost process events due to buffer overflow")
				continue
			}

			// Parse event
			var event ProcessEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				pm.logger.Error().Err(err).Msg("failed to parse eBPF event")
				continue
			}

			// Queue event for processing
			select {
			case pm.eventQueue <- event:
			case <-pm.ctx.Done():
				return
			default:
				pm.logger.Warn().Msg("event queue full, dropping process event")
			}
		}
	}
}

// Start begins the eBPF process monitor daemon.
func (pm *ProcessMonitor) Start() error {
	pm.logger.Info().
		Str("platform", runtime.GOOS).
		Int("workers", monitorScanWorkers).
		Msg("starting eBPF process monitor")

	// Load and attach eBPF programs
	if err := pm.loadEBPFPrograms(); err != nil {
		return err
	}

	// Perform initial scan of existing processes
	pm.logger.Info().Msg("performing initial scan of existing processes")
	if err := pm.scanner.scanAllProcesses(pm.ctx); err != nil {
		pm.logger.Error().Err(err).Msg("initial process scan failed")
	}

	// Start event workers

	for i := 0; i < monitorScanWorkers; i++ {
		pm.workerWG.Add(1)
		go pm.eventWorker()
	}

	// Start cleanup routine
	go pm.cleanupRoutine()

	// Start reading eBPF events (blocking)
	pm.logger.Info().Msg("monitoring for new processes (eBPF events)")
	pm.readEBPFEvents()

	return nil
}

// cleanupRoutine periodically cleans up old scan records.
func (pm *ProcessMonitor) cleanupRoutine() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.scanner.cleanupOldEntries()
		}
	}
}

// Stop gracefully shuts down the process monitor.
func (pm *ProcessMonitor) Stop() error {
	pm.logger.Info().Msg("stopping process monitor")

	// Cancel context
	pm.cancel()

	// Close event queue
	close(pm.eventQueue)

	// Wait for workers
	pm.workerWG.Wait()

	// Close perf reader
	if pm.reader != nil {
		pm.reader.Close()
	}

	// Detach tracepoints
	for _, l := range pm.links {
		l.Close()
	}

	// Close eBPF objects
	if pm.objs != nil {
		pm.objs.Close()
	}

	pm.logger.Info().Msg("process monitor stopped")
	return nil
}
