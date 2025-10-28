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
	processInitDelay = 100 * time.Millisecond
	cleanupInterval  = 1 * time.Minute
)

type ProcessEvent struct {
	PID       uint32
	PPID      uint32
	Comm      [16]byte
	EventType uint32 // 0=fork, 1=exec
}

type ProcessMonitor struct {
	scanner    *ProcessScanner
	logger     *zerolog.Logger
	objs       *bpfObjects
	links      []link.Link
	reader     *perf.Reader
	eventQueue chan ProcessEvent
	workerWG   sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewProcessMonitor(ctx context.Context, cancel context.CancelFunc, scanner *ProcessScanner, logger *zerolog.Logger) (*ProcessMonitor, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("eBPF process monitoring only supported on Linux")
	}

	return &ProcessMonitor{
		scanner:    scanner,
		logger:     logger,
		eventQueue: make(chan ProcessEvent, GlobalConfig.PerformanceSettings.ProcessScanBufferSize),
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (pm *ProcessMonitor) Start() error {
	pm.logger.Info().Str("platform", runtime.GOOS).Msg("starting eBPF process monitor")

	if err := pm.loadEBPFPrograms(); err != nil {
		return err
	}

	numWorkers := getMaxWorkers()
	pm.logger.Info().Int("workers", numWorkers).Msg("starting process scan workers")
	for range numWorkers {
		pm.workerWG.Add(1)
		go pm.eventWorker()
	}

	go pm.cleanupRoutine()

	pm.logger.Info().Msg("monitoring for new processes (eBPF events)")
	pm.readEBPFEvents()

	return nil
}

func (pm *ProcessMonitor) Stop() error {
	pm.logger.Info().Msg("stopping process monitor")

	pm.cancel()
	close(pm.eventQueue)
	pm.workerWG.Wait()

	if pm.reader != nil {
		pm.reader.Close()
	}

	for _, l := range pm.links {
		l.Close()
	}

	if pm.objs != nil {
		pm.objs.Close()
	}

	pm.logger.Info().Msg("process monitor stopped")
	return nil
}

func (pm *ProcessMonitor) loadEBPFPrograms() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		pm.logger.Warn().Err(err).Msg("failed to remove memlock limit, may need root")
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	objs := &bpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	pm.objs = objs

	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.TracepointSchedSchedProcessFork, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("failed to attach fork tracepoint: %w", err)
	}
	pm.links = append(pm.links, tpFork)

	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TracepointSchedSchedProcessExec, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("failed to attach exec tracepoint: %w", err)
	}
	pm.links = append(pm.links, tpExec)

	reader, err := perf.NewReader(objs.Events, os.Getpagesize()*16)
	if err != nil {
		objs.Close()
		return fmt.Errorf("failed to create perf reader: %w", err)
	}
	pm.reader = reader

	pm.logger.Info().Msg("eBPF programs loaded and attached successfully")
	return nil
}

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
				pm.logger.Warn().Uint64("lost_samples", record.LostSamples).Msg("lost process events")
				continue
			}

			var event ProcessEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				pm.logger.Error().Err(err).Msg("failed to parse eBPF event")
				continue
			}

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

func (pm *ProcessMonitor) processEvent(event ProcessEvent) {
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	switch event.EventType {
	case 0: // fork
		pm.logger.Debug().Uint32("pid", event.PID).Uint32("ppid", event.PPID).Str("comm", comm).Msg("process forked")

	case 1: // exec
		pm.logger.Info().Uint32("pid", event.PID).Uint32("ppid", event.PPID).Str("comm", comm).Msg("process executed")

		time.Sleep(processInitDelay)

		result := pm.scanner.scanProcess(pm.ctx, int32(event.PID))

		if result.Error != nil {
			if !isExpectedError(result.Error) {
				pm.logger.Debug().Err(result.Error).Int32("pid", result.PID).Str("name", result.Name).Msg("process scan error")
			}
			return
		}

		if len(result.Matches) > 0 {
			pm.logger.Warn().Int32("pid", result.PID).Str("name", result.Name).Str("cmdline", result.Cmdline).Int("matches", len(result.Matches)).Msg("THREAT DETECTED - YARA matches in process")

			for _, match := range result.Matches {
				pm.logger.Warn().Int32("pid", result.PID).Str("rule", match.Rule).Str("namespace", match.Namespace).Msg("YARA rule matched")
			}

			if err := pm.scanner.saveProcessScanResults([]ProcessScanResult{result}); err != nil {
				pm.logger.Error().Err(err).Msg("failed to save process scan result")
			}
		} else {
			pm.logger.Debug().Int32("pid", result.PID).Str("name", result.Name).Msg("process clean")
		}
	}
}

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

func isExpectedError(err error) bool {
	errStr := err.Error()
	return errStr == "failed to access process: process does not exist" ||
		errStr == "scan failed: could not attach to process" ||
		errStr == "skipped: kernel thread"
}
