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
package eBPFHandlers

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"
	"vajra/internal/database"
	"vajra/internal/eBPFListeners"
	"vajra/internal/utilities"

	"github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
)

// EventHandler manages the processing of eBPF events with YARA scanning
type EventHandler struct {
	logger          *zerolog.Logger
	yaraRules       *yara.Rules
	eventQueue      chan EventContext
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	config          *utilities.Config
	dbHandler       *database.DBHandler
	scanCache       *sync.Map // Cache to avoid duplicate scans
	rateLimiter     *time.Ticker
	recentScans     *RecentScanTracker
	processFilter   *ProcessFilter
	exclusionFilter *ExclusionFilter
}

// EventContext wraps event data with metadata for processing
type EventContext struct {
	EventType uint32
	EventData interface{}
	Timestamp time.Time
	Priority  string
}

// ScanResult represents the outcome of a YARA scan
type ScanResult struct {
	FilePath    string
	EventType   uint32
	PID         uint32
	UID         uint32
	Comm        string
	Matches     []yara.MatchRule
	ScanTime    time.Time
	IsMalicious bool
	RiskLevel   string
}

// NewEventHandler creates a new event handler with YARA integration
func NewEventHandler(logger *zerolog.Logger, config *utilities.Config, dbHandler *database.DBHandler) (*EventHandler, error) {
	ctx, cancel := context.WithCancel(context.Background())

	eh := &EventHandler{
		logger:          logger,
		eventQueue:      make(chan EventContext, 10000),
		ctx:             ctx,
		cancel:          cancel,
		config:          config,
		dbHandler:       dbHandler,
		scanCache:       &sync.Map{},
		rateLimiter:     time.NewTicker(10 * time.Millisecond),
		exclusionFilter: NewExclusionFilter(config),
		recentScans:     NewRecentScanTracker(5 * time.Minute), // Don't rescan same file within 5 min
		processFilter:   NewProcessFilter(config),
	}

	// Load Yara Rules
	yaraHandler := utilities.NewYaraCompiler(logger)
	extractionPath := filepath.Join(config.GenericSettings.WorkDirectory, "rules")
	if err := yaraHandler.ExtractRules(config.ScanSettings.RulesFilepath, extractionPath); err != nil {
		logger.Error().Err(err).Msg("failed to extract rules")
	}
	var err error
	eh.yaraRules, err = yaraHandler.CompileRules(extractionPath)
	if err != nil {
		logger.Error().Err(err).Msg("failed to compile rules")
	}

	// Start worker pool
	eh.startWorkers(4) // Increased workers for better throughput
	return eh, nil
}

// EventListener is the main callback function for eBPF events
func (eh *EventHandler) EventListener(eventType uint32, eventData interface{}) {
	// Early filtering for high-volume events
	if eventType == eBPFListeners.EventTypeFileOpen || eventType == eBPFListeners.EventTypeFileCreate {
		// Apply quick filtering before queuing
		var filePath string
		var processName string

		switch data := eventData.(type) {
		case eBPFListeners.FileEvent:
			filePath = utilities.ConvertCStringToGo(data.Filename[:])
			processName = utilities.ConvertCStringToGo(data.Comm[:])
		default:
			return
		}

		// Quick path check
		if !eh.exclusionFilter.ShouldScan(filePath) {
			return
		}

		// Reduce monitoring for trusted processes
		if eh.processFilter.IsTrusted(processName) {
			// Only queue exec events for trusted processes
			if eventType != eBPFListeners.EventTypeProcessExec {
				return
			}
		}
	}

	priority := eh.getEventPriority(eventType)

	ctx := EventContext{
		EventType: eventType,
		EventData: eventData,
		Timestamp: time.Now(),
		Priority:  priority,
	}

	select {
	case eh.eventQueue <- ctx:
	default:
		eh.logger.Warn().
			Uint32("event_type", eventType).
			Msg("event queue full, dropping event")
	}
}

// getEventPriority assigns priority levels to different event types
func (eh *EventHandler) getEventPriority(eventType uint32) string {
	switch eventType {
	case eBPFListeners.EventTypeProcessExec,
		eBPFListeners.EventTypeProcessPtrace,
		eBPFListeners.EventTypeModuleLoad,
		eBPFListeners.EventTypeBPFLoad:
		return "CRITICAL"

	case eBPFListeners.EventTypeProcessMemfd,
		eBPFListeners.EventTypeProcessMmap,
		eBPFListeners.EventTypeProcessMprotect,
		eBPFListeners.EventTypeProcessSetuid,
		eBPFListeners.EventTypeProcessSetgid:
		return "HIGH"

	case eBPFListeners.EventTypeFileDelete,
		eBPFListeners.EventTypeFileRename,
		eBPFListeners.EventTypeFileChmod,
		eBPFListeners.EventTypeNetListen:
		return "MEDIUM"

	default:
		return "LOW"
	}
}

// startWorkers spawns worker goroutines to process events
func (eh *EventHandler) startWorkers(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		eh.wg.Add(1)
		go eh.worker(i)
	}
	eh.logger.Info().Int("workers", numWorkers).Msg("started event processing workers")
}

// worker processes events from the queue
func (eh *EventHandler) worker(id int) {
	defer eh.wg.Done()

	for {
		select {
		case <-eh.ctx.Done():
			eh.logger.Info().Int("worker_id", id).Msg("worker shutting down")
			return

		case event := <-eh.eventQueue:
			eh.processEvent(event)
		}
	}
}

// processEvent handles individual events and dispatches to appropriate handlers
func (eh *EventHandler) processEvent(event EventContext) {
	switch event.EventType {
	case eBPFListeners.EventTypeProcessExec:
		eh.handleProcessExec(event)

	case eBPFListeners.EventTypeProcessMemfd:
		eh.handleMemfdCreate(event)

	case eBPFListeners.EventTypeProcessMmap:
		eh.handleMmap(event)

	case eBPFListeners.EventTypeFileOpen,
		eBPFListeners.EventTypeFileCreate:
		eh.handleFileEvent(event)

	case eBPFListeners.EventTypeProcessPtrace:
		eh.handlePtrace(event)

	case eBPFListeners.EventTypeModuleLoad:
		eh.handleModuleLoad(event)

	case eBPFListeners.EventTypeBPFLoad:
		eh.handleBPFLoad(event)

	case eBPFListeners.EventTypeNetConnect,
		eBPFListeners.EventTypeNetBind,
		eBPFListeners.EventTypeNetListen:
		eh.handleNetworkEvent(event)

	default:
		eh.logEvent(event)
	}
}

// logEvent logs events that don't require scanning
func (eh *EventHandler) logEvent(event EventContext) {
	eh.logger.Debug().
		Uint32("event_type", event.EventType).
		Str("priority", event.Priority).
		Msg("event logged")
}

// calculateRiskLevel determines risk level based on YARA matches
func (eh *EventHandler) calculateRiskLevel(matches yara.MatchRules) string {
	if len(matches) == 0 {
		return "CLEAN"
	}

	for _, match := range matches {
		ruleName := match.Rule
		if len(ruleName) >= 4 && ruleName[:4] == "APT_" {
			return "CRITICAL"
		}
		if len(ruleName) >= 10 && ruleName[:10] == "Ransomware" {
			return "CRITICAL"
		}
		if len(ruleName) >= 7 && ruleName[:7] == "Exploit" {
			return "HIGH"
		}
	}

	if len(matches) > 3 {
		return "HIGH"
	}

	return "MEDIUM"
}

// storeScanResult stores scan results in the database
func (eh *EventHandler) storeScanResult(result ScanResult) {
	yaraRecords := database.ConvertYaraMatchRulesToRecords(result.Matches)

	severity := database.EventSeverity(result.RiskLevel)
	if severity == "" {
		severity = database.SeverityLow
	}

	fileScanResult := &database.FileScanResult{
		ScanTime:    result.ScanTime.Unix(),
		FilePath:    result.FilePath,
		YaraMatches: yaraRecords,
		Severity:    severity,
		Status:      database.StatusNew,
		EventType:   result.EventType,
		TriggerPID:  result.PID,
		TriggerUID:  result.UID,
		TriggerComm: result.Comm,
	}

	if fileInfo, err := os.Stat(result.FilePath); err == nil {
		fileScanResult.FileSize = fileInfo.Size()
		if hash, err := calculateFileHash(result.FilePath); err == nil {
			fileScanResult.FileHash = hash
		}
	}

	if err := eh.dbHandler.InsertFileScanResult(fileScanResult); err != nil {
		eh.logger.Error().
			Err(err).
			Str("file", result.FilePath).
			Msg("failed to store scan result in database")
	}
}

// Stop gracefully shuts down the event handler
func (eh *EventHandler) Stop() {
	eh.logger.Info().Msg("stopping event handler")
	eh.cancel()
	eh.rateLimiter.Stop()

	done := make(chan struct{})
	go func() {
		eh.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		eh.logger.Info().Msg("event handler stopped gracefully")
	case <-time.After(10 * time.Second):
		eh.logger.Warn().Msg("event handler shutdown timed out")
	}
}
