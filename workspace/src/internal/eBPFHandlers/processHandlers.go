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
	"fmt"
	"vajra/internal/database"
	"vajra/internal/eBPFListeners"
	"vajra/internal/utilities"
)

// handleProcessExec processes exec events and scans the executed binary
func (eh *EventHandler) handleProcessExec(event EventContext) {
	procEvent := event.EventData.(eBPFListeners.ProcessEvent)
	filename := utilities.ConvertCStringToGo(procEvent.Filename[:])
	comm := utilities.ConvertCStringToGo(procEvent.Comm[:])
	args := utilities.ConvertCStringToGo(procEvent.Args[:])

	eh.logger.Info().
		Uint32("pid", procEvent.PID).
		Uint32("ppid", procEvent.PPID).
		Uint32("uid", procEvent.UID).
		Str("comm", comm).
		Str("file", filename).
		Str("args", args).
		Msg("process exec detected")

	// Scan the executed binary
	if filename != "" {
		eh.scanFile(filename, event.EventType, procEvent.PID, procEvent.UID, comm)
	}
}

// handleMemfdCreate handles memfd_create events (fileless execution indicator)
func (eh *EventHandler) handleMemfdCreate(event EventContext) {
	procEvent := event.EventData.(eBPFListeners.ProcessEvent)
	name := utilities.ConvertCStringToGo(procEvent.Filename[:])
	comm := utilities.ConvertCStringToGo(procEvent.Comm[:])

	eh.logger.Warn().
		Uint32("pid", procEvent.PID).
		Str("name", name).
		Str("comm", comm).
		Msg("memfd_create detected - potential fileless execution")

	// Try to scan from /proc/PID/fd/ if possible
	procPath := fmt.Sprintf("/proc/%d/exe", procEvent.PID)
	eh.scanFile(procPath, event.EventType, procEvent.PID, procEvent.UID, comm)
}

// handleMmap handles memory mapping events
func (eh *EventHandler) handleMmap(event EventContext) {
	mmapEvent := event.EventData.(eBPFListeners.MmapEvent)
	filename := utilities.ConvertCStringToGo(mmapEvent.Filename[:])
	comm := utilities.ConvertCStringToGo(mmapEvent.Comm[:])

	// Check if executable memory mapping
	if mmapEvent.Prot&0x4 != 0 { // PROT_EXEC
		eh.logger.Warn().
			Uint32("pid", mmapEvent.PID).
			Uint64("addr", mmapEvent.Addr).
			Uint64("size", mmapEvent.Length).
			Uint32("prot", mmapEvent.Prot).
			Str("file", filename).
			Str("comm", comm).
			Msg("executable memory mapping detected")

		if filename != "" {
			eh.scanFile(filename, event.EventType, mmapEvent.PID, mmapEvent.UID, comm)
		}
	}
}

// handlePtrace handles ptrace events (debugging/injection attempts)
func (eh *EventHandler) handlePtrace(event EventContext) {
	ptraceEvent := event.EventData.(eBPFListeners.PtraceEvent)
	comm := utilities.ConvertCStringToGo(ptraceEvent.Comm[:])

	eh.logger.Warn().
		Uint32("pid", ptraceEvent.PID).
		Uint32("target_pid", ptraceEvent.TargetPID).
		Uint32("request", ptraceEvent.Request).
		Str("comm", comm).
		Msg("ptrace detected - potential code injection")

	// Store security event
	secEvent := &database.SecurityEventRecord{
		EventTime:   event.Timestamp.Unix(),
		EventType:   event.EventType,
		EventName:   "ptrace",
		PID:         ptraceEvent.PID,
		UID:         ptraceEvent.UID,
		ProcessName: comm,
		TargetPID:   ptraceEvent.TargetPID,
		Details:     fmt.Sprintf(`{"request": "0x%x"}`, ptraceEvent.Request),
		Severity:    database.SeverityCritical,
		Status:      database.StatusNew,
		ActionTaken: "logged",
	}

	if err := eh.dbHandler.InsertSecurityEvent(secEvent); err != nil {
		eh.logger.Error().Err(err).Msg("failed to store ptrace event")
	}

	// Scan both the tracer and target processes
	tracerPath := fmt.Sprintf("/proc/%d/exe", ptraceEvent.PID)
	targetPath := fmt.Sprintf("/proc/%d/exe", ptraceEvent.TargetPID)

	eh.scanFile(tracerPath, event.EventType, ptraceEvent.PID, ptraceEvent.UID, comm)
	eh.scanFile(targetPath, event.EventType, ptraceEvent.TargetPID, ptraceEvent.UID, "")
}

// handleModuleLoad handles kernel module loading events
func (eh *EventHandler) handleModuleLoad(event EventContext) {
	modEvent := event.EventData.(eBPFListeners.ModuleEvent)
	name := utilities.ConvertCStringToGo(modEvent.Name[:])
	comm := utilities.ConvertCStringToGo(modEvent.Comm[:])

	eh.logger.Warn().
		Uint32("pid", modEvent.PID).
		Str("module", name).
		Str("comm", comm).
		Msg("kernel module load detected")

	// Scan the module file if path is available
	if name != "" {
		eh.scanFile(name, event.EventType, modEvent.PID, modEvent.UID, comm)
	}
}

// handleBPFLoad handles eBPF program loading events
func (eh *EventHandler) handleBPFLoad(event EventContext) {
	modEvent := event.EventData.(eBPFListeners.ModuleEvent)
	name := utilities.ConvertCStringToGo(modEvent.Name[:])
	comm := utilities.ConvertCStringToGo(modEvent.Comm[:])

	eh.logger.Warn().
		Uint32("pid", modEvent.PID).
		Str("name", name).
		Str("comm", comm).
		Msg("eBPF program load detected")
}
