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
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
)

// Captures logs routinely and adds into logs for enhanced vision

func logMetrics() {
	// --- System CPU usage (over 100ms interval) ---
	cpuPercents, err := cpu.Percent(100*time.Millisecond, false)
	systemCPU := 0.0
	if err == nil && len(cpuPercents) > 0 {
		systemCPU = cpuPercents[0] // total across all cores
	}

	// --- Current process ---
	p, err := process.NewProcess(int32(os.Getpid()))
	procCPU := 0.0
	procRSS := uint64(0)
	if err == nil {
		if c, err := p.CPUPercent(); err == nil {
			procCPU = c // process CPU %
		}
		if m, err := p.MemoryInfo(); err == nil {
			procRSS = m.RSS // resident memory in bytes
		}
	}

	// --- Go runtime memory stats ---
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	log.Info().
		Float64("system_cpu_percent", systemCPU).
		Float64("process_cpu_percent", procCPU).
		Uint64("process_rss_mb", procRSS/1024/1024). // closer to htop RES
		Uint64("current_heap_mb", mem.Alloc/1024/1024).
		Uint64("total_heap_mb", mem.TotalAlloc/1024/1024).
		Uint64("allocated_system_memory_mb", mem.Sys/1024/1024).
		Uint32("garbage_cycle_count", mem.NumGC).
		Msg("process stats")
}

// This is the main function which parses complete config and starts relevant activities
func Entrypoint(config_path string) {
	var err error

	// Parse the configuration file and load it.
	GlobalConfig, err = loadConfig(config_path)
	if err != nil {
		log.Error().Msg("failed to load configuration")
	}

	// Setup logging.
	logger = getLogger(GlobalConfig)

	// Setup temp directory for working.
	if err := os.MkdirAll(GlobalConfig.GenericSettings.WorkDirectory, 0755); err != nil {
		logger.Error().Err(err).Str("recommended_action", "change your work directory").Msg("failed to setup work directory.")
		return
	}

	// Setup database
	if err := os.MkdirAll(GlobalConfig.GenericSettings.DbDirectory, 0755); err != nil {
		logger.Error().Err(err).Str("recommended_action", "change your db directory").Msg("failed to setup database directory")
		return
	}
	setupDB()

	// Start monitoring goroutine
	go func() {
		ticker := time.NewTicker(time.Duration(GlobalConfig.GenericSettings.MonitoringTimeSec) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			logMetrics()
		}
	}()

	// Start the code into designated mode.
	logger.Info().Str("operation_mode", GlobalConfig.GenericSettings.OperationMode).Str("scan_target", GlobalConfig.ScanSettings.TargetDirectory).Msg("locked and loaded ready to go!")

	switch GlobalConfig.GenericSettings.OperationMode {
	case "instant_scan":
		// Perform full scan of targets and quit.
		startFileScan()
		startProcessScan()
	case "daemon_mode":
		// Perform full scan of specified targets.
		startFileScan()
		startProcessScan()

		// Start all daemons together and wait for signal to stop.
		startDaemonMode()
	}
}
