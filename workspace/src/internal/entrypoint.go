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
	// System CPU usage
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercent) == 0 {
		cpuPercent = []float64{0} // fallback
	}

	// Process CPU usage
	procCPUPercent := 0.0
	p, err := process.NewProcess(int32(os.Getpid()))
	if err == nil {
		if procCPU, err := p.CPUPercent(); err == nil {
			procCPUPercent = procCPU
		}
	}

	// Memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	logger.Info().
		Uint64("current_heap_mb", m.Alloc/1024/1024).
		Uint64("total_heap_mb", m.TotalAlloc/1024/1024).
		Uint64("allocated_system_memory_mb", m.Sys/1024/1024).
		Uint32("garbage_cycle_count", m.NumGC).
		Float64("system_cpu_percent", cpuPercent[0]).
		Float64("process_cpu_percent", procCPUPercent).
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
