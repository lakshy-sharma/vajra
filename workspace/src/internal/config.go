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
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	GenericSettings     GenericSettings     `yaml:"generic_settings"`
	APIServerSettings   APIServerSettings   `yaml:"api_settings"`
	TimingSettings      TimingSettings      `yaml:"timing_settings"`
	PerformanceSettings PerformanceSettings `yaml:"performance_settings"`
	ScanSettings        ScanSettings        `yaml:"scan_settings"`
	Logging             LoggingSettings     `yaml:"logging"`
}

type APIServerSettings struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type GenericSettings struct {
	OperationMode     string `yaml:"operation_mode"`
	WorkDirectory     string `yaml:"work_directory"`
	DbDirectory       string `yaml:"db_directory"`
	DbFilename        string `yaml:"db_filename"`
	MonitoringTimeSec int    `yaml:"monitoring_timer_sec"`
}

type TimingSettings struct {
	ShutdownTimeoutSec            int `yaml:"shutdown_timeout_sec"`
	SingleFileScanTimeoutSec      int `yaml:"single_file_scan_timeout_sec"`
	SingleProcessScanTimeoutSec   int `yaml:"single_process_scan_timeout_sec"`
	CompleteFileScanTimeoutMin    int `yaml:"complete_file_scan_timeout_min"`
	CompleteProcessScanTimeoutMin int `yaml:"complete_process_scan_timeout_min"`
}

type PerformanceSettings struct {
	DefaultThreads        int `yaml:"default_threads"`
	MaxAllowedThreads     int `yaml:"max_allowed_threads"`
	DBInsertBatchSize     int `yaml:"db_insert_batch_size"`
	FileScanBufferSize    int `yaml:"file_scan_buffer_size"`
	ProcessScanBufferSize int `yaml:"process_scan_buffer_size"`
}

type ScanSettings struct {
	TargetDirectory string `yaml:"target_directory"`
	RulesFilepath   string `yaml:"rules_filepath"`
}

// Configuration for logging
type LoggingSettings struct {
	EnableConsole     bool   `yaml:"enable_console"`
	UseJSON           bool   `yaml:"use_json"`
	EnableFileLogging bool   `yaml:"enable_file_logging"`
	Directory         string `yaml:"log_directory"`
	Filename          string `yaml:"log_filename"`
	MaxSizeMB         int    `yaml:"max_size_mb"`
	MaxAgeDays        int    `yaml:"max_age_days"`
	MaxBackups        int    `yaml:"max_backups"`
	LogLevel          string `yaml:"log_level"`
	TimeFormat        string `yaml:"time_format"`
}

var GlobalConfig Config

// loadConfig reads and unmarshals the YAML configuration file.
func loadConfig(configPath string) (Config, error) {
	var config Config

	// Read the file content
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Unmarshal the YAML data into the Config struct
	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal config file %s: %w", configPath, err)
	}

	return config, nil
}
