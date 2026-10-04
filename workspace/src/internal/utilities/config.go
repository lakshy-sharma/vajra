// internal/utilities/config.go
package utilities

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
	OperationMode string `yaml:"operation_mode"`
	WorkDirectory string `yaml:"work_directory"`
	DBDirectory   string `yaml:"db_directory"`
	DBFilename    string `yaml:"db_filename"`
}

type TimingSettings struct {
	AutorunScanTimeMin       int `yaml:"autorun_scan_time_min"`
	DatabaseCleanupTimeHour  int `yaml:"database_cleanup_time_hour"`
	DatabaseRetentionDays    int `yaml:"database_retention_days"` // NEW: was hardcoded 90
	ShutdownTimeoutSec       int `yaml:"shutdown_timeout_sec"`
	SingleFileScanTimeoutSec int `yaml:"single_file_scan_timeout_sec"`
}

type PerformanceSettings struct {
	DefaultThreads     int `yaml:"default_threads"`
	MaxAllowedThreads  int `yaml:"max_allowed_threads"`
	ScanQueueSize      int `yaml:"scan_queue_size"` // NEW: pool queue depth
	FileScanBufferSize int `yaml:"file_scan_buffer_size"`
}

type ScanSettings struct {
	TargetDirectory string         `yaml:"target_directory"`
	RulesFilepath   string         `yaml:"rules_filepath"`
	ExclusionRules  ExclusionRules `yaml:"exclusion_rules"`
}

type ExclusionRules struct {
	ExcludePaths      []string `yaml:"exclude_paths"`
	ExcludeExtensions []string `yaml:"exclude_extensions"`
	ExcludePatterns   []string `yaml:"exclude_patterns"`
	ExcludeProcesses  []string `yaml:"exclude_processes"`
}

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

func LoadConfig(configPath string) (Config, error) {
	var config Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("config: read %s: %w", configPath, err)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("config: parse %s: %w", configPath, err)
	}
	applyDefaults(&config)
	return config, nil
}

// applyDefaults fills in zero values with sane starting points.
// This prevents panics when fields are omitted from the YAML.
func applyDefaults(c *Config) {
	if c.TimingSettings.AutorunScanTimeMin == 0 {
		c.TimingSettings.AutorunScanTimeMin = 30
	}
	if c.TimingSettings.DatabaseCleanupTimeHour == 0 {
		c.TimingSettings.DatabaseCleanupTimeHour = 24
	}
	if c.TimingSettings.DatabaseRetentionDays == 0 {
		c.TimingSettings.DatabaseRetentionDays = 90
	}
	if c.TimingSettings.ShutdownTimeoutSec == 0 {
		c.TimingSettings.ShutdownTimeoutSec = 30
	}
	if c.TimingSettings.SingleFileScanTimeoutSec == 0 {
		c.TimingSettings.SingleFileScanTimeoutSec = 30
	}
	if c.PerformanceSettings.DefaultThreads == 0 {
		c.PerformanceSettings.DefaultThreads = 2
	}
	if c.PerformanceSettings.MaxAllowedThreads == 0 {
		c.PerformanceSettings.MaxAllowedThreads = 8
	}
	if c.PerformanceSettings.ScanQueueSize == 0 {
		c.PerformanceSettings.ScanQueueSize = 1000
	}
}
