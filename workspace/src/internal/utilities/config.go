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
	RulesSettings       RulesSettings       `yaml:"rules_settings"`
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
	DatabaseRetentionDays    int `yaml:"database_retention_days"`
	ShutdownTimeoutSec       int `yaml:"shutdown_timeout_sec"`
	SingleFileScanTimeoutSec int `yaml:"single_file_scan_timeout_sec"`
	DedupWindowMin           int `yaml:"dedup_window_min"`
}

type PerformanceSettings struct {
	DefaultThreads     int `yaml:"default_threads"`
	MaxAllowedThreads  int `yaml:"max_allowed_threads"`
	ScanQueueSize      int `yaml:"scan_queue_size"`
	FileScanBufferSize int `yaml:"file_scan_buffer_size"`
}

// RulesSettings controls YARA rule storage and remote sync.
type RulesSettings struct {
	// RulesFilepath is the active rules archive loaded on startup.
	RulesFilepath string `yaml:"rules_filepath"`

	// RulesArchiveDir holds the previous N rule archives for audit.
	RulesArchiveDir string `yaml:"rules_archive_dir"`

	// RulesRemoteURL is the download URL for the latest rules zip.
	RulesRemoteURL string `yaml:"rules_remote_url"`

	// RulesRemoteHashURL is the URL of the SHA256 manifest file.
	// Used to check whether a download is needed before fetching
	// the full archive.
	RulesRemoteHashURL string `yaml:"rules_remote_hash_url"`

	// RulesSyncIntervalHour is how often the sync job runs.
	RulesSyncIntervalHour int `yaml:"rules_sync_interval_hour"`

	// RulesArchiveCount is how many old archives to retain.
	// Oldest archives are deleted when count is exceeded.
	RulesArchiveCount int `yaml:"rules_archive_count"`
}

type ScanSettings struct {
	TargetDirectory string         `yaml:"target_directory"`
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
	if c.TimingSettings.DedupWindowMin == 0 {
		c.TimingSettings.DedupWindowMin = 5
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
	if c.RulesSettings.RulesFilepath == "" {
		c.RulesSettings.RulesFilepath = "/opt/vajra/rules.zip"
	}
	if c.RulesSettings.RulesArchiveDir == "" {
		c.RulesSettings.RulesArchiveDir = "/opt/vajra/rules-archive"
	}
	if c.RulesSettings.RulesRemoteURL == "" {
		c.RulesSettings.RulesRemoteURL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
	}
	if c.RulesSettings.RulesRemoteHashURL == "" {
		c.RulesSettings.RulesRemoteHashURL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip.sha256"
	}
	if c.RulesSettings.RulesSyncIntervalHour == 0 {
		c.RulesSettings.RulesSyncIntervalHour = 24
	}
	if c.RulesSettings.RulesArchiveCount == 0 {
		c.RulesSettings.RulesArchiveCount = 7
	}
}
