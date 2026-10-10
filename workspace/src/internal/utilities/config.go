// internal/utilities/config.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

var defaultSecretDirs = []string{
	"/home",
	"/root",
	"/etc",
	"/tmp",
	"/opt",
	"/var",
	"/srv",
	"/run",
}

var defaultExcludeSegments = []string{
	"/.git/objects/",
	"/node_modules/",
	"/go/pkg/mod/",
	"/.cache/go-build/",
}

var defaultBrowserCacheSegments = []string{
	"/cache2/entries/",
	"/.cache/mozilla/",
	"/.cache/chromium/",
	"/snap/firefox/",
	"/snap/chromium/",
	"/.cache/tracker",
}

type Config struct {
	GenericSettings     GenericSettings     `yaml:"generic_settings"`
	APIServerSettings   APIServerSettings   `yaml:"api_settings"`
	TimingSettings      TimingSettings      `yaml:"timing_settings"`
	PerformanceSettings PerformanceSettings `yaml:"performance_settings"`
	RulesSettings       RulesSettings       `yaml:"rules_settings"`
	ThreatIntelSettings ThreatIntelSettings `yaml:"threat_intel_settings"`
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

type RulesSettings struct {
	RulesFilepath         string `yaml:"rules_filepath"`
	RulesArchiveDir       string `yaml:"rules_archive_dir"`
	RulesRemoteURL        string `yaml:"rules_remote_url"`
	RulesRemoteHashURL    string `yaml:"rules_remote_hash_url"`
	RulesSyncIntervalHour int    `yaml:"rules_sync_interval_hour"`
	RulesArchiveCount     int    `yaml:"rules_archive_count"`
}

// ThreatIntelSettings controls hash-based threat intelligence.
// BloomFilterPath is loaded by HashAnalyzer at startup — if absent
// the analyzer disables itself gracefully.
type ThreatIntelSettings struct {
	MalwareBazaarAuthKey string `yaml:"malware_bazaar_auth_key"`
	BloomFilterPath      string `yaml:"bloom_filter_path"`
	HashSyncIntervalHour int    `yaml:"hash_sync_interval_hour"`
}

type SecretsSettings struct {
	TargetDirectories   []string `yaml:"target_directories"`
	ExcludeSegments     []string `yaml:"exclude_segments"`
	ExcludeBrowserCache *bool    `yaml:"exclude_browser_cache"`
}

func (s SecretsSettings) IsDefaultConfig() bool {
	if len(s.TargetDirectories) != len(defaultSecretDirs) {
		return false
	}
	for i, d := range s.TargetDirectories {
		if d != defaultSecretDirs[i] {
			return false
		}
	}
	return true
}

func (s SecretsSettings) BrowserCacheExcluded() bool {
	if s.ExcludeBrowserCache == nil {
		return true
	}
	return *s.ExcludeBrowserCache
}

func (s SecretsSettings) AllExcludeSegments(dbDirectory string) []string {
	segments := []string{dbDirectory}
	segments = append(segments, defaultExcludeSegments...)
	if s.BrowserCacheExcluded() {
		segments = append(segments, defaultBrowserCacheSegments...)
	}
	segments = append(segments, s.ExcludeSegments...)
	return segments
}

type ScanSettings struct {
	TargetDirectory string          `yaml:"target_directory"`
	Secrets         SecretsSettings `yaml:"secrets"`
	ExclusionRules  ExclusionRules  `yaml:"exclusion_rules"`
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
	if c.ThreatIntelSettings.BloomFilterPath == "" {
		c.ThreatIntelSettings.BloomFilterPath = "/opt/vajra/hashes.bloom"
	}
	if c.ThreatIntelSettings.HashSyncIntervalHour == 0 {
		c.ThreatIntelSettings.HashSyncIntervalHour = 24
	}
	if len(c.ScanSettings.Secrets.TargetDirectories) == 0 {
		c.ScanSettings.Secrets.TargetDirectories = make([]string, len(defaultSecretDirs))
		copy(c.ScanSettings.Secrets.TargetDirectories, defaultSecretDirs)
	}
}
