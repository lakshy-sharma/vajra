// shared/config/config.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package config

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
	GenericSettings     GenericSettings     `yaml:"generic_settings"     json:"generic_settings"`
	APIServerSettings   APIServerSettings   `yaml:"api_settings"         json:"api_settings"`
	TimingSettings      TimingSettings      `yaml:"timing_settings"      json:"timing_settings"`
	PerformanceSettings PerformanceSettings `yaml:"performance_settings" json:"performance_settings"`
	RulesSettings       RulesSettings       `yaml:"rules_settings"       json:"rules_settings"`
	ThreatIntelSettings ThreatIntelSettings `yaml:"threat_intel_settings" json:"threat_intel_settings"`
	ScanSettings        ScanSettings        `yaml:"scan_settings"        json:"scan_settings"`
	Logging             LoggingSettings     `yaml:"logging"              json:"logging"`
}

type APIServerSettings struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

type GenericSettings struct {
	OperationMode string `yaml:"operation_mode" json:"operation_mode"`
	WorkDirectory string `yaml:"work_directory"  json:"work_directory"`
	// DBDirectory and DBFilename are always sourced from the YAML file.
	// They are intentionally excluded from DB-side config merges to avoid
	// a chicken-and-egg situation where the DB path needed to read the
	// config is itself stored in the config inside that DB.
	DBDirectory string `yaml:"db_directory" json:"db_directory"`
	DBFilename  string `yaml:"db_filename"  json:"db_filename"`
}

type TimingSettings struct {
	AutorunScanTimeMin       int `yaml:"autorun_scan_time_min"       json:"autorun_scan_time_min"`
	DatabaseCleanupTimeHour  int `yaml:"database_cleanup_time_hour"  json:"database_cleanup_time_hour"`
	DatabaseRetentionDays    int `yaml:"database_retention_days"     json:"database_retention_days"`
	ShutdownTimeoutSec       int `yaml:"shutdown_timeout_sec"        json:"shutdown_timeout_sec"`
	SingleFileScanTimeoutSec int `yaml:"single_file_scan_timeout_sec" json:"single_file_scan_timeout_sec"`
	DedupWindowMin           int `yaml:"dedup_window_min"            json:"dedup_window_min"`
	StatsSyncIntervalMin     int `yaml:"stats_sync_interval_min"     json:"stats_sync_interval_min"`
}

type PerformanceSettings struct {
	DefaultThreads     int `yaml:"default_threads"      json:"default_threads"`
	MaxAllowedThreads  int `yaml:"max_allowed_threads"  json:"max_allowed_threads"`
	ScanQueueSize      int `yaml:"scan_queue_size"      json:"scan_queue_size"`
	FileScanBufferSize int `yaml:"file_scan_buffer_size" json:"file_scan_buffer_size"`
}

type RulesSettings struct {
	RulesFilepath         string `yaml:"rules_filepath"          json:"rules_filepath"`
	RulesArchiveDir       string `yaml:"rules_archive_dir"       json:"rules_archive_dir"`
	RulesRemoteURL        string `yaml:"rules_remote_url"        json:"rules_remote_url"`
	RulesRemoteHashURL    string `yaml:"rules_remote_hash_url"   json:"rules_remote_hash_url"`
	RulesSyncIntervalHour int    `yaml:"rules_sync_interval_hour" json:"rules_sync_interval_hour"`
	RulesArchiveCount     int    `yaml:"rules_archive_count"     json:"rules_archive_count"`
}

// ThreatIntelSettings controls hash-based threat intelligence.
// BloomFilterPath is loaded by HashAnalyzer at startup — if absent
// the analyzer disables itself gracefully.
type ThreatIntelSettings struct {
	MalwareBazaarAuthKey string `yaml:"malware_bazaar_auth_key" json:"malware_bazaar_auth_key"`
	BloomFilterPath      string `yaml:"bloom_filter_path"       json:"bloom_filter_path"`
	HashSyncIntervalHour int    `yaml:"hash_sync_interval_hour" json:"hash_sync_interval_hour"`
}

type SecretsSettings struct {
	TargetDirectories   []string `yaml:"target_directories"   json:"target_directories"`
	ExcludeSegments     []string `yaml:"exclude_segments"     json:"exclude_segments"`
	ExcludeBrowserCache *bool    `yaml:"exclude_browser_cache" json:"exclude_browser_cache"`
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
	TargetDirectory string          `yaml:"target_directory" json:"target_directory"`
	Secrets         SecretsSettings `yaml:"secrets"          json:"secrets"`
	ExclusionRules  ExclusionRules  `yaml:"exclusion_rules"  json:"exclusion_rules"`
}

type ExclusionRules struct {
	ExcludePaths      []string `yaml:"exclude_paths"       json:"exclude_paths"`
	ExcludeExtensions []string `yaml:"exclude_extensions"  json:"exclude_extensions"`
	ExcludePatterns   []string `yaml:"exclude_patterns"    json:"exclude_patterns"`
	ExcludeProcesses  []string `yaml:"exclude_processes"   json:"exclude_processes"`
}

type LoggingSettings struct {
	EnableConsole     bool   `yaml:"enable_console"      json:"enable_console"`
	UseJSON           bool   `yaml:"use_json"            json:"use_json"`
	EnableFileLogging bool   `yaml:"enable_file_logging" json:"enable_file_logging"`
	Directory         string `yaml:"log_directory"       json:"log_directory"`
	Filename          string `yaml:"log_filename"        json:"log_filename"`
	MaxSizeMB         int    `yaml:"max_size_mb"         json:"max_size_mb"`
	MaxAgeDays        int    `yaml:"max_age_days"        json:"max_age_days"`
	MaxBackups        int    `yaml:"max_backups"         json:"max_backups"`
	LogLevel          string `yaml:"log_level"           json:"log_level"`
	TimeFormat        string `yaml:"time_format"         json:"time_format"`
}

// LoadConfig reads a YAML file from configPath and returns a fully
// initialised Config with defaults applied.
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

// SaveConfig marshals cfg to YAML and writes it to path.
// The caller is responsible for ensuring it has permission to write
// the target path — the UI uses pkexec to acquire elevated privileges
// before calling this when writing to system-owned locations such as
// /etc/vajra/config.yaml.
func SaveConfig(cfg Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
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
	if c.TimingSettings.StatsSyncIntervalMin == 0 {
		c.TimingSettings.StatsSyncIntervalMin = 5
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
