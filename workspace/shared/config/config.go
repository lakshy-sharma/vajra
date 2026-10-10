// shared/config/config.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ── Typed enumerations ────────────────────────────────────────────────────────

// OperationMode controls which subsystems are active.
type OperationMode string

const (
	ModeMonitor  OperationMode = "monitor"  // observe and record; no blocking
	ModeEnforce  OperationMode = "enforce"  // block on confirmed detections
	ModeDiagnose OperationMode = "diagnose" // verbose logging, no blocking
)

// ── Top-level config ──────────────────────────────────────────────────────────

// Config is the single source of truth loaded from YAML and persisted to the
// database as a JSON blob. Every subsection has its own struct so that callers
// only import the fields they actually need.
//
// SECURITY: SaveConfig writes with mode 0o600. LoadConfig rejects files not
// owned by root (uid 0) on Linux to prevent privilege escalation via config
// poisoning.
type Config struct {
	GenericSettings     GenericSettings     `yaml:"generic_settings"`
	ScanSettings        ScanSettings        `yaml:"scan_settings"`
	PerformanceSettings PerformanceSettings `yaml:"performance_settings"`
	TimingSettings      TimingSettings      `yaml:"timing_settings"`
	RulesSettings       RulesSettings       `yaml:"rules_settings"`
	SecretsSettings     SecretsSettings     `yaml:"secrets_settings"`
	ThreatIntelSettings ThreatIntelSettings `yaml:"threat_intel_settings"`
	AlertPolicy         AlertPolicySettings `yaml:"alert_policy"`
	LogSettings         LogSettings         `yaml:"log_settings"`
	UISettings          UISettings          `yaml:"ui_settings"`
}

// ── Generic / top-level paths ─────────────────────────────────────────────────

type GenericSettings struct {
	Mode          OperationMode `yaml:"mode"`
	DBDirectory   string        `yaml:"db_directory"`
	DBFilename    string        `yaml:"db_filename"`
	WorkDirectory string        `yaml:"work_directory"`
	MachineID     string        `yaml:"machine_id"`
}

// ── Scan settings ─────────────────────────────────────────────────────────────

type ScanSettings struct {
	TargetDirectory   string   `yaml:"target_directory"`
	ExcludedPaths     []string `yaml:"excluded_paths"`
	ExcludedProcesses []string `yaml:"excluded_processes"`
	MaxFileSizeBytes  int64    `yaml:"max_file_size_bytes"`
	YaraSnapshotBytes int      `yaml:"yara_snapshot_bytes"`
}

// ── Performance settings ──────────────────────────────────────────────────────

type PerformanceSettings struct {
	DefaultThreads          int `yaml:"default_threads"`
	MaxAllowedThreads       int `yaml:"max_allowed_threads"`
	StartupMaxThreads       int `yaml:"startup_max_threads"`
	StartupRampupMin        int `yaml:"startup_rampup_min"`
	ScanQueueSize           int `yaml:"scan_queue_size"`
	EBPFPerfRingPages       int `yaml:"ebpf_perf_ring_pages"`
	YaraAutotuneIntervalSec int `yaml:"yara_autotune_interval_sec"`

	// ResultCacheSize is the maximum number of per-SHA256 scan results held
	// in the LRU cache shared across file and process scanners. Evicting the
	// oldest entry is cheap; set this large enough that hot binaries stay cached.
	ResultCacheSize int `yaml:"result_cache_size"`

	// AutorunConcurrency is the maximum number of autorun source goroutines
	// that may run in parallel during a single scan pass. Lower values reduce
	// I/O contention during startup; higher values speed up the first pass.
	AutorunConcurrency int `yaml:"autorun_concurrency"`
}

// ── Timing settings ───────────────────────────────────────────────────────────

type TimingSettings struct {
	SingleFileScanTimeoutSec      int `yaml:"single_file_scan_timeout_sec"`
	DedupWindowMin                int `yaml:"dedup_window_min"`
	AutorunScanIntervalMin        int `yaml:"autorun_scan_interval_min"`
	RulesSyncIntervalHour         int `yaml:"rules_sync_interval_hour"`
	SecretsScanIntervalMin        int `yaml:"secrets_scan_interval_min"`
	SingleTargetSecretsTimeoutMin int `yaml:"single_target_secrets_timeout_min"`
	StatsSyncIntervalMin          int `yaml:"stats_sync_interval_min"`
	CleanupIntervalHour           int `yaml:"cleanup_interval_hour"`
	EventRetentionDays            int `yaml:"event_retention_days"`
	HashSyncIntervalHour          int `yaml:"hash_sync_interval_hour"`
	StartupProcwalkDelaySec       int `yaml:"startup_procwalk_delay_sec"`
	StartupSecretsDelayMin        int `yaml:"startup_secrets_delay_min"`
	StartupAutorunDelaySec        int `yaml:"startup_autorun_delay_sec"`
}

// ── Rules settings ────────────────────────────────────────────────────────────

type RulesSettings struct {
	RulesFilepath         string `yaml:"rules_filepath"`
	RulesRemoteURL        string `yaml:"rules_remote_url"`
	RulesArchiveDir       string `yaml:"rules_archive_dir"`
	RulesArchiveCount     int    `yaml:"rules_archive_count"`
	RulesSyncIntervalHour int    `yaml:"rules_sync_interval_hour"`
}

// ── Secrets settings ──────────────────────────────────────────────────────────

type SecretsSettings struct {
	Enabled           bool     `yaml:"enabled"`
	ScanTargets       []string `yaml:"scan_targets"`
	ExcludedPaths     []string `yaml:"excluded_paths"`
	MinimumConfidence int      `yaml:"minimum_confidence"`
	IgnoreFile        string   `yaml:"ignore_file"`
	MatchContextLines int      `yaml:"match_context_lines"`
}

// ── Threat intelligence settings ──────────────────────────────────────────────

type ThreatIntelSettings struct {
	MalwareBazaarURL string  `yaml:"malwarebazaar_url"`
	APIKey           string  `yaml:"api_key"`
	BloomFilterPath  string  `yaml:"bloom_filter_path"`
	BloomCapacity    uint    `yaml:"bloom_capacity"`
	BloomFPRate      float64 `yaml:"bloom_fp_rate"`
}

// ── Alert policy settings ─────────────────────────────────────────────────────

// AlertPolicySettings replaces all hardcoded detection lists. Moving these
// into config lets operators tune detection sensitivity without recompiling.
type AlertPolicySettings struct {
	// Interpreters is the set of known shell and scripting interpreter paths.
	Interpreters []string `yaml:"interpreters"`

	// LOLBins is the set of executables commonly abused for living-off-the-land.
	LOLBins []string `yaml:"lolbins"`

	// DangerousCapabilities lists Linux capability names that warrant HIGH or
	// CRITICAL severity when observed in a process's effective capability set.
	DangerousCapabilities []string `yaml:"dangerous_capabilities"`

	// ProcessCapabilityExclusions maps process comm names to capabilities that
	// are expected for that process and should not trigger alerts.
	// Example: openvpn: [CAP_NET_ADMIN, CAP_NET_RAW]
	ProcessCapabilityExclusions map[string][]string `yaml:"process_capability_exclusions"`

	// HighValueInboundPorts triggers HIGH severity when a process binds to them.
	HighValueInboundPorts []uint16 `yaml:"high_value_inbound_ports"`

	// HighValueOutboundPorts triggers HIGH severity when a process connects out.
	HighValueOutboundPorts []uint16 `yaml:"high_value_outbound_ports"`

	// TrustedLDPaths is the whitelist of directories from which LD_PRELOAD and
	// LD_LIBRARY_PATH entries are considered legitimate. Any entry outside this
	// list triggers a HIGH severity alert regardless of the process identity.
	// Snap and other user-writable mount points are intentionally excluded —
	// they are wide surfaces that any user can write into.
	TrustedLDPaths []string `yaml:"trusted_ld_paths"`
}

// ── Log settings ──────────────────────────────────────────────────────────────

type LogSettings struct {
	Directory  string `yaml:"directory"`
	Filename   string `yaml:"filename"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   bool   `yaml:"compress"`
	Level      string `yaml:"level"`
}

// ── UI settings ───────────────────────────────────────────────────────────────

type UISettings struct {
	DefaultTheme    string `yaml:"default_theme"`
	WindowWidth     int    `yaml:"window_width"`
	WindowHeight    int    `yaml:"window_height"`
	MinWindowWidth  int    `yaml:"min_window_width"`
	MinWindowHeight int    `yaml:"min_window_height"`
	PageSize        int    `yaml:"page_size"`
}

// ── Load / save ───────────────────────────────────────────────────────────────

// LoadConfig reads and parses the YAML file at path, merges it over the
// compiled-in defaults, and returns a validated Config.
//
// SECURITY: The file must be owned by uid 0 on Linux. This prevents a
// less-privileged process from replacing the config to alter EDR behaviour.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}

	if err := checkOwnership(path); err != nil {
		return Config{}, fmt.Errorf("config: security check failed: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	cfg := defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: validation failed: %w", err)
	}

	cfg.excludeOwnFiles()
	return cfg, nil
}

// SaveConfig writes cfg to path with mode 0o600 (owner-read/write only).
func SaveConfig(cfg Config, path string) error {
	if path == "" {
		path = DefaultConfigPath()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("config: write temp: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

// DefaultConfigPath returns /etc/vajra/config.yaml.
func DefaultConfigPath() string {
	return "/etc/vajra/config.yaml"
}

// ── Validation ────────────────────────────────────────────────────────────────

func (c *Config) Validate() error {
	var errs []error

	switch c.GenericSettings.Mode {
	case ModeMonitor, ModeEnforce, ModeDiagnose:
	default:
		errs = append(errs, fmt.Errorf("generic_settings.mode must be one of: monitor, enforce, diagnose (got %q)", c.GenericSettings.Mode))
	}
	if c.GenericSettings.DBDirectory == "" {
		errs = append(errs, errors.New("generic_settings.db_directory must not be empty"))
	}
	if c.GenericSettings.DBFilename == "" {
		errs = append(errs, errors.New("generic_settings.db_filename must not be empty"))
	}
	if c.GenericSettings.WorkDirectory == "" {
		errs = append(errs, errors.New("generic_settings.work_directory must not be empty"))
	}

	if c.ScanSettings.YaraSnapshotBytes <= 0 {
		errs = append(errs, errors.New("scan_settings.yara_snapshot_bytes must be > 0"))
	}

	if c.PerformanceSettings.DefaultThreads <= 0 {
		errs = append(errs, errors.New("performance_settings.default_threads must be > 0"))
	}
	if c.PerformanceSettings.MaxAllowedThreads < c.PerformanceSettings.DefaultThreads {
		errs = append(errs, errors.New("performance_settings.max_allowed_threads must be >= default_threads"))
	}
	if c.PerformanceSettings.ScanQueueSize <= 0 {
		errs = append(errs, errors.New("performance_settings.scan_queue_size must be > 0"))
	}
	if p := c.PerformanceSettings.EBPFPerfRingPages; p <= 0 || (p&(p-1)) != 0 {
		errs = append(errs, fmt.Errorf("performance_settings.ebpf_perf_ring_pages must be a power of two > 0 (got %d)", p))
	}
	if c.PerformanceSettings.ResultCacheSize <= 0 {
		errs = append(errs, errors.New("performance_settings.result_cache_size must be > 0"))
	}
	if c.PerformanceSettings.AutorunConcurrency <= 0 {
		errs = append(errs, errors.New("performance_settings.autorun_concurrency must be > 0"))
	}

	if c.TimingSettings.DedupWindowMin <= 0 {
		errs = append(errs, errors.New("timing_settings.dedup_window_min must be > 0"))
	}

	if c.RulesSettings.RulesFilepath == "" {
		errs = append(errs, errors.New("rules_settings.rules_filepath must not be empty"))
	}

	if c.ThreatIntelSettings.BloomCapacity == 0 {
		errs = append(errs, errors.New("threat_intel_settings.bloom_capacity must be > 0"))
	}
	if c.ThreatIntelSettings.BloomFPRate <= 0 || c.ThreatIntelSettings.BloomFPRate >= 1 {
		errs = append(errs, fmt.Errorf("threat_intel_settings.bloom_fp_rate must be in (0, 1) (got %f)", c.ThreatIntelSettings.BloomFPRate))
	}

	switch c.UISettings.DefaultTheme {
	case "light", "dark", "system":
	default:
		errs = append(errs, fmt.Errorf("ui_settings.default_theme must be one of: light, dark, system (got %q)", c.UISettings.DefaultTheme))
	}

	return errors.Join(errs...)
}

// ── Defaults ──────────────────────────────────────────────────────────────────

func defaults() Config {
	return Config{
		GenericSettings: GenericSettings{
			Mode:          ModeMonitor,
			DBDirectory:   "/var/lib/vajra",
			DBFilename:    "vajra.db",
			WorkDirectory: "/var/lib/vajra/work",
		},
		ScanSettings: ScanSettings{
			TargetDirectory:   "/",
			MaxFileSizeBytes:  100 * 1024 * 1024,
			YaraSnapshotBytes: 128,
		},
		PerformanceSettings: PerformanceSettings{
			DefaultThreads:          4,
			MaxAllowedThreads:       16,
			StartupMaxThreads:       2,
			StartupRampupMin:        5,
			ScanQueueSize:           512,
			EBPFPerfRingPages:       64,
			YaraAutotuneIntervalSec: 60,
			ResultCacheSize:         10_000,
			AutorunConcurrency:      2,
		},
		TimingSettings: TimingSettings{
			SingleFileScanTimeoutSec:      30,
			DedupWindowMin:                15,
			AutorunScanIntervalMin:        60,
			SecretsScanIntervalMin:        60,
			SingleTargetSecretsTimeoutMin: 10,
			StatsSyncIntervalMin:          5,
			CleanupIntervalHour:           24,
			EventRetentionDays:            30,
			HashSyncIntervalHour:          24,
			StartupProcwalkDelaySec:       30,
			StartupSecretsDelayMin:        5,
			StartupAutorunDelaySec:        15,
		},
		RulesSettings: RulesSettings{
			RulesArchiveCount:     5,
			RulesSyncIntervalHour: 24,
		},
		SecretsSettings: SecretsSettings{
			Enabled:           true,
			ScanTargets:       []string{"/home", "/root", "/etc", "/opt", "/var", "/srv", "/run"},
			MinimumConfidence: 80,
			MatchContextLines: 3,
		},
		ThreatIntelSettings: ThreatIntelSettings{
			BloomCapacity: 10_000_000,
			BloomFPRate:   0.001,
		},
		AlertPolicy: alertPolicyDefaults(),
		LogSettings: LogSettings{
			Filename:   "vajra.log",
			MaxSizeMB:  100,
			MaxBackups: 5,
			MaxAgeDays: 30,
			Compress:   true,
			Level:      "info",
		},
		UISettings: UISettings{
			DefaultTheme:    "system",
			WindowWidth:     1280,
			WindowHeight:    800,
			MinWindowWidth:  900,
			MinWindowHeight: 600,
			PageSize:        50,
		},
	}
}

func alertPolicyDefaults() AlertPolicySettings {
	return AlertPolicySettings{
		Interpreters: []string{
			"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/fish",
			"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh", "/usr/bin/fish",
			"/bin/python", "/bin/python2", "/bin/python3",
			"/usr/bin/python", "/usr/bin/python2", "/usr/bin/python3",
			"/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/lua",
			"/usr/bin/node", "/usr/bin/nodejs",
		},
		LOLBins: []string{
			"awk", "base64", "bash", "busybox", "curl", "dd", "env", "find",
			"gdb", "grep", "install", "ld", "less", "mv", "nano", "nc",
			"ncat", "netcat", "nm", "nmap", "openssl", "perl", "php", "python",
			"python2", "python3", "ruby", "sed", "sh", "socat", "strace",
			"tee", "wget", "xxd",
		},
		DangerousCapabilities: []string{
			"CAP_SYS_ADMIN",
			"CAP_SYS_PTRACE",
			"CAP_SYS_MODULE",
			"CAP_SYS_RAWIO",
			"CAP_NET_ADMIN",
			"CAP_NET_RAW",
			"CAP_DAC_READ_SEARCH",
			"CAP_DAC_OVERRIDE",
			"CAP_SETUID",
			"CAP_SETGID",
			"CAP_CHOWN",
			"CAP_FOWNER",
			"CAP_KILL",
			"CAP_BPF",
			"CAP_PERFMON",
			"CAP_CHECKPOINT_RESTORE",
		},
		ProcessCapabilityExclusions: map[string][]string{},
		HighValueInboundPorts:       []uint16{22, 23, 3389, 5900, 5901, 6000},
		HighValueOutboundPorts:      []uint16{4444, 1337, 9001, 6667, 6697, 31337, 12345},
		// Snap and other user-writable mount points are excluded from trusted paths
		// because any user can write into them — they are not controlled by root.
		TrustedLDPaths: []string{
			"/lib",
			"/lib64",
			"/usr/lib",
			"/usr/lib64",
			"/usr/local/lib",
			"/usr/local/lib64",
		},
	}
}

// ── Auto-exclusion of own files ───────────────────────────────────────────────

func (c *Config) excludeOwnFiles() {
	dbPath := filepath.Join(c.GenericSettings.DBDirectory, c.GenericSettings.DBFilename)
	walPath := dbPath + "-wal"
	shmPath := dbPath + "-shm"

	own := []string{dbPath, walPath, shmPath}
	if c.ThreatIntelSettings.BloomFilterPath != "" {
		own = append(own, c.ThreatIntelSettings.BloomFilterPath)
	}
	if c.RulesSettings.RulesFilepath != "" {
		own = append(own, c.RulesSettings.RulesFilepath)
	}

	seen := make(map[string]struct{}, len(c.ScanSettings.ExcludedPaths)+len(own))
	for _, p := range c.ScanSettings.ExcludedPaths {
		seen[p] = struct{}{}
	}
	for _, p := range own {
		if _, ok := seen[p]; !ok {
			c.ScanSettings.ExcludedPaths = append(c.ScanSettings.ExcludedPaths, p)
			seen[p] = struct{}{}
		}
	}
}

// ── IsDefault ─────────────────────────────────────────────────────────────────

func IsDefault(c Config) bool {
	d := defaults()
	d.excludeOwnFiles()

	got, err1 := yaml.Marshal(c)
	want, err2 := yaml.Marshal(d)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(got) == string(want)
}
