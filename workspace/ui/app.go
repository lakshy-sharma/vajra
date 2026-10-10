// ui/app.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	sharedconfig "vajra/shared/config"
	shareddb "vajra/shared/db"
	"vajra/ui/internal/queries"
)

const writeConfigMaxBytes = 1 * 1024 * 1024 // 1 MiB — UI2

// ── UIConfig and sub-types ────────────────────────────────────────────────────
// Wrapper types with explicit camelCase json tags so the Wails binding
// generator produces idiomatic TypeScript. The full Config is never sent to
// the frontend — sensitive fields (API keys, DB paths) are excluded.

type UIGenericSettings struct {
	OperationMode string `json:"operationMode"`
	WorkDirectory string `json:"workDirectory"`
}

type UIThreatIntelSettings struct {
	BloomFilterPath string `json:"bloomFilterPath"`
}

type UITimingSettings struct {
	DedupWindowMin                int `json:"dedupWindowMin"`
	AutorunScanIntervalMin        int `json:"autorunScanIntervalMin"`
	SecretsScanIntervalMin        int `json:"secretsScanIntervalMin"`
	SingleTargetSecretsTimeoutMin int `json:"singleTargetSecretsTimeoutMin"`
	StatsSyncIntervalMin          int `json:"statsSyncIntervalMin"`
	CleanupIntervalHour           int `json:"cleanupIntervalHour"`
	EventRetentionDays            int `json:"eventRetentionDays"`
	HashSyncIntervalHour          int `json:"hashSyncIntervalHour"`
	RulesSyncIntervalHour         int `json:"rulesSyncIntervalHour"`
}

type UIPerformanceSettings struct {
	DefaultThreads     int `json:"defaultThreads"`
	MaxAllowedThreads  int `json:"maxAllowedThreads"`
	ScanQueueSize      int `json:"scanQueueSize"`
	ResultCacheSize    int `json:"resultCacheSize"`
	AutorunConcurrency int `json:"autorunConcurrency"`
}

type UIScanSettings struct {
	TargetDirectory   string `json:"targetDirectory"`
	MaxFileSizeBytes  int64  `json:"maxFileSizeBytes"`
	YaraSnapshotBytes int    `json:"yaraSnapshotBytes"`
}

type UIRulesSettings struct {
	RulesFilepath         string `json:"rulesFilepath"`
	RulesRemoteURL        string `json:"rulesRemoteURL"`
	RulesArchiveCount     int    `json:"rulesArchiveCount"`
	RulesSyncIntervalHour int    `json:"rulesSyncIntervalHour"`
}

type UILogSettings struct {
	Directory  string `json:"directory"`
	Level      string `json:"level"`
	MaxSizeMB  int    `json:"maxSizeMB"`
	MaxBackups int    `json:"maxBackups"`
	MaxAgeDays int    `json:"maxAgeDays"`
	Compress   bool   `json:"compress"`
}

type UIWindowSettings struct {
	DefaultTheme    string `json:"defaultTheme"`
	WindowWidth     int    `json:"windowWidth"`
	WindowHeight    int    `json:"windowHeight"`
	MinWindowWidth  int    `json:"minWindowWidth"`
	MinWindowHeight int    `json:"minWindowHeight"`
	PageSize        int    `json:"pageSize"`
}

type UIAlertPolicy struct {
	HighValueInboundPorts  []uint16 `json:"highValueInboundPorts"`
	HighValueOutboundPorts []uint16 `json:"highValueOutboundPorts"`
}

// UIConfig is everything the frontend can read and propose for writes.
// UI4: all json tags use camelCase consistently.
type UIConfig struct {
	GenericSettings     UIGenericSettings     `json:"genericSettings"`
	ThreatIntelSettings UIThreatIntelSettings `json:"threatIntelSettings"`
	Timing              UITimingSettings      `json:"timing"`
	Performance         UIPerformanceSettings `json:"performance"`
	Scan                UIScanSettings        `json:"scan"`
	Rules               UIRulesSettings       `json:"rules"`
	Log                 UILogSettings         `json:"log"`
	Window              UIWindowSettings      `json:"window"`
	AlertPolicy         UIAlertPolicy         `json:"alertPolicy"`
}

// ── Page result ───────────────────────────────────────────────────────────────

type Page[T any] struct {
	Items      []T   `json:"items"`
	TotalCount int64 `json:"totalCount"`
	Page       int   `json:"page"`
	PerPage    int   `json:"perPage"`
}

// ── App ───────────────────────────────────────────────────────────────────────

type App struct {
	ctx     context.Context
	cfgPath string
	initErr string

	// UI1: cfg cached after first load; invalidated on WriteConfig success.
	cfgMu sync.RWMutex
	cfg   *sharedconfig.Config

	db *shareddb.DB
	q  *queries.Queries
}

func NewApp(cfgPath string) *App {
	app := &App{cfgPath: cfgPath}

	cfg, err := sharedconfig.LoadConfig(cfgPath)
	if err != nil {
		app.initErr = fmt.Sprintf("Cannot load config %s: %v\n\nSet VAJRA_CONFIG to your config file path.", cfgPath, err)
		return app
	}
	app.cfg = &cfg

	dbPath := filepath.Join(cfg.GenericSettings.DBDirectory, cfg.GenericSettings.DBFilename)
	db, err := shareddb.OpenReadOnly(dbPath)
	if err != nil {
		app.initErr = fmt.Sprintf("Cannot open database %s: %v", dbPath, err)
		return app
	}

	app.db = db
	app.q = queries.New(db)
	return app
}

func (a *App) ready() error {
	if a.initErr != "" {
		return fmt.Errorf("%s", a.initErr)
	}
	return nil
}

func (a *App) InitError() string { return a.initErr }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

func (a *App) shutdown(_ context.Context) {
	if a.db != nil {
		_ = a.db.Close()
	}
}

// loadCfg returns the cached config. UI1: avoids re-reading YAML on every call.
func (a *App) loadCfg() (*sharedconfig.Config, error) {
	a.cfgMu.RLock()
	if a.cfg != nil {
		defer a.cfgMu.RUnlock()
		return a.cfg, nil
	}
	a.cfgMu.RUnlock()

	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	cfg, err := sharedconfig.LoadConfig(a.cfgPath)
	if err != nil {
		return nil, err
	}
	a.cfg = &cfg
	return a.cfg, nil
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func (a *App) GetTotals() ([]queries.StatRow, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.q.Totals()
}

func (a *App) GetStatsByDateRange(startUnix, endUnix int64) ([]queries.StatRow, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.q.StatsByDateRange(startUnix, endUnix)
}

// ── Detections ────────────────────────────────────────────────────────────────

type DetectionFilters struct {
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Source   string `json:"source"`
}

func (a *App) GetDetections(page, perPage int, filters DetectionFilters) (Page[queries.DetectionRow], error) {
	if err := a.ready(); err != nil {
		return Page[queries.DetectionRow]{}, err
	}
	if page < 1 {
		page = 1
	}
	// UI3: return an error instead of silently clamping — the frontend shows it.
	if perPage < 1 || perPage > 200 {
		return Page[queries.DetectionRow]{}, fmt.Errorf("perPage must be 1–200 (got %d)", perPage)
	}
	rows, total, err := a.q.Detections(page, perPage, filters.Severity, filters.Status, filters.Source)
	if err != nil {
		return Page[queries.DetectionRow]{}, err
	}
	return Page[queries.DetectionRow]{Items: rows, TotalCount: total, Page: page, PerPage: perPage}, nil
}

// ── Events ────────────────────────────────────────────────────────────────────

func (a *App) GetSecurityEvents(page, perPage int) (Page[queries.SecurityEventRow], error) {
	if err := a.ready(); err != nil {
		return Page[queries.SecurityEventRow]{}, err
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		return Page[queries.SecurityEventRow]{}, fmt.Errorf("perPage must be 1–200 (got %d)", perPage)
	}
	rows, total, err := a.q.SecurityEvents(page, perPage)
	if err != nil {
		return Page[queries.SecurityEventRow]{}, err
	}
	return Page[queries.SecurityEventRow]{Items: rows, TotalCount: total, Page: page, PerPage: perPage}, nil
}

func (a *App) GetNetworkEvents(page, perPage int) (Page[queries.NetworkEventRow], error) {
	if err := a.ready(); err != nil {
		return Page[queries.NetworkEventRow]{}, err
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		return Page[queries.NetworkEventRow]{}, fmt.Errorf("perPage must be 1–200 (got %d)", perPage)
	}
	rows, total, err := a.q.NetworkEvents(page, perPage)
	if err != nil {
		return Page[queries.NetworkEventRow]{}, err
	}
	return Page[queries.NetworkEventRow]{Items: rows, TotalCount: total, Page: page, PerPage: perPage}, nil
}

func (a *App) GetMemoryEvents(page, perPage int) (Page[queries.MemoryEventRow], error) {
	if err := a.ready(); err != nil {
		return Page[queries.MemoryEventRow]{}, err
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		return Page[queries.MemoryEventRow]{}, fmt.Errorf("perPage must be 1–200 (got %d)", perPage)
	}
	rows, total, err := a.q.MemoryEvents(page, perPage)
	if err != nil {
		return Page[queries.MemoryEventRow]{}, err
	}
	return Page[queries.MemoryEventRow]{Items: rows, TotalCount: total, Page: page, PerPage: perPage}, nil
}

// ── Autoruns ──────────────────────────────────────────────────────────────────

func (a *App) GetAutoruns() ([]queries.AutorunRow, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.q.Autoruns()
}

// ── Config ────────────────────────────────────────────────────────────────────

// GetConfig returns the cached UIConfig with sensitive fields excluded.
// UI1: uses loadCfg — no disk read after first call.
func (a *App) GetConfig() (UIConfig, error) {
	cfg, err := a.loadCfg()
	if err != nil {
		return UIConfig{}, err
	}
	return configToUI(cfg), nil
}

func configToUI(cfg *sharedconfig.Config) UIConfig {
	return UIConfig{
		GenericSettings: UIGenericSettings{
			OperationMode: string(cfg.GenericSettings.Mode),
			WorkDirectory: cfg.GenericSettings.WorkDirectory,
		},
		ThreatIntelSettings: UIThreatIntelSettings{
			BloomFilterPath: cfg.ThreatIntelSettings.BloomFilterPath,
		},
		Timing: UITimingSettings{
			DedupWindowMin:                cfg.TimingSettings.DedupWindowMin,
			AutorunScanIntervalMin:        cfg.TimingSettings.AutorunScanIntervalMin,
			SecretsScanIntervalMin:        cfg.TimingSettings.SecretsScanIntervalMin,
			SingleTargetSecretsTimeoutMin: cfg.TimingSettings.SingleTargetSecretsTimeoutMin,
			StatsSyncIntervalMin:          cfg.TimingSettings.StatsSyncIntervalMin,
			CleanupIntervalHour:           cfg.TimingSettings.CleanupIntervalHour,
			EventRetentionDays:            cfg.TimingSettings.EventRetentionDays,
			HashSyncIntervalHour:          cfg.TimingSettings.HashSyncIntervalHour,
			RulesSyncIntervalHour:         cfg.TimingSettings.RulesSyncIntervalHour,
		},
		Performance: UIPerformanceSettings{
			DefaultThreads:     cfg.PerformanceSettings.DefaultThreads,
			MaxAllowedThreads:  cfg.PerformanceSettings.MaxAllowedThreads,
			ScanQueueSize:      cfg.PerformanceSettings.ScanQueueSize,
			ResultCacheSize:    cfg.PerformanceSettings.ResultCacheSize,
			AutorunConcurrency: cfg.PerformanceSettings.AutorunConcurrency,
		},
		Scan: UIScanSettings{
			TargetDirectory:   cfg.ScanSettings.TargetDirectory,
			MaxFileSizeBytes:  cfg.ScanSettings.MaxFileSizeBytes,
			YaraSnapshotBytes: cfg.ScanSettings.YaraSnapshotBytes,
		},
		Rules: UIRulesSettings{
			RulesFilepath:         cfg.RulesSettings.RulesFilepath,
			RulesRemoteURL:        cfg.RulesSettings.RulesRemoteURL,
			RulesArchiveCount:     cfg.RulesSettings.RulesArchiveCount,
			RulesSyncIntervalHour: cfg.RulesSettings.RulesSyncIntervalHour,
		},
		Log: UILogSettings{
			Directory:  cfg.LogSettings.Directory,
			Level:      cfg.LogSettings.Level,
			MaxSizeMB:  cfg.LogSettings.MaxSizeMB,
			MaxBackups: cfg.LogSettings.MaxBackups,
			MaxAgeDays: cfg.LogSettings.MaxAgeDays,
			Compress:   cfg.LogSettings.Compress,
		},
		Window: UIWindowSettings{
			DefaultTheme:    cfg.UISettings.DefaultTheme,
			WindowWidth:     cfg.UISettings.WindowWidth,
			WindowHeight:    cfg.UISettings.WindowHeight,
			MinWindowWidth:  cfg.UISettings.MinWindowWidth,
			MinWindowHeight: cfg.UISettings.MinWindowHeight,
			PageSize:        cfg.UISettings.PageSize,
		},
		AlertPolicy: UIAlertPolicy{
			HighValueInboundPorts:  cfg.AlertPolicy.HighValueInboundPorts,
			HighValueOutboundPorts: cfg.AlertPolicy.HighValueOutboundPorts,
		},
	}
}

// WriteConfig merges the incoming UIConfig over the current full config and
// writes the result via pkexec → vajra config-write.
// UI2: rejects payloads > 1 MiB before any processing.
func (a *App) WriteConfig(configJSON string) error {
	if len(configJSON) > writeConfigMaxBytes {
		return fmt.Errorf("WriteConfig: payload too large (%d bytes, max %d)", len(configJSON), writeConfigMaxBytes)
	}

	var incoming UIConfig
	if err := json.Unmarshal([]byte(configJSON), &incoming); err != nil {
		return fmt.Errorf("WriteConfig: invalid JSON: %w", err)
	}

	// Load full current config — UIConfig is a subset, so we merge over the
	// on-disk config to preserve fields the UI doesn't expose (DB paths, keys).
	full, err := sharedconfig.LoadConfig(a.cfgPath)
	if err != nil {
		return fmt.Errorf("WriteConfig: load current config: %w", err)
	}

	// Apply UIConfig fields onto full config.
	full.GenericSettings.Mode = sharedconfig.OperationMode(incoming.GenericSettings.OperationMode)
	full.GenericSettings.WorkDirectory = incoming.GenericSettings.WorkDirectory
	full.ThreatIntelSettings.BloomFilterPath = incoming.ThreatIntelSettings.BloomFilterPath
	full.TimingSettings.DedupWindowMin = incoming.Timing.DedupWindowMin
	full.TimingSettings.AutorunScanIntervalMin = incoming.Timing.AutorunScanIntervalMin
	full.TimingSettings.SecretsScanIntervalMin = incoming.Timing.SecretsScanIntervalMin
	full.TimingSettings.SingleTargetSecretsTimeoutMin = incoming.Timing.SingleTargetSecretsTimeoutMin
	full.TimingSettings.StatsSyncIntervalMin = incoming.Timing.StatsSyncIntervalMin
	full.TimingSettings.CleanupIntervalHour = incoming.Timing.CleanupIntervalHour
	full.TimingSettings.EventRetentionDays = incoming.Timing.EventRetentionDays
	full.TimingSettings.HashSyncIntervalHour = incoming.Timing.HashSyncIntervalHour
	full.TimingSettings.RulesSyncIntervalHour = incoming.Timing.RulesSyncIntervalHour
	full.PerformanceSettings.DefaultThreads = incoming.Performance.DefaultThreads
	full.PerformanceSettings.MaxAllowedThreads = incoming.Performance.MaxAllowedThreads
	full.PerformanceSettings.ScanQueueSize = incoming.Performance.ScanQueueSize
	full.PerformanceSettings.ResultCacheSize = incoming.Performance.ResultCacheSize
	full.PerformanceSettings.AutorunConcurrency = incoming.Performance.AutorunConcurrency
	full.ScanSettings.TargetDirectory = incoming.Scan.TargetDirectory
	full.ScanSettings.MaxFileSizeBytes = incoming.Scan.MaxFileSizeBytes
	full.ScanSettings.YaraSnapshotBytes = incoming.Scan.YaraSnapshotBytes
	full.RulesSettings.RulesFilepath = incoming.Rules.RulesFilepath
	full.RulesSettings.RulesRemoteURL = incoming.Rules.RulesRemoteURL
	full.RulesSettings.RulesArchiveCount = incoming.Rules.RulesArchiveCount
	full.RulesSettings.RulesSyncIntervalHour = incoming.Rules.RulesSyncIntervalHour
	full.LogSettings.Directory = incoming.Log.Directory
	full.LogSettings.Level = incoming.Log.Level
	full.LogSettings.MaxSizeMB = incoming.Log.MaxSizeMB
	full.LogSettings.MaxBackups = incoming.Log.MaxBackups
	full.LogSettings.MaxAgeDays = incoming.Log.MaxAgeDays
	full.LogSettings.Compress = incoming.Log.Compress
	full.UISettings.DefaultTheme = incoming.Window.DefaultTheme
	full.UISettings.WindowWidth = incoming.Window.WindowWidth
	full.UISettings.WindowHeight = incoming.Window.WindowHeight
	full.UISettings.MinWindowWidth = incoming.Window.MinWindowWidth
	full.UISettings.MinWindowHeight = incoming.Window.MinWindowHeight
	full.UISettings.PageSize = incoming.Window.PageSize
	full.AlertPolicy.HighValueInboundPorts = incoming.AlertPolicy.HighValueInboundPorts
	full.AlertPolicy.HighValueOutboundPorts = incoming.AlertPolicy.HighValueOutboundPorts

	fullJSON, err := json.Marshal(full)
	if err != nil {
		return fmt.Errorf("WriteConfig: marshal: %w", err)
	}

	cmd := exec.Command("pkexec",
		"/opt/vajra/vajra",
		"config-write",
		"--config", a.cfgPath,
	)
	cmd.Stdin = bytes.NewReader(fullJSON)

	out, err := cmd.CombinedOutput()
	if err != nil {
		runtime.LogWarningf(a.ctx, "config-write: %v — output: %s", err, out)
		return fmt.Errorf("config write failed: %w", err)
	}

	// Invalidate cache so next GetConfig picks up the newly written values.
	a.cfgMu.Lock()
	a.cfg = nil
	a.cfgMu.Unlock()
	return nil
}
