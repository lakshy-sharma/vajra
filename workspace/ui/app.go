// ui/app.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License
//
// App is the Wails backend. All exported methods become callable from the
// React frontend via the generated wailsjs/go/main/App bindings.
//
// Security invariants enforced here:
//   - The DB is opened read-only (OpenReadOnly); the UI never writes event data.
//   - Config writes go through pkexec → vajra config-write, never directly.
//   - DBDirectory and DBFilename are never sent to the frontend (filtered in
//     GetConfig / excluded from the return value).

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	sharedconfig "vajra/shared/config"
	shareddb "vajra/shared/db"
	"vajra/ui/internal/queries"
)

// ── Public result types ───────────────────────────────────────────────────────
// These are what the frontend receives; they mirror shared/models but with
// only the fields the UI needs (avoiding leaking internal DB IDs etc.).

type Page[T any] struct {
	Items      []T   `json:"items"`
	TotalCount int64 `json:"totalCount"`
	Page       int   `json:"page"`
	PerPage    int   `json:"perPage"`
}

// UIConfig is the config the frontend can read and submit for writes.
// DBDirectory and DBFilename are intentionally absent.

// UIGenericSettings is the subset of GenericSettings safe for the frontend.
type UIGenericSettings struct {
	OperationMode string `json:"operationMode"`
	WorkDirectory string `json:"workDirectory"`
}

// UIAPIServerSettings mirrors APIServerSettings for frontend use.
type UIAPIServerSettings struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// UIThreatIntelSettings is the subset of ThreatIntelSettings safe for the
// frontend. MalwareBazaarAuthKey is intentionally excluded.
type UIThreatIntelSettings struct {
	BloomFilterPath      string `json:"bloom_filter_path"`
	HashSyncIntervalHour int    `json:"hash_sync_interval_hour"`
}

type UIConfig struct {
	GenericSettings     UIGenericSettings                `json:"genericSettings"`
	APIServerSettings   UIAPIServerSettings              `json:"apiServerSettings"`
	TimingSettings      sharedconfig.TimingSettings      `json:"timingSettings"`
	PerformanceSettings sharedconfig.PerformanceSettings `json:"performanceSettings"`
	RulesSettings       sharedconfig.RulesSettings       `json:"rulesSettings"`
	ThreatIntelSettings UIThreatIntelSettings            `json:"threatIntelSettings"`
	Logging             sharedconfig.LoggingSettings     `json:"logging"`
}

// ── App ───────────────────────────────────────────────────────────────────────

type App struct {
	ctx     context.Context
	cfgPath string
	initErr string // non-empty when config/db could not be loaded; surfaced to the frontend
	db      *shareddb.DB
	q       *queries.Queries
}

// NewApp always returns a valid *App. If config or DB cannot be opened the
// error is stored in initErr and every data method will return it — this lets
// Wails open the window and show a meaningful error instead of crashing during
// binding generation (which runs before the window opens).
func NewApp(cfgPath string) *App {
	app := &App{cfgPath: cfgPath}

	cfg, err := sharedconfig.LoadConfig(cfgPath)
	if err != nil {
		app.initErr = fmt.Sprintf("Cannot load config %s: %v\n\nSet VAJRA_CONFIG to your config file path.", cfgPath, err)
		return app
	}

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

// ready returns an error if the app failed to initialise.
func (a *App) ready() error {
	if a.initErr != "" {
		return fmt.Errorf("%s", a.initErr)
	}
	return nil
}

// InitError lets the frontend display the startup error message, if any.
func (a *App) InitError() string { return a.initErr }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(_ context.Context) {
	if a.db != nil {
		_ = a.db.Close()
	}
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func (a *App) GetTotals() ([]queries.StatRow, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.q.Totals()
}

func (a *App) GetStatsByDateRange(start, end string) ([]queries.StatRow, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	return a.q.StatsByDateRange(start, end)
}

// ── Detections ────────────────────────────────────────────────────────────────

type DetectionFilters struct {
	Severity string `json:"severity"` // empty = all
	Status   string `json:"status"`   // empty = all
	Source   string `json:"source"`   // empty = all
}

func (a *App) GetDetections(page, perPage int, filters DetectionFilters) (Page[queries.DetectionRow], error) {
	if err := a.ready(); err != nil {
		return Page[queries.DetectionRow]{}, err
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
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
		perPage = 50
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
		perPage = 50
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
		perPage = 50
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

// GetConfig returns the current on-disk config with sensitive fields removed.
// MalwareBazaarAuthKey and DB paths are never sent to the frontend.
func (a *App) GetConfig() (UIConfig, error) {
	cfg, err := sharedconfig.LoadConfig(a.cfgPath)
	if err != nil {
		return UIConfig{}, err
	}

	var out UIConfig
	out.GenericSettings.OperationMode = cfg.GenericSettings.OperationMode
	out.GenericSettings.WorkDirectory = cfg.GenericSettings.WorkDirectory
	out.APIServerSettings.Host = cfg.APIServerSettings.Host
	out.APIServerSettings.Port = cfg.APIServerSettings.Port
	out.TimingSettings = cfg.TimingSettings
	out.PerformanceSettings = cfg.PerformanceSettings
	out.RulesSettings = cfg.RulesSettings
	out.ThreatIntelSettings.BloomFilterPath = cfg.ThreatIntelSettings.BloomFilterPath           // → bloom_filter_path
	out.ThreatIntelSettings.HashSyncIntervalHour = cfg.ThreatIntelSettings.HashSyncIntervalHour // → hash_sync_interval_hour
	out.Logging = cfg.Logging
	return out, nil
}

// WriteConfig pipes configJSON (a full Config JSON) to
//
//	pkexec /opt/vajra/vajra config-write --config <cfgPath>
//
// polkit presents the native auth dialog. Returns nil on success.
func (a *App) WriteConfig(configJSON string) error {
	// Validate that the incoming string is valid JSON that decodes into Config.
	var check sharedconfig.Config
	if err := json.Unmarshal([]byte(configJSON), &check); err != nil {
		return fmt.Errorf("WriteConfig: invalid JSON: %w", err)
	}

	cmd := exec.Command("pkexec",
		"/opt/vajra/vajra",
		"config-write",
		"--config", a.cfgPath,
	)
	cmd.Stdin = bytes.NewBufferString(configJSON)

	out, err := cmd.CombinedOutput()
	if err != nil {
		runtime.LogWarningf(a.ctx, "config-write: %v — output: %s", err, out)
		return fmt.Errorf("config write failed: %w", err)
	}
	return nil
}
