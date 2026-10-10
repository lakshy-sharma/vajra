// internal/entrypoint.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package internal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vajra/internal/utilities"

	"github.com/rs/zerolog"
	daemondb "vajra/internal/db"

	sharedconfig "vajra/shared/config"
)

// Entrypoint is the daemon's main entry point. It loads config from YAML,
// opens the database (running migrations), merges any stored config from the
// app_config table (DB wins except for DBDirectory/DBFilename), then hands off
// to startServiceMode.
func Entrypoint(configPath string) {
	// 1. Load config from YAML — this is authoritative for DBDirectory/DBFilename.
	cfg, err := sharedconfig.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vajra: load config: %v\n", err)
		os.Exit(1)
	}

	// 2. Set up logger (uses cfg for log level/path).
	logger := utilities.GetLogger(&cfg)

	// 3. Ensure required directories exist.
	for _, dir := range []string{
		cfg.GenericSettings.DBDirectory,
		cfg.GenericSettings.WorkDirectory,
		cfg.RulesSettings.RulesArchiveDir,
	} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			logger.Fatal().Err(err).Str("dir", dir).Msg("failed to create directory")
		}
	}

	// 4. Open database and run migrations.
	dbPath := filepath.Join(cfg.GenericSettings.DBDirectory, cfg.GenericSettings.DBFilename)
	database, err := daemondb.Open(dbPath)
	if err != nil {
		logger.Fatal().Err(err).Str("path", dbPath).Msg("failed to open database")
	}
	logger.Info().Str("path", dbPath).Msg("database ready")

	// 5. Merge stored config from app_config (DB wins, except DBDirectory/DBFilename).
	//    On first start insert the YAML-derived config as the initial blob.
	cfg = mergeOrSeedAppConfig(database.SQL(), cfg, configPath, logger)

	// 6. Load system information (hostname, machine ID, kernel version, …).
	sysInfo, err := utilities.LoadSystemInfo()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to load system info")
	}

	logger.Info().
		Str("machine_id", sysInfo.MachineID).
		Msg("vajra daemon starting")

	startServiceMode(logger, &cfg, database, sysInfo)
}

// mergeOrSeedAppConfig reads the app_config row if it exists and merges it
// into cfg (DB wins for every field except DBDirectory and DBFilename which
// must always come from YAML). If no row exists it writes the initial blob.
func mergeOrSeedAppConfig(db *sql.DB, cfg sharedconfig.Config, yamlPath string, logger *zerolog.Logger) sharedconfig.Config {
	// Preserve the YAML-only fields before any merge.
	yamlDBDir := cfg.GenericSettings.DBDirectory
	yamlDBFile := cfg.GenericSettings.DBFilename

	var configJSON string
	err := db.QueryRow(`SELECT config_json FROM app_config WHERE id = 1`).Scan(&configJSON)
	if err == sql.ErrNoRows {
		// First start: seed the table from the YAML-derived config.
		blob, jsonErr := json.Marshal(cfg)
		if jsonErr != nil {
			logger.Warn().Err(jsonErr).Msg("app_config: failed to marshal config; skipping seed")
			return cfg
		}
		if _, execErr := db.Exec(
			`INSERT INTO app_config (id, config_json, yaml_path) VALUES (1, ?, ?)`,
			string(blob), yamlPath,
		); execErr != nil {
			logger.Warn().Err(execErr).Msg("app_config: failed to seed initial config")
		}
		return cfg
	}
	if err != nil {
		logger.Warn().Err(err).Msg("app_config: read failed; using YAML config")
		return cfg
	}

	// Merge: unmarshal the DB blob over cfg (DB wins).
	var merged sharedconfig.Config
	if err := json.Unmarshal([]byte(configJSON), &merged); err != nil {
		logger.Warn().Err(err).Msg("app_config: unmarshal failed; using YAML config")
		return cfg
	}

	// Chicken-and-egg protection: DBDirectory and DBFilename must always
	// come from YAML because we need them to find the DB in the first place.
	merged.GenericSettings.DBDirectory = yamlDBDir
	merged.GenericSettings.DBFilename = yamlDBFile

	logger.Info().Msg("app_config: merged stored config from database")
	return merged
}
