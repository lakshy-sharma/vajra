// internal/entrypoint.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vajra/internal/utilities"

	"github.com/rs/zerolog"
	daemondb "vajra/internal/db"
	sharedconfig "vajra/shared/config"
	shareddb "vajra/shared/db"
)

// currentSchemaVersion is incremented when Config adds required fields that
// would break an existing stored blob. On mismatch the stored blob is ignored
// and the YAML config is re-seeded. J15: was missing entirely.
const currentSchemaVersion = 1

// Entrypoint is the daemon's main entry point. It loads config from YAML,
// opens the database (running migrations), merges any stored config from the
// app_config table, then hands off to startServiceMode.
func Entrypoint(configPath string) {
	cfg, err := sharedconfig.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vajra: load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := utilities.GetLogger(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vajra: setup logger: %v\n", err)
		os.Exit(1)
	}

	for _, dir := range []string{
		cfg.GenericSettings.DBDirectory,
		cfg.GenericSettings.WorkDirectory,
		cfg.RulesSettings.RulesArchiveDir,
	} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			logger.Fatal().Err(err).Str("dir", dir).Msg("failed to create directory")
		}
	}

	dbPath := filepath.Join(cfg.GenericSettings.DBDirectory, cfg.GenericSettings.DBFilename)
	database, err := daemondb.Open(dbPath)
	if err != nil {
		logger.Fatal().Err(err).Str("path", dbPath).Msg("failed to open database")
	}
	logger.Info().Str("path", dbPath).Msg("database ready")

	// J14: was calling database.SQL() which exposes *sql.DB — removed by D1.
	// database itself implements shareddb.DBConn via delegation.
	cfg = mergeOrSeedAppConfig(context.Background(), database, cfg, configPath, logger)

	sysInfo, err := utilities.LoadSystemInfo()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to load system info")
	}

	logger.Info().
		Str("machine_id", sysInfo.MachineID).
		Msg("vajra daemon starting")

	startServiceMode(logger, &cfg, database, sysInfo)
}

// mergeOrSeedAppConfig reads the app_config row and merges it into cfg.
// DB wins for every field except DBDirectory and DBFilename, which must
// always come from YAML because we need them to locate the DB itself.
//
// J14: uses DBConn instead of raw *sql.DB.
// J15: stores and checks SchemaVersion — if the stored blob predates the
// current schema, it is discarded and the YAML config is re-seeded.
func mergeOrSeedAppConfig(ctx context.Context, db shareddb.DBConn, cfg sharedconfig.Config, yamlPath string, logger *zerolog.Logger) sharedconfig.Config {
	yamlDBDir := cfg.GenericSettings.DBDirectory
	yamlDBFile := cfg.GenericSettings.DBFilename

	var configJSON string
	var schemaVersion int
	err := db.QueryRowContext(ctx, `SELECT config_json, schema_version FROM app_config WHERE id = 1`).
		Scan(&configJSON, &schemaVersion)
	if err != nil {
		// First start or read error: seed the table from YAML config.
		blob, jsonErr := json.Marshal(cfg)
		if jsonErr != nil {
			logger.Warn().Err(jsonErr).Msg("app_config: marshal failed; skipping seed")
			return cfg
		}
		if _, execErr := db.ExecContext(ctx,
			`INSERT OR REPLACE INTO app_config (id, config_json, schema_version, yaml_path) VALUES (1, ?, ?, ?)`,
			string(blob), currentSchemaVersion, yamlPath,
		); execErr != nil {
			logger.Warn().Err(execErr).Msg("app_config: seed failed")
		}
		return cfg
	}

	// Discard stored blobs from an older schema — required fields may be
	// missing and unmarshaling would silently produce zero values.
	if schemaVersion < currentSchemaVersion {
		logger.Warn().
			Int("stored", schemaVersion).
			Int("current", currentSchemaVersion).
			Msg("app_config: schema version mismatch; re-seeding from YAML")
		blob, _ := json.Marshal(cfg)
		_, _ = db.ExecContext(ctx,
			`UPDATE app_config SET config_json = ?, schema_version = ?, yaml_path = ? WHERE id = 1`,
			string(blob), currentSchemaVersion, yamlPath,
		)
		return cfg
	}

	var merged sharedconfig.Config
	if err := json.Unmarshal([]byte(configJSON), &merged); err != nil {
		logger.Warn().Err(err).Msg("app_config: unmarshal failed; using YAML config")
		return cfg
	}

	// Chicken-and-egg: these fields must always come from YAML because
	// we need them before the DB can be opened.
	merged.GenericSettings.DBDirectory = yamlDBDir
	merged.GenericSettings.DBFilename = yamlDBFile

	logger.Info().Msg("app_config: merged stored config from database")
	return merged
}
