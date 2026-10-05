// internal/entrypoint.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package internal

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"vajra/internal/db"
	"vajra/internal/utilities"
)

func Entrypoint(configPath string) {
	cfg, err := utilities.LoadConfig(configPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", configPath).Msg("failed to load configuration")
		return
	}

	logger := utilities.GetLogger(cfg)

	for _, dir := range []string{
		cfg.GenericSettings.WorkDirectory,
		cfg.GenericSettings.DBDirectory,
		cfg.RulesSettings.RulesArchiveDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			logger.Fatal().Err(err).Str("path", dir).Msg("failed to create directory")
			return
		}
	}

	dbPath := filepath.Join(cfg.GenericSettings.DBDirectory, cfg.GenericSettings.DBFilename)
	database, err := db.Open(dbPath, logger)
	if err != nil {
		logger.Fatal().Err(err).Str("path", dbPath).Msg("failed to open database")
		return
	}
	defer database.Close()

	sysInfo, err := utilities.LoadSystemInfo()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to load system info")
		return
	}

	logger.Info().
		Str("version", "0.0.1").
		Str("mode", cfg.GenericSettings.OperationMode).
		Str("target", cfg.ScanSettings.TargetDirectory).
		Str("rules", cfg.RulesSettings.RulesFilepath).
		Int("pid", os.Getpid()).
		Str("machine_id", sysInfo.MachineID).
		Int64("boot_epoch", sysInfo.BootEpoch).
		Msg("starting vajra edr")

	switch cfg.GenericSettings.OperationMode {
	case "monitor":
		startServiceMode(logger, &cfg, database, sysInfo)
	default:
		logger.Fatal().Str("mode", cfg.GenericSettings.OperationMode).Msg("unknown operation mode")
	}
}
