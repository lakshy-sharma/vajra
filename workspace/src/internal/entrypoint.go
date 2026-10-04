package internal

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"vajra/internal/db"
	"vajra/internal/utilities"
)

func Entrypoint(configPath string) {
	AppConfig, err := utilities.LoadConfig(configPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", configPath).Msg("failed to load configuration")
		return
	}

	logger := utilities.GetLogger(AppConfig)

	if err := os.MkdirAll(AppConfig.GenericSettings.WorkDirectory, 0o755); err != nil {
		logger.Fatal().Err(err).Str("path", AppConfig.GenericSettings.WorkDirectory).Msg("failed to create work directory")
		return
	}

	if err := os.MkdirAll(AppConfig.GenericSettings.DBDirectory, 0o755); err != nil {
		logger.Fatal().Err(err).Str("path", AppConfig.GenericSettings.DBDirectory).Msg("failed to create database directory")
		return
	}

	if err := os.MkdirAll(AppConfig.RulesSettings.RulesArchiveDir, 0o755); err != nil {
		logger.Fatal().Err(err).Str("path", AppConfig.RulesSettings.RulesArchiveDir).Msg("failed to create rules archive directory")
		return
	}

	dbPath := filepath.Join(AppConfig.GenericSettings.DBDirectory, AppConfig.GenericSettings.DBFilename)
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
		Str("mode", AppConfig.GenericSettings.OperationMode).
		Str("target", AppConfig.ScanSettings.TargetDirectory).
		Str("rules", AppConfig.RulesSettings.RulesFilepath).
		Int("pid", os.Getpid()).
		Str("machine_id", sysInfo.MachineID).
		Int64("boot_epoch", sysInfo.BootEpoch).
		Msg("starting vajra edr")

	switch AppConfig.GenericSettings.OperationMode {
	case "monitor":
		startServiceMode(logger, &AppConfig, database, sysInfo)
	default:
		logger.Fatal().Str("mode", AppConfig.GenericSettings.OperationMode).Msg("unknown operation mode")
	}
}
