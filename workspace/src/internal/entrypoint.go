/*
internal/entrypoint.go
Package internal for the vajra project.
All function declared here are supposed to be used inside the project and
the function APIs are subject to change at authr's discretion.

Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package internal

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"vajra/internal/db"
	"vajra/internal/utilities"
)

// Entrypoint function to parse the configurations and start services.
func Entrypoint(configPath string) {
	// Parse the configuration file and load it.
	AppConfig, err := utilities.LoadConfig(configPath)
	if err != nil {
		log.Error().Msg("failed to load configuration")
	}

	// Setup logger
	logger := utilities.GetLogger(AppConfig)

	// Setup work directory
	if err := os.MkdirAll(AppConfig.GenericSettings.WorkDirectory, 0o755); err != nil {
		logger.Error().Err(err).Str("recommendation", "change your work directory").Msg("failed to setup work directory.")
		return
	}

	// Create the required folder and setup the DB.
	// Create a dbHandler to pass into another database.
	if err := os.MkdirAll(AppConfig.GenericSettings.DBDirectory, 0o755); err != nil {
		logger.Error().Err(err).Str("recommendation", "change your db directory").Msg("failed to setup database directory")
		return
	}
	dbPath := filepath.Join(AppConfig.GenericSettings.DBDirectory, AppConfig.GenericSettings.DBFilename)
	database, err := db.Open(dbPath, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to open database")
		return
	}
	defer database.Close()
	// Log startup information
	logger.Info().
		Str("version", "0.0.1").
		Str("mode", AppConfig.GenericSettings.OperationMode).
		Str("target", AppConfig.ScanSettings.TargetDirectory).
		Str("rules", AppConfig.ScanSettings.RulesFilepath).
		Int("pid", os.Getpid()).
		Msg("starting_vajra_edr")

	// Start main operations.
	switch AppConfig.GenericSettings.OperationMode {
	// case "quick_scan":
	// runInstantScan(logger, &AppConfig, dbHandler)
	case "monitor":
		startServiceMode(logger, &AppConfig, database)
	default:
		logger.Fatal().
			Str("mode", AppConfig.GenericSettings.OperationMode).
			Msg("unknown operation mode")
	}
}
