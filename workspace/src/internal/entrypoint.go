/*
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

	"github.com/rs/zerolog/log"
)

// This is the main function which parses complete config and starts relevant activities
func Entrypoint(config_path string) {
	var err error

	// Parse the configuration file and load it.
	GlobalConfig, err = loadConfig(config_path)
	if err != nil {
		log.Error().Msg("failed to load configuration")
	}

	// Setup logging.
	logger = getLogger(GlobalConfig)

	// Setup temp directory for working.
	if err := os.MkdirAll(GlobalConfig.GenericSettings.WorkDirectory, 0755); err != nil {
		logger.Error().Err(err).Str("recommended_action", "change your work directory").Msg("failed to setup work directory.")
		return
	}

	// Setup database
	if err := os.MkdirAll(GlobalConfig.GenericSettings.DbDirectory, 0755); err != nil {
		logger.Error().Err(err).Str("recommended_action", "change your db directory").Msg("failed to setup database directory")
		return
	}
	setupDB()

	// Start the code into designated mode.
	logger.Info().Str("operation_mode", GlobalConfig.GenericSettings.OperationMode).Str("scan_target", GlobalConfig.ScanSettings.TargetDirectory).Msg("locked and loaded ready to go!")

	switch GlobalConfig.GenericSettings.OperationMode {
	case "instant_scan":
		// Perform full scan of targets and quit.
		logger.Info().Msg("starting file scan")
		startFileScan()
		logger.Info().Msg("starting process scan")
		startProcessScan()
	case "daemon_mode":
		// Perform full scan of specified targets.
		logger.Info().Msg("starting file scan")
		startFileScan()
		logger.Info().Msg("starting process scan")
		startProcessScan()

		// Start all daemons together and wait for signal to stop.
		startDaemonMode()
	}
}
