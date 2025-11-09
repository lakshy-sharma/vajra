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
package utilities

import (
	"io"
	"os"
	"path"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Generates a rolling file lumberjack object for our logger.
func newRollingFile(config Config) io.Writer {
	if err := os.MkdirAll(config.Logging.Directory, 0744); err != nil {
		log.Error().Err(err).Str("path", config.Logging.Directory).Msg("can't create log directory")
		return nil
	}

	return &lumberjack.Logger{
		Filename:   path.Join(config.Logging.Directory, config.Logging.Filename),
		MaxBackups: config.Logging.MaxBackups,
		MaxSize:    config.Logging.MaxSizeMB,
		MaxAge:     config.Logging.MaxAgeDays,
	}
}

// Create a logger.
func GetLogger(config Config) *zerolog.Logger {
	var writers []io.Writer

	if config.Logging.EnableConsole {
		writers = append(writers, zerolog.ConsoleWriter{Out: os.Stderr})
	}
	if config.Logging.EnableFileLogging {
		writers = append(writers, newRollingFile(config))
	}
	mw := io.MultiWriter(writers...)

	// Set logging levels
	if config.Logging.LogLevel != "" {
		level, err := zerolog.ParseLevel(config.Logging.LogLevel)
		if err == nil {
			zerolog.SetGlobalLevel(level)
		} else {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			log.Error().Err(err).Str("log_level", config.Logging.LogLevel).Msg("Invalid log level specified, defaulting to INFO")
		}
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Set time format
	if config.Logging.TimeFormat != "" {
		zerolog.TimeFieldFormat = config.Logging.TimeFormat
	} else {
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	}

	logger := zerolog.New(mw).With().Timestamp().Caller().Stack().Logger()
	logger.Info().
		Bool("file_logging", config.Logging.EnableFileLogging).
		Bool("json_output", config.Logging.UseJSON).
		Str("log_directory", config.Logging.Directory).
		Str("filename", config.Logging.Filename).
		Int("max_size_mb", config.Logging.MaxSizeMB).
		Int("max_backups", config.Logging.MaxBackups).
		Int("max_age_days", config.Logging.MaxAgeDays).
		Msg("logging configured")

	return &logger
}
