// internal/utilities/logging.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"io"
	"os"
	"path"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
	sharedconfig "vajra/shared/config"
)

// newRollingFile generates a rolling file lumberjack writer.
func newRollingFile(config *sharedconfig.Config) io.Writer {
	if err := os.MkdirAll(config.Logging.Directory, 0o744); err != nil {
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

// GetLogger returns a zerolog Logger configured from cfg.
func GetLogger(config *sharedconfig.Config) *zerolog.Logger {
	var writers []io.Writer

	if config.Logging.EnableConsole {
		writers = append(writers, zerolog.ConsoleWriter{Out: os.Stderr})
	}
	if config.Logging.EnableFileLogging {
		writers = append(writers, newRollingFile(config))
	}
	mw := io.MultiWriter(writers...)

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
