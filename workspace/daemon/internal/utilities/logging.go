// internal/utilities/logging.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package utilities

import (
	"fmt"
	"io"
	"os"
	"path"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
	sharedconfig "vajra/shared/config"
)

// newRollingFile creates the log directory and returns a rotating file writer.
// Returns an error rather than nil so callers cannot silently lose log output.
func newRollingFile(cfg *sharedconfig.Config) (io.Writer, error) {
	// 0o700 — log files contain detection data; no group/other read.
	if err := os.MkdirAll(cfg.LogSettings.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("logging: create log dir %s: %w", cfg.LogSettings.Directory, err)
	}
	return &lumberjack.Logger{
		Filename:   path.Join(cfg.LogSettings.Directory, cfg.LogSettings.Filename),
		MaxBackups: cfg.LogSettings.MaxBackups,
		MaxSize:    cfg.LogSettings.MaxSizeMB,
		MaxAge:     cfg.LogSettings.MaxAgeDays,
		Compress:   cfg.LogSettings.Compress,
	}, nil
}

// GetLogger returns a zerolog Logger configured from cfg.
// Returns an error so callers cannot silently proceed with no log output.
func GetLogger(cfg *sharedconfig.Config) (*zerolog.Logger, error) {
	file, err := newRollingFile(cfg)
	if err != nil {
		return nil, err
	}

	level, err := zerolog.ParseLevel(cfg.LogSettings.Level)
	if err != nil {
		// Unknown level strings fail loud — a misconfigured daemon must not
		// silently drop events by defaulting to a higher level.
		return nil, fmt.Errorf("logging: invalid level %q: %w", cfg.LogSettings.Level, err)
	}

	// zerolog.TimeFieldFormat is package-global state; set it once at startup.
	// Unix epoch seconds keep log timestamps consistent with all DB and event
	// structs in this project which also use int64 Unix epoch.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Use .Level() on the instance — zerolog.SetGlobalLevel() would silently
	// alter any other zerolog logger created in the same process.
	logger := zerolog.New(file).Level(level).With().Timestamp().Caller().Stack().Logger()
	return &logger, nil
}
