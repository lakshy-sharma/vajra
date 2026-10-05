// internal/db/db.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
)

type DB struct {
	sql    *sql.DB
	logger *zerolog.Logger
}

func (d *DB) SQL() *sql.DB { return d.sql }

func Open(path string, logger *zerolog.Logger) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("db: create directory: %w", err)
	}

	sqlDB, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	sqlDB.SetMaxOpenConns(1)

	d := &DB{sql: sqlDB, logger: logger}

	if err := d.applyPragmas(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	logger.Info().Str("path", path).Msg("database ready")
	return d, nil
}

func OpenReadOnly(path string, logger *zerolog.Logger) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_journal_mode=WAL", path)
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open read-only: %w", err)
	}
	return &DB{sql: sqlDB, logger: logger}, nil
}

func (d *DB) Close() error {
	if d.sql != nil {
		return d.sql.Close()
	}
	return nil
}

func (d *DB) Ping() error {
	return d.sql.Ping()
}

func (d *DB) applyPragmas() error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=10000",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := d.sql.Exec(p); err != nil {
			return fmt.Errorf("db: pragma %q: %w", p, err)
		}
	}
	return nil
}

func (d *DB) migrate() error {
	stmts := []string{
		// ── file_scan_results ─────────────────────────────────
		`CREATE TABLE IF NOT EXISTS file_scan_results (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT     NOT NULL DEFAULT '',
			scan_time    INTEGER  NOT NULL,
			file_path    TEXT     NOT NULL,
			file_size    INTEGER,
			file_hash    TEXT,
			yara_matches TEXT,
			severity     TEXT     NOT NULL DEFAULT 'LOW',
			status       TEXT     NOT NULL DEFAULT 'NEW',
			event_type   INTEGER,
			trigger_pid  INTEGER,
			trigger_uid  INTEGER,
			trigger_comm TEXT,
			dedup_count  INTEGER  NOT NULL DEFAULT 0,
			notes        TEXT,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fsr_machine_id ON file_scan_results(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_fsr_scan_time  ON file_scan_results(scan_time)`,
		`CREATE INDEX IF NOT EXISTS idx_fsr_file_path  ON file_scan_results(file_path)`,
		`CREATE INDEX IF NOT EXISTS idx_fsr_file_hash  ON file_scan_results(file_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_fsr_severity   ON file_scan_results(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_fsr_status     ON file_scan_results(status)`,
		`CREATE INDEX IF NOT EXISTS idx_fsr_event_type ON file_scan_results(event_type)`,

		// ── process_scan_results ──────────────────────────────
		`CREATE TABLE IF NOT EXISTS process_scan_results (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT     NOT NULL DEFAULT '',
			scan_time    INTEGER  NOT NULL,
			pid          INTEGER  NOT NULL,
			ppid         INTEGER,
			uid          INTEGER  NOT NULL,
			gid          INTEGER,
			euid         INTEGER,
			egid         INTEGER,
			process_name TEXT     NOT NULL,
			exe_path     TEXT,
			cmdline      TEXT,
			cwd          TEXT,
			file_hash    TEXT,
			yara_matches TEXT,
			severity     TEXT     NOT NULL DEFAULT 'LOW',
			status       TEXT     NOT NULL DEFAULT 'NEW',
			event_type   INTEGER,
			dedup_count  INTEGER  NOT NULL DEFAULT 0,
			notes        TEXT,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_psr_machine_id ON process_scan_results(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_psr_scan_time  ON process_scan_results(scan_time)`,
		`CREATE INDEX IF NOT EXISTS idx_psr_pid        ON process_scan_results(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_psr_severity   ON process_scan_results(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_psr_status     ON process_scan_results(status)`,
		`CREATE INDEX IF NOT EXISTS idx_psr_name       ON process_scan_results(process_name)`,
		`CREATE INDEX IF NOT EXISTS idx_psr_file_hash  ON process_scan_results(file_hash)`,

		// ── network_events ────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS network_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT     NOT NULL DEFAULT '',
			event_time   INTEGER  NOT NULL,
			event_type   INTEGER  NOT NULL,
			pid          INTEGER  NOT NULL,
			uid          INTEGER  NOT NULL,
			process_name TEXT     NOT NULL,
			src_addr     TEXT,
			dst_addr     TEXT,
			src_port     INTEGER,
			dst_port     INTEGER,
			protocol     TEXT,
			severity     TEXT     NOT NULL DEFAULT 'LOW',
			status       TEXT     NOT NULL DEFAULT 'NEW',
			notes        TEXT,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_machine_id ON network_events(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_event_time ON network_events(event_time)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_pid        ON network_events(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_dst_port   ON network_events(dst_port)`,
		`CREATE INDEX IF NOT EXISTS idx_ne_severity   ON network_events(severity)`,

		// ── security_events ───────────────────────────────────
		`CREATE TABLE IF NOT EXISTS security_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT     NOT NULL DEFAULT '',
			event_time   INTEGER  NOT NULL,
			event_type   INTEGER  NOT NULL,
			event_name   TEXT     NOT NULL,
			pid          INTEGER  NOT NULL,
			uid          INTEGER  NOT NULL,
			process_name TEXT     NOT NULL,
			target_pid   INTEGER,
			target_path  TEXT,
			details      TEXT,
			severity     TEXT     NOT NULL DEFAULT 'MEDIUM',
			status       TEXT     NOT NULL DEFAULT 'NEW',
			yara_matches TEXT,
			action_taken TEXT,
			notes        TEXT,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_se_machine_id ON security_events(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_se_event_time ON security_events(event_time)`,
		`CREATE INDEX IF NOT EXISTS idx_se_event_type ON security_events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_se_pid        ON security_events(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_se_severity   ON security_events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_se_status     ON security_events(status)`,

		// ── memory_events ─────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS memory_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id   TEXT     NOT NULL DEFAULT '',
			event_time   INTEGER  NOT NULL,
			event_type   INTEGER  NOT NULL,
			pid          INTEGER  NOT NULL,
			uid          INTEGER  NOT NULL,
			process_name TEXT     NOT NULL,
			address      INTEGER,
			length       INTEGER,
			protection   INTEGER,
			flags        INTEGER,
			file_path    TEXT,
			severity     TEXT     NOT NULL DEFAULT 'MEDIUM',
			status       TEXT     NOT NULL DEFAULT 'NEW',
			notes        TEXT,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_me_machine_id ON memory_events(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_me_event_time ON memory_events(event_time)`,
		`CREATE INDEX IF NOT EXISTS idx_me_pid        ON memory_events(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_me_severity   ON memory_events(severity)`,

		// ── autoruns ──────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS autoruns (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			category     TEXT     NOT NULL,
			location     TEXT     NOT NULL,
			image_path   TEXT,
			image_name   TEXT,
			arguments    TEXT,
			md5          TEXT,
			sha1         TEXT,
			sha256       TEXT,
			is_active    BOOLEAN  NOT NULL DEFAULT 1,
			first_seen   INTEGER  NOT NULL,
			last_seen    INTEGER  NOT NULL,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_category   ON autoruns(category)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_location   ON autoruns(location)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_image_path ON autoruns(image_path)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_sha256     ON autoruns(sha256)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_is_active  ON autoruns(is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_first_seen ON autoruns(first_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_ar_last_seen  ON autoruns(last_seen)`,

		// ── quarantined_files ─────────────────────────────────
		`CREATE TABLE IF NOT EXISTS quarantined_files (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			original_path   TEXT     NOT NULL,
			quarantine_path TEXT     NOT NULL,
			file_hash       TEXT     NOT NULL,
			file_size       INTEGER,
			quarantine_time INTEGER  NOT NULL,
			related_scan_id INTEGER,
			severity        TEXT     NOT NULL,
			reason          TEXT     NOT NULL,
			restored        BOOLEAN  NOT NULL DEFAULT 0,
			restored_time   INTEGER,
			notes           TEXT,
			created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_qf_quarantine_time ON quarantined_files(quarantine_time)`,
		`CREATE INDEX IF NOT EXISTS idx_qf_file_hash       ON quarantined_files(file_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_qf_severity        ON quarantined_files(severity)`,

		// ── event_statistics ──────────────────────────────────
		`CREATE TABLE IF NOT EXISTS event_statistics (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			date            TEXT    NOT NULL,
			event_type      INTEGER NOT NULL,
			event_name      TEXT    NOT NULL,
			total_count     INTEGER NOT NULL DEFAULT 0,
			malicious_count INTEGER NOT NULL DEFAULT 0,
			clean_count     INTEGER NOT NULL DEFAULT 0,
			UNIQUE(date, event_type)
		)`,

		// ── sync_state ────────────────────────────────────────
		// Watermark table for remote sync. One row per event table.
		// last_synced_id tracks the highest ID shipped to the server.
		// Purge job deletes rows with id <= last_synced_id older than retention.
		`CREATE TABLE IF NOT EXISTS sync_state (
			table_name     TEXT    PRIMARY KEY,
			last_synced_id INTEGER NOT NULL DEFAULT 0,
			last_synced_at INTEGER NOT NULL DEFAULT 0,
			synced_rows    INTEGER NOT NULL DEFAULT 0
		)`,
		// ── process_tree ──────────────────────────────────────
		// Adjacency list of every execve event. Written on every
		// process execution regardless of scan result or dedup.
		// The server reconstructs full execution forests via recursive
		// CTE on (machine_id, ppid, pid). Never pruned by retention
		// cleanup — tree completeness matters more than disk space.
		`CREATE TABLE IF NOT EXISTS process_tree (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			machine_id TEXT    NOT NULL DEFAULT '',
			pid        INTEGER NOT NULL,
			ppid       INTEGER NOT NULL,
			comm       TEXT    NOT NULL DEFAULT '',
			exe_path   TEXT    NOT NULL DEFAULT '',
			cmdline    TEXT    NOT NULL DEFAULT '',
			event_time INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_machine_id ON process_tree(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_pid        ON process_tree(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_ppid       ON process_tree(ppid)`,
		`CREATE INDEX IF NOT EXISTS idx_pt_event_time ON process_tree(event_time)`,
		// Composite index for the recursive CTE query pattern.
		`CREATE INDEX IF NOT EXISTS idx_pt_machine_ppid_pid ON process_tree(machine_id, ppid, pid)`,
	}

	for _, stmt := range stmts {
		if _, err := d.sql.Exec(stmt); err != nil {
			return fmt.Errorf("db: migrate: %w\nstatement: %.120s", err, stmt)
		}
	}

	d.logger.Info().Msg("database migration complete")
	return nil
}
