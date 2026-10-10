// shared/db/db.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a SQLite connection. The logger has been intentionally removed
// from this struct — callers log the outcome of Open/OpenReadOnly at their
// own level so that shared/db carries no logging dependency.
type DB struct {
	sql *sql.DB
}

// SQL returns the underlying *sql.DB for use by query structs.
func (d *DB) SQL() *sql.DB { return d.sql }

// Close closes the underlying database connection.
func (d *DB) Close() error {
	if d.sql != nil {
		return d.sql.Close()
	}
	return nil
}

// Ping verifies the connection is still alive.
func (d *DB) Ping() error { return d.sql.Ping() }

// Open opens (or creates) a SQLite database at path with WAL mode and
// standard pragmas applied. It does NOT run schema migrations — the daemon
// calls its own Open wrapper which runs migrate() after this returns.
// The UI calls this directly since it never needs to migrate.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("db: create directory: %w", err)
	}
	sqlDB, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	// SQLite does not support concurrent writers; a single connection
	// prevents the "database is locked" error under WAL mode.
	sqlDB.SetMaxOpenConns(1)

	d := &DB{sql: sqlDB}
	if err := d.applyPragmas(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// OpenReadOnly opens an existing SQLite database in read-only mode.
// Suitable for the UI's non-config read queries where no writes are needed.
func OpenReadOnly(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_journal_mode=WAL", path)
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open read-only: %w", err)
	}
	return &DB{sql: sqlDB}, nil
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
