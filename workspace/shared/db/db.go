// shared/db/db.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

// Package db provides the database handle and the DBConn interface used by all
// query layers. No caller outside this package receives a *sql.DB directly —
// that would expose the full database/sql surface (Prepare, raw Exec strings,
// etc.) to every subsystem. DBConn is the minimal contract callers need.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	_ "github.com/mattn/go-sqlite3" // driver registration side effect
)

// ── DBConn interface ──────────────────────────────────────────────────────────

// DBConn is the only interface query packages and tests use. It is satisfied by
// *sql.DB, *sql.Tx, and the test-double types in testutil — which means every
// query function accepts either a live connection or a transaction transparently.
//
// Do not extend this interface. If a query method needs Prepare, it should
// accept *sql.DB directly and be documented as a migration-level function.
type DBConn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// ── DB wrapper ────────────────────────────────────────────────────────────────

// DB wraps *sql.DB. It implements DBConn and adds Open/Close lifecycle. The
// underlying *sql.DB is intentionally unexported — callers use DBConn.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path with WAL mode and the
// pragmas required for a write-capable connection.
//
// DSN considerations:
//   - The path is URL-encoded so that unusual characters in directory names
//     (spaces, brackets, etc.) do not corrupt the DSN.
//   - busy_timeout prevents "database is locked" errors under concurrent access.
//   - WAL mode allows one writer and many readers to proceed concurrently.
//   - foreign_keys is enabled at the application layer rather than relying on
//     a schema-level PRAGMA so it is always active regardless of SQLite version.
func Open(path string) (*DB, error) {
	dsn := buildDSN(path, false)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open %s: %w", path, err)
	}

	// Single writer: more than one idle write connection causes "database is
	// locked" errors with WAL unless a shared cache is used. Keeping one
	// connection eliminates contention without shared cache complexity.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := ping(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: ping %s: %w", path, err)
	}
	return &DB{db: db}, nil
}

// OpenReadOnly opens an existing database for read-only queries. It applies
// the same consistency pragmas as Open but does not set WAL mode (a read-only
// connection cannot change the journal mode).
func OpenReadOnly(path string) (*DB, error) {
	dsn := buildDSN(path, true)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open readonly %s: %w", path, err)
	}

	// Read-only connections can scale; allow up to 8 concurrent readers.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)

	if err := ping(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: ping (readonly) %s: %w", path, err)
	}
	return &DB{db: db}, nil
}

// Close releases the database connection pool.
func (d *DB) Close() error {
	return d.db.Close()
}

// ── DBConn delegation ─────────────────────────────────────────────────────────

func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.db.ExecContext(ctx, query, args...)
}

func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.db.QueryContext(ctx, query, args...)
}

func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.db.QueryRowContext(ctx, query, args...)
}

func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return d.db.BeginTx(ctx, opts)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// buildDSN assembles a go-sqlite3 DSN with all required pragmas embedded as
// query parameters. The path is percent-encoded to handle arbitrary characters
// in directory names. The _busy_timeout parameter serialises concurrent writers
// for up to 5 seconds before returning SQLITE_BUSY, which is far preferable to
// an immediate failure.
func buildDSN(path string, readOnly bool) string {
	q := url.Values{}
	q.Set("_journal_mode", "WAL")
	q.Set("_foreign_keys", "on")
	q.Set("_busy_timeout", "5000")  // milliseconds
	q.Set("_synchronous", "NORMAL") // safe with WAL; FULL would be redundant
	q.Set("_cache_size", "-32000")  // 32 MiB page cache (negative = KiB)

	if readOnly {
		q.Set("mode", "ro")
		// Immutable signals to SQLite that the file will not change while the
		// connection is open. Only safe for snapshot reads; do not use for a
		// long-lived read connection on a live database.
		// q.Set("immutable", "1")  ← intentionally left commented out
	}

	// url.PathEscape handles spaces and special characters in the path.
	// The sqlite3 driver interprets the DSN as a file: URI when it starts
	// with "file:".
	return "file:" + url.PathEscape(path) + "?" + q.Encode()
}

// ping runs a no-op query to verify the connection and that pragmas took effect.
func ping(db *sql.DB) error {
	if err := db.Ping(); err != nil {
		return err
	}
	// Verify WAL journal mode was applied. This catches read-only file systems
	// or pre-existing databases with a conflicting journal mode.
	var mode string
	row := db.QueryRow("PRAGMA journal_mode")
	if err := row.Scan(&mode); err != nil {
		return fmt.Errorf("journal_mode check: %w", err)
	}
	if mode != "wal" {
		return fmt.Errorf("expected journal_mode=wal, got %q — database may be on a network or read-only filesystem", mode)
	}
	return nil
}
