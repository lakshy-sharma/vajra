// internal/db/queries/autoruns.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
	"vajra/shared/models"
)

type AutorunQueries struct {
	db *shareddb.DB
}

func NewAutorunQueries(d *shareddb.DB) *AutorunQueries {
	return &AutorunQueries{db: d}
}

// Insert adds a new autorun entry.
func (q *AutorunQueries) Insert(e *models.AutorunEntry) error {
	sqlStr, args, err := sq.
		Insert("autoruns").
		Columns(
			"category", "location", "image_path", "image_name", "arguments",
			"md5", "sha1", "sha256", "is_active", "first_seen", "last_seen",
		).
		Values(
			string(e.Category), e.Location, e.ImagePath, e.ImageName, e.Arguments,
			e.MD5, e.SHA1, e.SHA256, e.IsActive, e.FirstSeen, e.LastSeen,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("autoruns.Insert: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// MarkInactive sets is_active=0 and updates last_seen for a
// specific entry identified by its unique key fields.
func (q *AutorunQueries) MarkInactive(e *models.AutorunEntry, timestamp int64) error {
	builder := sq.
		Update("autoruns").
		Set("is_active", 0).
		Set("last_seen", timestamp).
		Set("updated_at", time.Now().UTC())

	// Match by SHA256 when available; fall back to composite key.
	if e.SHA256 != "" {
		builder = builder.Where(sq.Eq{"sha256": e.SHA256})
	} else {
		builder = builder.Where(sq.And{
			sq.Eq{"category": string(e.Category)},
			sq.Eq{"location": e.Location},
			sq.Eq{"image_path": e.ImagePath},
		})
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return fmt.Errorf("autoruns.MarkInactive: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// UpdateLastSeen bumps the last_seen timestamp for an entry
// that was observed again on the current scan cycle.
func (q *AutorunQueries) UpdateLastSeen(e *models.AutorunEntry, timestamp int64) error {
	builder := sq.
		Update("autoruns").
		Set("last_seen", timestamp).
		Set("updated_at", time.Now().UTC())

	if e.SHA256 != "" {
		builder = builder.Where(sq.Eq{"sha256": e.SHA256})
	} else {
		builder = builder.Where(sq.And{
			sq.Eq{"category": string(e.Category)},
			sq.Eq{"location": e.Location},
			sq.Eq{"image_path": e.ImagePath},
		})
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return fmt.Errorf("autoruns.UpdateLastSeen: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// LoadActive returns all currently active autorun entries.
// Used to seed the in-memory state on startup.
func (q *AutorunQueries) LoadActive() ([]models.AutorunEntry, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "category", "location", "image_path", "image_name", "arguments",
			"md5", "sha1", "sha256", "is_active", "first_seen", "last_seen",
			"created_at", "updated_at",
		).
		From("autoruns").
		Where(sq.Eq{"is_active": 1}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("autoruns.LoadActive: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

// ListByCategory returns all entries (active or not) for a
// given persistence category.
func (q *AutorunQueries) ListByCategory(cat models.AutorunCategory) ([]models.AutorunEntry, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "category", "location", "image_path", "image_name", "arguments",
			"md5", "sha1", "sha256", "is_active", "first_seen", "last_seen",
			"created_at", "updated_at",
		).
		From("autoruns").
		Where(sq.Eq{"category": string(cat)}).
		OrderBy("first_seen DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("autoruns.ListByCategory: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *AutorunQueries) scanRows(sqlStr string, args ...interface{}) ([]models.AutorunEntry, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.AutorunEntry
	for rows.Next() {
		var e models.AutorunEntry
		var createdAt, updatedAt string

		if err := rows.Scan(
			&e.ID, &e.Category, &e.Location, &e.ImagePath, &e.ImageName, &e.Arguments,
			&e.MD5, &e.SHA1, &e.SHA256, &e.IsActive, &e.FirstSeen, &e.LastSeen,
			&createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("autoruns.scanRows: scan: %w", err)
		}

		entries = append(entries, e)
	}

	return entries, rows.Err()
}
