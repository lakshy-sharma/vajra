// internal/db/queries/autoruns.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
	"vajra/shared/models"
)

type AutorunQueries struct {
	db shareddb.DBConn
}

func NewAutorunQueries(d shareddb.DBConn) *AutorunQueries {
	return &AutorunQueries{db: d}
}

func (q *AutorunQueries) Insert(ctx context.Context, e *models.AutorunEntry, now int64) error {
	sqlStr, args, err := sq.
		Insert("autoruns").
		Columns(
			"machine_id", "category", "location", "image_path", "image_name",
			"arguments", "sha256", "is_active", "first_seen", "last_seen",
			"created_at", "updated_at",
		).
		Values(
			e.MachineID, string(e.Category), e.Location, e.ImagePath, e.ImageName,
			e.Arguments, e.SHA256, e.IsActive, e.FirstSeen, e.LastSeen,
			now, now,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("autoruns.Insert: build: %w", err)
	}
	res, err := q.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return fmt.Errorf("autoruns.Insert: exec: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("autoruns.Insert: last id: %w", err)
	}
	e.ID = id
	return nil
}

// MarkInactive sets is_active=0 for an entry no longer present on the system.
// The composite key (category+location+image_path) is always used — sha256
// alone does not uniquely identify a persistence location.
func (q *AutorunQueries) MarkInactive(ctx context.Context, e *models.AutorunEntry, now int64) error {
	sqlStr, args, err := sq.
		Update("autoruns").
		Set("is_active", 0).
		Set("last_seen", now).
		Set("updated_at", now).
		Where(sq.And{
			sq.Eq{"category": string(e.Category)},
			sq.Eq{"location": e.Location},
			sq.Eq{"image_path": e.ImagePath},
		}).
		ToSql()
	if err != nil {
		return fmt.Errorf("autoruns.MarkInactive: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *AutorunQueries) UpdateLastSeen(ctx context.Context, e *models.AutorunEntry, now int64) error {
	sqlStr, args, err := sq.
		Update("autoruns").
		Set("last_seen", now).
		Set("updated_at", now).
		Where(sq.And{
			sq.Eq{"category": string(e.Category)},
			sq.Eq{"location": e.Location},
			sq.Eq{"image_path": e.ImagePath},
		}).
		ToSql()
	if err != nil {
		return fmt.Errorf("autoruns.UpdateLastSeen: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *AutorunQueries) LoadActive(ctx context.Context) ([]models.AutorunEntry, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "category", "location", "image_path", "image_name",
			"arguments", "sha256", "is_active", "first_seen", "last_seen",
			"created_at", "updated_at",
		).
		From("autoruns").
		Where(sq.Eq{"is_active": 1}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("autoruns.LoadActive: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *AutorunQueries) ListByCategory(ctx context.Context, cat models.AutorunCategory) ([]models.AutorunEntry, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "category", "location", "image_path", "image_name",
			"arguments", "sha256", "is_active", "first_seen", "last_seen",
			"created_at", "updated_at",
		).
		From("autoruns").
		Where(sq.Eq{"category": string(cat)}).
		OrderBy("first_seen DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("autoruns.ListByCategory: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *AutorunQueries) scanRows(ctx context.Context, sqlStr string, args ...interface{}) ([]models.AutorunEntry, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.AutorunEntry
	for rows.Next() {
		var e models.AutorunEntry
		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.Category, &e.Location, &e.ImagePath, &e.ImageName,
			&e.Arguments, &e.SHA256, &e.IsActive, &e.FirstSeen, &e.LastSeen,
			&e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("autoruns.scanRows: scan: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
