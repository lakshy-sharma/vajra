// internal/db/queries/memory.go
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

type MemoryQueries struct {
	db shareddb.DBConn
}

func NewMemoryQueries(d shareddb.DBConn) *MemoryQueries {
	return &MemoryQueries{db: d}
}

func (q *MemoryQueries) Insert(ctx context.Context, e *models.MemoryEvent, now int64) error {
	sqlStr, args, err := sq.
		Insert("memory_events").
		Columns(
			"machine_id", "event_time", "event_type", "pid", "uid", "process_name",
			"address", "length", "protection", "flags", "file_path",
			"severity", "status", "notes", "created_at", "updated_at",
		).
		Values(
			e.MachineID, e.EventTime, e.EventType, e.PID, e.UID, e.ProcessName,
			e.Address, e.Length, e.Protection, e.Flags, e.FilePath,
			string(e.Severity), string(e.Status), e.Notes, now, now,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("memory.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *MemoryQueries) ListByPID(ctx context.Context, pid uint32, limit uint64) ([]models.MemoryEvent, error) {
	builder := sq.
		Select(
			"id", "machine_id", "event_time", "event_type", "pid", "uid", "process_name",
			"address", "length", "protection", "flags", "file_path",
			"severity", "status", "notes", "created_at", "updated_at",
		).
		From("memory_events").
		Where(sq.Eq{"pid": pid}).
		OrderBy("event_time DESC")
	if limit > 0 {
		builder = builder.Limit(limit)
	}
	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("memory.ListByPID: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *MemoryQueries) DeleteBefore(ctx context.Context, cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("memory_events").
		Where(sq.Lt{"event_time": cutoff}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("memory.DeleteBefore: build: %w", err)
	}
	res, err := q.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q *MemoryQueries) scanRows(ctx context.Context, sqlStr string, args ...interface{}) ([]models.MemoryEvent, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.MemoryEvent
	for rows.Next() {
		var e models.MemoryEvent
		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.EventTime, &e.EventType, &e.PID, &e.UID, &e.ProcessName,
			&e.Address, &e.Length, &e.Protection, &e.Flags, &e.FilePath,
			&e.Severity, &e.Status, &e.Notes, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("memory.scanRows: scan: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
