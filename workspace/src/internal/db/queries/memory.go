// internal/db/queries/memory.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"vajra/internal/db"
	"vajra/shared/models"
)

type MemoryQueries struct {
	db *db.DB
}

func NewMemoryQueries(d *db.DB) *MemoryQueries {
	return &MemoryQueries{db: d}
}

func (q *MemoryQueries) Insert(e *models.MemoryEvent) error {
	sqlStr, args, err := sq.
		Insert("memory_events").
		Columns(
			"machine_id", "event_time", "event_type", "pid", "uid", "process_name",
			"address", "length", "protection", "flags", "file_path",
			"severity", "status", "notes",
		).
		Values(
			e.MachineID, e.EventTime, e.EventType, e.PID, e.UID, e.ProcessName,
			e.Address, e.Length, e.Protection, e.Flags, e.FilePath,
			string(e.Severity), string(e.Status), e.Notes,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("memory.Insert: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *MemoryQueries) ListByPID(pid uint32, limit uint64) ([]models.MemoryEvent, error) {
	builder := sq.
		Select(
			"id", "machine_id", "event_time", "event_type", "pid", "uid", "process_name",
			"address", "length", "protection", "flags", "file_path",
			"severity", "status", "notes", "created_at",
		).
		From("memory_events").
		Where(sq.Eq{"pid": pid}).
		OrderBy("event_time DESC")

	if limit > 0 {
		builder = builder.Limit(limit)
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("memory.ListByPID: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *MemoryQueries) DeleteBefore(cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("memory_events").
		Where(sq.Lt{"event_time": cutoff}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("memory.DeleteBefore: build query: %w", err)
	}

	res, err := q.db.SQL().Exec(sqlStr, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q *MemoryQueries) scanRows(sqlStr string, args ...interface{}) ([]models.MemoryEvent, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.MemoryEvent
	for rows.Next() {
		var e models.MemoryEvent
		var createdAt string

		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.EventTime, &e.EventType, &e.PID, &e.UID, &e.ProcessName,
			&e.Address, &e.Length, &e.Protection, &e.Flags, &e.FilePath,
			&e.Severity, &e.Status, &e.Notes, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("memory.scanRows: scan: %w", err)
		}

		events = append(events, e)
	}

	return events, rows.Err()
}
