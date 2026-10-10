// internal/db/queries/processtree.go
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

type ProcessTreeQueries struct {
	db shareddb.DBConn
}

func NewProcessTreeQueries(d shareddb.DBConn) *ProcessTreeQueries {
	return &ProcessTreeQueries{db: d}
}

func (q *ProcessTreeQueries) Insert(ctx context.Context, e *models.ProcessTreeEntry, now int64) error {
	sqlStr, args, err := sq.
		Insert("process_tree").
		Columns(
			"machine_id", "pid", "ppid", "comm",
			"exe_path", "cmdline", "event_time", "created_at",
		).
		Values(
			e.MachineID, e.PID, e.PPID, e.Comm,
			e.ExePath, e.CmdLine, e.EventTime, now,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("processtree.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

// GetByPID returns the most recent process_tree entry for a given PID.
// Needed by analyzers that walk the ancestry chain.
func (q *ProcessTreeQueries) GetByPID(ctx context.Context, pid uint32) (*models.ProcessTreeEntry, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "pid", "ppid", "comm",
			"exe_path", "cmdline", "event_time", "created_at",
		).
		From("process_tree").
		Where(sq.Eq{"pid": pid}).
		OrderBy("event_time DESC").
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("processtree.GetByPID: build: %w", err)
	}
	row := q.db.QueryRowContext(ctx, sqlStr, args...)
	var e models.ProcessTreeEntry
	if err := row.Scan(
		&e.ID, &e.MachineID, &e.PID, &e.PPID, &e.Comm,
		&e.ExePath, &e.CmdLine, &e.EventTime, &e.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("processtree.GetByPID: scan: %w", err)
	}
	return &e, nil
}

func (q *ProcessTreeQueries) ListByPPID(ctx context.Context, ppid uint32, limit uint64) ([]models.ProcessTreeEntry, error) {
	builder := sq.
		Select(
			"id", "machine_id", "pid", "ppid", "comm",
			"exe_path", "cmdline", "event_time", "created_at",
		).
		From("process_tree").
		Where(sq.Eq{"ppid": ppid}).
		OrderBy("event_time DESC")
	if limit > 0 {
		builder = builder.Limit(limit)
	}
	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("processtree.ListByPPID: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *ProcessTreeQueries) ListByTimeRange(ctx context.Context, start, end int64) ([]models.ProcessTreeEntry, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "pid", "ppid", "comm",
			"exe_path", "cmdline", "event_time", "created_at",
		).
		From("process_tree").
		Where(sq.And{
			sq.GtOrEq{"event_time": start},
			sq.LtOrEq{"event_time": end},
		}).
		OrderBy("event_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("processtree.ListByTimeRange: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *ProcessTreeQueries) scanRows(ctx context.Context, sqlStr string, args ...interface{}) ([]models.ProcessTreeEntry, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.ProcessTreeEntry
	for rows.Next() {
		var e models.ProcessTreeEntry
		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.PID, &e.PPID, &e.Comm,
			&e.ExePath, &e.CmdLine, &e.EventTime, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("processtree.scanRows: scan: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
