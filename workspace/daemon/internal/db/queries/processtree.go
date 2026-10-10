// internal/db/queries/processtree.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"
	"vajra/shared/models"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
)

type ProcessTreeQueries struct {
	db *shareddb.DB
}

func NewProcessTreeQueries(d *shareddb.DB) *ProcessTreeQueries {
	return &ProcessTreeQueries{db: d}
}

func (q *ProcessTreeQueries) Insert(e *models.ProcessTreeEntry) error {
	sqlStr, args, err := sq.
		Insert("process_tree").
		Columns(
			"machine_id", "pid", "ppid", "comm",
			"exe_path", "cmdline", "event_time",
		).
		Values(
			e.MachineID, e.PID, e.PPID, e.Comm,
			e.ExePath, e.CmdLine, e.EventTime,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("processtree.Insert: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *ProcessTreeQueries) ListByPPID(ppid uint32, limit uint64) ([]models.ProcessTreeEntry, error) {
	builder := sq.
		Select(
			"id", "machine_id", "pid", "ppid", "comm",
			"exe_path", "cmdline", "event_time",
		).
		From("process_tree").
		Where(sq.Eq{"ppid": ppid}).
		OrderBy("event_time DESC")

	if limit > 0 {
		builder = builder.Limit(limit)
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("processtree.ListByPPID: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *ProcessTreeQueries) ListByTimeRange(start, end int64) ([]models.ProcessTreeEntry, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "pid", "ppid", "comm",
			"exe_path", "cmdline", "event_time",
		).
		From("process_tree").
		Where(sq.And{
			sq.GtOrEq{"event_time": start},
			sq.LtOrEq{"event_time": end},
		}).
		OrderBy("event_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("processtree.ListByTimeRange: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *ProcessTreeQueries) scanRows(sqlStr string, args ...interface{}) ([]models.ProcessTreeEntry, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.ProcessTreeEntry
	for rows.Next() {
		var e models.ProcessTreeEntry
		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.PID, &e.PPID, &e.Comm,
			&e.ExePath, &e.CmdLine, &e.EventTime,
		); err != nil {
			return nil, fmt.Errorf("processtree.scanRows: scan: %w", err)
		}
		entries = append(entries, e)
	}

	return entries, rows.Err()
}
