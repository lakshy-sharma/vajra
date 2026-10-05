// internal/db/queries/processtree.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"vajra/internal/db"
	"vajra/shared/models"
)

type ProcessTreeQueries struct {
	db *db.DB
}

func NewProcessTreeQueries(d *db.DB) *ProcessTreeQueries {
	return &ProcessTreeQueries{db: d}
}

// Insert writes one execve event into the process tree adjacency list.
// Called on every execve regardless of dedup or scan result — tree
// completeness is required for server-side recursive CTE traversal.
func (q *ProcessTreeQueries) Insert(e *models.ProcessTreeEntry) error {
	sqlStr, args, err := sq.
		Insert("process_tree").
		Columns("machine_id", "pid", "ppid", "comm", "exe_path", "cmdline", "event_time").
		Values(e.MachineID, e.PID, e.PPID, e.Comm, e.ExePath, e.CmdLine, e.EventTime).
		ToSql()
	if err != nil {
		return fmt.Errorf("processtree.Insert: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// GetByPID returns the most recent process_tree entry for a given PID.
// Used by LOLBin analyzer for shallow parent context lookup — not full
// tree traversal, which belongs server-side.
func (q *ProcessTreeQueries) GetByPID(pid uint32) (*models.ProcessTreeEntry, error) {
	sqlStr, args, err := sq.
		Select("id", "machine_id", "pid", "ppid", "comm", "exe_path", "cmdline", "event_time").
		From("process_tree").
		Where(sq.Eq{"pid": pid}).
		OrderBy("event_time DESC").
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("processtree.GetByPID: build query: %w", err)
	}

	row := q.db.SQL().QueryRow(sqlStr, args...)
	var e models.ProcessTreeEntry
	if err := row.Scan(
		&e.ID, &e.MachineID, &e.PID, &e.PPID,
		&e.Comm, &e.ExePath, &e.CmdLine, &e.EventTime,
	); err != nil {
		return nil, fmt.Errorf("processtree.GetByPID: scan: %w", err)
	}

	return &e, nil
}
