// internal/db/queries/processes.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"encoding/json"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"vajra/internal/db"
	"vajra/shared/models"
)

type ProcessQueries struct {
	db *db.DB
}

func NewProcessQueries(d *db.DB) *ProcessQueries {
	return &ProcessQueries{db: d}
}

func (q *ProcessQueries) Insert(r *models.ProcessScanResult) error {
	yaraJSON, err := json.Marshal(r.YaraMatches)
	if err != nil {
		return fmt.Errorf("processes.Insert: marshal yara: %w", err)
	}

	sqlStr, args, err := sq.
		Insert("process_scan_results").
		Columns(
			"scan_time", "pid", "ppid", "uid", "gid", "euid", "egid",
			"process_name", "exe_path", "cmdline", "cwd",
			"yara_matches", "severity", "status", "event_type", "notes",
		).
		Values(
			r.ScanTime, r.PID, r.PPID, r.UID, r.GID, r.EUID, r.EGID,
			r.ProcessName, r.ExePath, r.CmdLine, r.CWD,
			string(yaraJSON), string(r.Severity), string(r.Status), r.EventType, r.Notes,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("processes.Insert: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *ProcessQueries) UpdateStatus(id int64, status models.EventStatus, notes string) error {
	sqlStr, args, err := sq.
		Update("process_scan_results").
		Set("status", string(status)).
		Set("notes", notes).
		Set("updated_at", time.Now().UTC()).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("processes.UpdateStatus: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *ProcessQueries) ListByPID(pid uint32) ([]models.ProcessScanResult, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "scan_time", "pid", "ppid", "uid", "gid", "euid", "egid",
			"process_name", "exe_path", "cmdline", "cwd",
			"yara_matches", "severity", "status", "event_type", "notes",
			"created_at", "updated_at",
		).
		From("process_scan_results").
		Where(sq.Eq{"pid": pid}).
		OrderBy("scan_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("processes.ListByPID: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *ProcessQueries) ListBySeverity(limit uint64, severities ...models.EventSeverity) ([]models.ProcessScanResult, error) {
	vals := make([]interface{}, len(severities))
	for i, s := range severities {
		vals[i] = string(s)
	}

	builder := sq.
		Select(
			"id", "scan_time", "pid", "ppid", "uid", "gid", "euid", "egid",
			"process_name", "exe_path", "cmdline", "cwd",
			"yara_matches", "severity", "status", "event_type", "notes",
			"created_at", "updated_at",
		).
		From("process_scan_results").
		Where(sq.Eq{"severity": vals}).
		OrderBy("scan_time DESC")

	if limit > 0 {
		builder = builder.Limit(limit)
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("processes.ListBySeverity: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *ProcessQueries) DeleteResolvedBefore(cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("process_scan_results").
		Where(sq.And{
			sq.Lt{"scan_time": cutoff},
			sq.Eq{"status": string(models.StatusResolved)},
		}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("processes.DeleteResolvedBefore: build query: %w", err)
	}

	res, err := q.db.SQL().Exec(sqlStr, args...)
	if err != nil {
		return 0, err
	}

	return res.RowsAffected()
}

func (q *ProcessQueries) scanRows(sqlStr string, args ...interface{}) ([]models.ProcessScanResult, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.ProcessScanResult
	for rows.Next() {
		var r models.ProcessScanResult
		var yaraJSON string
		var createdAt, updatedAt string

		if err := rows.Scan(
			&r.ID, &r.ScanTime, &r.PID, &r.PPID, &r.UID, &r.GID, &r.EUID, &r.EGID,
			&r.ProcessName, &r.ExePath, &r.CmdLine, &r.CWD,
			&yaraJSON, &r.Severity, &r.Status, &r.EventType, &r.Notes,
			&createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("processes.scanRows: scan: %w", err)
		}

		if err := json.Unmarshal([]byte(yaraJSON), &r.YaraMatches); err != nil {
			r.YaraMatches = nil
		}

		results = append(results, r)
	}

	return results, rows.Err()
}
