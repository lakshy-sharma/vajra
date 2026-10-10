// internal/db/queries/detections.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
	"vajra/shared/models"
)

type DetectionQueries struct {
	db *shareddb.DB
}

func NewDetectionQueries(d *shareddb.DB) *DetectionQueries {
	return &DetectionQueries{db: d}
}

// Insert writes a detection record and populates d.ID via LastInsertId.
func (q *DetectionQueries) Insert(d *models.Detection) error {
	sqlStr, args, err := sq.
		Insert("detections").
		Columns(
			"machine_id", "detection_time", "source", "severity", "status",
			"pid", "ppid", "uid", "gid", "euid", "egid",
			"process_name", "exe_path", "cmdline", "cwd",
			"target_path", "rule_id", "mitre_technique",
			"notes", "dedup_count",
		).
		Values(
			d.MachineID, d.DetectionTime, d.Source, string(d.Severity), string(d.Status),
			d.PID, d.PPID, d.UID, d.GID, d.EUID, d.EGID,
			d.ProcessName, d.ExePath, d.CmdLine, d.CWD,
			d.TargetPath, d.RuleID, d.MITRETechnique,
			d.Notes, d.DedupCount,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("detections.Insert: build: %w", err)
	}

	res, err := q.db.SQL().Exec(sqlStr, args...)
	if err != nil {
		return fmt.Errorf("detections.Insert: exec: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("detections.Insert: last id: %w", err)
	}
	d.ID = id
	return nil
}

// IncrementDedupCount bumps the dedup counter on an existing detection.
func (q *DetectionQueries) IncrementDedupCount(id int64) error {
	sqlStr, args, err := sq.
		Update("detections").
		Set("dedup_count", sq.Expr("dedup_count + 1")).
		Set("updated_at", time.Now().UTC()).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("detections.IncrementDedupCount: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// UpdateStatus sets status and notes on an existing detection.
func (q *DetectionQueries) UpdateStatus(id int64, status models.EventStatus, notes string) error {
	sqlStr, args, err := sq.
		Update("detections").
		Set("status", string(status)).
		Set("notes", notes).
		Set("updated_at", time.Now().UTC()).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("detections.UpdateStatus: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// ListBySeverity returns detections filtered by one or more severities.
func (q *DetectionQueries) ListBySeverity(limit uint64, severities ...models.EventSeverity) ([]models.Detection, error) {
	vals := make([]interface{}, len(severities))
	for i, s := range severities {
		vals[i] = string(s)
	}
	builder := sq.
		Select(
			"id", "machine_id", "detection_time", "source", "severity", "status",
			"pid", "ppid", "uid", "gid", "euid", "egid",
			"process_name", "exe_path", "cmdline", "cwd",
			"target_path", "rule_id", "mitre_technique",
			"notes", "dedup_count", "created_at", "updated_at",
		).
		From("detections").
		Where(sq.Eq{"severity": vals}).
		OrderBy("detection_time DESC")
	if limit > 0 {
		builder = builder.Limit(limit)
	}
	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("detections.ListBySeverity: build: %w", err)
	}
	return q.scanRows(sqlStr, args...)
}

// DeleteResolvedBefore removes resolved detections older than cutoff.
func (q *DetectionQueries) DeleteResolvedBefore(cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("detections").
		Where(sq.And{
			sq.Lt{"detection_time": cutoff},
			sq.Eq{"status": string(models.StatusResolved)},
		}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("detections.DeleteResolvedBefore: build: %w", err)
	}
	res, err := q.db.SQL().Exec(sqlStr, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q *DetectionQueries) scanRows(sqlStr string, args ...interface{}) ([]models.Detection, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Detection
	for rows.Next() {
		var d models.Detection
		var createdAt, updatedAt string
		if err := rows.Scan(
			&d.ID, &d.MachineID, &d.DetectionTime, &d.Source, &d.Severity, &d.Status,
			&d.PID, &d.PPID, &d.UID, &d.GID, &d.EUID, &d.EGID,
			&d.ProcessName, &d.ExePath, &d.CmdLine, &d.CWD,
			&d.TargetPath, &d.RuleID, &d.MITRETechnique,
			&d.Notes, &d.DedupCount, &createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("detections.scanRows: scan: %w", err)
		}
		results = append(results, d)
	}
	return results, rows.Err()
}
