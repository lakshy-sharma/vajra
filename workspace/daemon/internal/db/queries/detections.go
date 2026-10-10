// internal/db/queries/detections.go
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

type DetectionQueries struct {
	db shareddb.DBConn
}

func NewDetectionQueries(d shareddb.DBConn) *DetectionQueries {
	return &DetectionQueries{db: d}
}

func (q *DetectionQueries) Insert(ctx context.Context, d *models.Detection, now int64) error {
	sqlStr, args, err := sq.
		Insert("detections").
		Columns(
			"machine_id", "detection_time", "source", "severity", "status",
			"pid", "ppid", "uid", "gid", "euid", "egid",
			"process_name", "exe_path", "cmd_line", "cwd",
			"target_path", "rule_id", "mitre_technique",
			"notes", "dedup_count", "created_at", "updated_at",
		).
		Values(
			d.MachineID, d.DetectionTime, d.Source, string(d.Severity), string(d.Status),
			d.PID, d.PPID, d.UID, d.GID, d.EUID, d.EGID,
			d.ProcessName, d.ExePath, d.CmdLine, d.CWD,
			d.TargetPath, d.RuleID, d.MITRETechnique,
			d.Notes, d.DedupCount, now, now,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("detections.Insert: build: %w", err)
	}
	res, err := q.db.ExecContext(ctx, sqlStr, args...)
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

func (q *DetectionQueries) IncrementDedupCount(ctx context.Context, id int64, now int64) error {
	sqlStr, args, err := sq.
		Update("detections").
		Set("dedup_count", sq.Expr("dedup_count + 1")).
		Set("updated_at", now).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("detections.IncrementDedupCount: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *DetectionQueries) UpdateStatus(ctx context.Context, id int64, status models.EventStatus, notes string, now int64) error {
	sqlStr, args, err := sq.
		Update("detections").
		Set("status", string(status)).
		Set("notes", notes).
		Set("updated_at", now).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("detections.UpdateStatus: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *DetectionQueries) ListBySeverity(ctx context.Context, limit uint64, severities ...models.EventSeverity) ([]models.Detection, error) {
	vals := make([]interface{}, len(severities))
	for i, s := range severities {
		vals[i] = string(s)
	}
	builder := sq.
		Select(
			"id", "machine_id", "detection_time", "source", "severity", "status",
			"pid", "ppid", "uid", "gid", "euid", "egid",
			"process_name", "exe_path", "cmd_line", "cwd",
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
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *DetectionQueries) DeleteResolvedBefore(ctx context.Context, cutoff int64) (int64, error) {
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
	res, err := q.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q *DetectionQueries) scanRows(ctx context.Context, sqlStr string, args ...interface{}) ([]models.Detection, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.Detection
	for rows.Next() {
		var d models.Detection
		if err := rows.Scan(
			&d.ID, &d.MachineID, &d.DetectionTime, &d.Source, &d.Severity, &d.Status,
			&d.PID, &d.PPID, &d.UID, &d.GID, &d.EUID, &d.EGID,
			&d.ProcessName, &d.ExePath, &d.CmdLine, &d.CWD,
			&d.TargetPath, &d.RuleID, &d.MITRETechnique,
			&d.Notes, &d.DedupCount, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("detections.scanRows: scan: %w", err)
		}
		results = append(results, d)
	}
	return results, rows.Err()
}
