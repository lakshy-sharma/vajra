// internal/db/queries/security.go
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

type SecurityQueries struct {
	db shareddb.DBConn
}

func NewSecurityQueries(d shareddb.DBConn) *SecurityQueries {
	return &SecurityQueries{db: d}
}

func (q *SecurityQueries) Insert(ctx context.Context, e *models.SecurityEvent, now int64) error {
	sqlStr, args, err := sq.
		Insert("security_events").
		Columns(
			"machine_id", "event_time", "event_type", "event_name",
			"pid", "uid", "process_name",
			"target_pid", "target_path", "details",
			"severity", "status", "action_taken", "notes",
			"created_at", "updated_at",
		).
		Values(
			e.MachineID, e.EventTime, e.EventType, e.EventName,
			e.PID, e.UID, e.ProcessName,
			e.TargetPID, e.TargetPath, e.Details,
			string(e.Severity), string(e.Status), e.ActionTaken, e.Notes,
			now, now,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("security.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *SecurityQueries) ListByTimeRange(ctx context.Context, start, end int64) ([]models.SecurityEvent, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "event_time", "event_type", "event_name",
			"pid", "uid", "process_name",
			"target_pid", "target_path", "details",
			"severity", "status", "action_taken", "notes",
			"created_at", "updated_at",
		).
		From("security_events").
		Where(sq.And{
			sq.GtOrEq{"event_time": start},
			sq.LtOrEq{"event_time": end},
		}).
		OrderBy("event_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("security.ListByTimeRange: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *SecurityQueries) ListByPID(ctx context.Context, pid uint32, limit uint64) ([]models.SecurityEvent, error) {
	builder := sq.
		Select(
			"id", "machine_id", "event_time", "event_type", "event_name",
			"pid", "uid", "process_name",
			"target_pid", "target_path", "details",
			"severity", "status", "action_taken", "notes",
			"created_at", "updated_at",
		).
		From("security_events").
		Where(sq.Eq{"pid": pid}).
		OrderBy("event_time DESC")
	if limit > 0 {
		builder = builder.Limit(limit)
	}
	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("security.ListByPID: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *SecurityQueries) DeleteLowSeverityBefore(ctx context.Context, cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("security_events").
		Where(sq.And{
			sq.Lt{"event_time": cutoff},
			sq.Eq{"severity": string(models.SeverityLow)},
		}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("security.DeleteLowSeverityBefore: build: %w", err)
	}
	res, err := q.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q *SecurityQueries) scanRows(ctx context.Context, sqlStr string, args ...interface{}) ([]models.SecurityEvent, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.EventTime, &e.EventType, &e.EventName,
			&e.PID, &e.UID, &e.ProcessName,
			&e.TargetPID, &e.TargetPath, &e.Details,
			&e.Severity, &e.Status, &e.ActionTaken, &e.Notes,
			&e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("security.scanRows: scan: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
