// internal/db/queries/auditlog.go
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

type AuditLogQueries struct {
	db shareddb.DBConn
}

func NewAuditLogQueries(d shareddb.DBConn) *AuditLogQueries {
	return &AuditLogQueries{db: d}
}

// Insert appends one audit event. Audit log is append-only by design.
func (q *AuditLogQueries) Insert(ctx context.Context, e *models.AuditLog) error {
	sqlStr, args, err := sq.
		Insert("audit_log").
		Columns(
			"machine_id", "logged_at", "component", "event_type",
			"status", "details", "duration_ms", "items_processed",
		).
		Values(
			e.MachineID, e.LoggedAt, e.Component, e.EventType,
			e.Status, e.Details, e.DurationMS, e.ItemsProcessed,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("auditlog.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *AuditLogQueries) ListByComponent(ctx context.Context, component string, limit uint64) ([]models.AuditLog, error) {
	builder := sq.
		Select(
			"id", "machine_id", "logged_at", "component", "event_type",
			"status", "details", "duration_ms", "items_processed",
		).
		From("audit_log").
		Where(sq.Eq{"component": component}).
		OrderBy("logged_at DESC")
	if limit > 0 {
		builder = builder.Limit(limit)
	}
	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("auditlog.ListByComponent: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *AuditLogQueries) scanRows(ctx context.Context, sqlStr string, args ...interface{}) ([]models.AuditLog, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.AuditLog
	for rows.Next() {
		var e models.AuditLog
		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.LoggedAt, &e.Component, &e.EventType,
			&e.Status, &e.Details, &e.DurationMS, &e.ItemsProcessed,
		); err != nil {
			return nil, fmt.Errorf("auditlog.scanRows: scan: %w", err)
		}
		results = append(results, e)
	}
	return results, rows.Err()
}
