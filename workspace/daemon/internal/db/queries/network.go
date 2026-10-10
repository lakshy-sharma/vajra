// internal/db/queries/network.go
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

type NetworkQueries struct {
	db shareddb.DBConn
}

func NewNetworkQueries(d shareddb.DBConn) *NetworkQueries {
	return &NetworkQueries{db: d}
}

func (q *NetworkQueries) Insert(ctx context.Context, e *models.NetworkEvent, now int64) error {
	sqlStr, args, err := sq.
		Insert("network_events").
		Columns(
			"machine_id", "event_time", "event_type", "pid", "uid", "process_name",
			"src_addr", "dst_addr", "src_port", "dst_port", "protocol",
			"severity", "status", "notes", "created_at", "updated_at",
		).
		Values(
			e.MachineID, e.EventTime, e.EventType, e.PID, e.UID, e.ProcessName,
			e.SrcAddr, e.DstAddr, e.SrcPort, e.DstPort, e.Protocol,
			string(e.Severity), string(e.Status), e.Notes, now, now,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("network.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *NetworkQueries) ListByDstPort(ctx context.Context, port uint16, limit uint64) ([]models.NetworkEvent, error) {
	builder := sq.
		Select(
			"id", "machine_id", "event_time", "event_type", "pid", "uid", "process_name",
			"src_addr", "dst_addr", "src_port", "dst_port", "protocol",
			"severity", "status", "notes", "created_at", "updated_at",
		).
		From("network_events").
		Where(sq.Eq{"dst_port": port}).
		OrderBy("event_time DESC")
	if limit > 0 {
		builder = builder.Limit(limit)
	}
	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("network.ListByDstPort: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *NetworkQueries) ListByTimeRange(ctx context.Context, start, end int64) ([]models.NetworkEvent, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "event_time", "event_type", "pid", "uid", "process_name",
			"src_addr", "dst_addr", "src_port", "dst_port", "protocol",
			"severity", "status", "notes", "created_at", "updated_at",
		).
		From("network_events").
		Where(sq.And{
			sq.GtOrEq{"event_time": start},
			sq.LtOrEq{"event_time": end},
		}).
		OrderBy("event_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("network.ListByTimeRange: build: %w", err)
	}
	return q.scanRows(ctx, sqlStr, args...)
}

func (q *NetworkQueries) DeleteLowSeverityBefore(ctx context.Context, cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("network_events").
		Where(sq.And{
			sq.Lt{"event_time": cutoff},
			sq.Eq{"severity": string(models.SeverityLow)},
		}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("network.DeleteLowSeverityBefore: build: %w", err)
	}
	res, err := q.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q *NetworkQueries) scanRows(ctx context.Context, sqlStr string, args ...interface{}) ([]models.NetworkEvent, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.NetworkEvent
	for rows.Next() {
		var e models.NetworkEvent
		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.EventTime, &e.EventType, &e.PID, &e.UID, &e.ProcessName,
			&e.SrcAddr, &e.DstAddr, &e.SrcPort, &e.DstPort, &e.Protocol,
			&e.Severity, &e.Status, &e.Notes, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("network.scanRows: scan: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
