// internal/db/queries/network.go
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

type NetworkQueries struct {
	db *db.DB
}

func NewNetworkQueries(d *db.DB) *NetworkQueries {
	return &NetworkQueries{db: d}
}

func (q *NetworkQueries) Insert(e *models.NetworkEvent) error {
	sqlStr, args, err := sq.
		Insert("network_events").
		Columns(
			"event_time", "event_type", "pid", "uid", "process_name",
			"src_addr", "dst_addr", "src_port", "dst_port", "protocol",
			"severity", "status", "notes",
		).
		Values(
			e.EventTime, e.EventType, e.PID, e.UID, e.ProcessName,
			e.SrcAddr, e.DstAddr, e.SrcPort, e.DstPort, e.Protocol,
			string(e.Severity), string(e.Status), e.Notes,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("network.Insert: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *NetworkQueries) ListByDstPort(port uint16, limit uint64) ([]models.NetworkEvent, error) {
	builder := sq.
		Select(
			"id", "event_time", "event_type", "pid", "uid", "process_name",
			"src_addr", "dst_addr", "src_port", "dst_port", "protocol",
			"severity", "status", "notes", "created_at",
		).
		From("network_events").
		Where(sq.Eq{"dst_port": port}).
		OrderBy("event_time DESC")

	if limit > 0 {
		builder = builder.Limit(limit)
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("network.ListByDstPort: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *NetworkQueries) ListByTimeRange(start, end int64) ([]models.NetworkEvent, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "event_time", "event_type", "pid", "uid", "process_name",
			"src_addr", "dst_addr", "src_port", "dst_port", "protocol",
			"severity", "status", "notes", "created_at",
		).
		From("network_events").
		Where(sq.And{
			sq.GtOrEq{"event_time": start},
			sq.LtOrEq{"event_time": end},
		}).
		OrderBy("event_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("network.ListByTimeRange: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

// DeleteLowSeverityBefore removes LOW severity rows older than cutoff.
func (q *NetworkQueries) DeleteLowSeverityBefore(cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("network_events").
		Where(sq.And{
			sq.Lt{"event_time": cutoff},
			sq.Eq{"severity": string(models.SeverityLow)},
		}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("network.DeleteLowSeverityBefore: build query: %w", err)
	}

	res, err := q.db.SQL().Exec(sqlStr, args...)
	if err != nil {
		return 0, err
	}

	return res.RowsAffected()
}

func (q *NetworkQueries) scanRows(sqlStr string, args ...interface{}) ([]models.NetworkEvent, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.NetworkEvent
	for rows.Next() {
		var e models.NetworkEvent
		var createdAt string

		if err := rows.Scan(
			&e.ID, &e.EventTime, &e.EventType, &e.PID, &e.UID, &e.ProcessName,
			&e.SrcAddr, &e.DstAddr, &e.SrcPort, &e.DstPort, &e.Protocol,
			&e.Severity, &e.Status, &e.Notes, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("network.scanRows: scan: %w", err)
		}

		events = append(events, e)
	}

	return events, rows.Err()
}
