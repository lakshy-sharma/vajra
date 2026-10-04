// internal/db/queries/security.go
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

type SecurityQueries struct {
	db *db.DB
}

func NewSecurityQueries(d *db.DB) *SecurityQueries {
	return &SecurityQueries{db: d}
}

func (q *SecurityQueries) Insert(e *models.SecurityEvent) error {
	yaraJSON, err := json.Marshal(e.YaraMatches)
	if err != nil {
		return fmt.Errorf("security.Insert: marshal yara: %w", err)
	}

	sqlStr, args, err := sq.
		Insert("security_events").
		Columns(
			"machine_id", "event_time", "event_type", "event_name",
			"pid", "uid", "process_name",
			"target_pid", "target_path", "details",
			"severity", "status", "yara_matches", "action_taken", "notes",
		).
		Values(
			e.MachineID, e.EventTime, e.EventType, e.EventName,
			e.PID, e.UID, e.ProcessName,
			e.TargetPID, e.TargetPath, e.Details,
			string(e.Severity), string(e.Status), string(yaraJSON), e.ActionTaken, e.Notes,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("security.Insert: build query: %w", err)
	}

	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *SecurityQueries) UpdateStatus(id int64, status models.EventStatus, notes string) error {
	sqlStr, args, err := sq.
		Update("security_events").
		Set("status", string(status)).
		Set("notes", notes).
		Set("updated_at", time.Now().UTC()).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("security.UpdateStatus: build query: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *SecurityQueries) ListCritical(limit uint64) ([]models.SecurityEvent, error) {
	builder := sq.
		Select(
			"id", "machine_id", "event_time", "event_type", "event_name",
			"pid", "uid", "process_name",
			"target_pid", "target_path", "details",
			"severity", "status", "yara_matches", "action_taken", "notes",
			"created_at", "updated_at",
		).
		From("security_events").
		Where(sq.Eq{"severity": string(models.SeverityCritical)}).
		OrderBy("event_time DESC")

	if limit > 0 {
		builder = builder.Limit(limit)
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("security.ListCritical: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *SecurityQueries) scanRows(sqlStr string, args ...interface{}) ([]models.SecurityEvent, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.SecurityEvent
	for rows.Next() {
		var e models.SecurityEvent
		var yaraJSON string
		var createdAt, updatedAt string

		if err := rows.Scan(
			&e.ID, &e.MachineID, &e.EventTime, &e.EventType, &e.EventName,
			&e.PID, &e.UID, &e.ProcessName,
			&e.TargetPID, &e.TargetPath, &e.Details,
			&e.Severity, &e.Status, &yaraJSON, &e.ActionTaken, &e.Notes,
			&createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("security.scanRows: scan: %w", err)
		}

		if err := json.Unmarshal([]byte(yaraJSON), &e.YaraMatches); err != nil {
			e.YaraMatches = nil
		}

		events = append(events, e)
	}

	return events, rows.Err()
}
