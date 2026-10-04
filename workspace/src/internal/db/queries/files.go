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

type FileQueries struct {
	db *db.DB
}

func NewFileQueries(d *db.DB) *FileQueries {
	return &FileQueries{db: d}
}

func (q *FileQueries) Insert(r *models.FileScanResult) error {
	yaraJSON, err := json.Marshal(r.YaraMatches)
	if err != nil {
		return fmt.Errorf("files.Insert: marshal yara: %w", err)
	}

	sqlStr, args, err := sq.
		Insert("file_scan_results").
		Columns(
			"machine_id", "scan_time", "file_path", "file_size", "file_hash",
			"yara_matches", "severity", "status",
			"event_type", "trigger_pid", "trigger_uid", "trigger_comm",
			"dedup_count", "notes",
		).
		Values(
			r.MachineID, r.ScanTime, r.FilePath, r.FileSize, r.FileHash,
			string(yaraJSON), string(r.Severity), string(r.Status),
			r.EventType, r.TriggerPID, r.TriggerUID, r.TriggerComm,
			r.DedupCount, r.Notes,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("files.Insert: build query: %w", err)
	}

	res, err := q.db.SQL().Exec(sqlStr, args...)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("files.Insert: last insert id: %w", err)
	}
	r.ID = id
	return nil
}

func (q *FileQueries) BatchInsert(results []models.FileScanResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := q.db.SQL().Begin()
	if err != nil {
		return fmt.Errorf("files.BatchInsert: begin tx: %w", err)
	}
	defer tx.Rollback()

	for i := range results {
		r := &results[i]
		yaraJSON, err := json.Marshal(r.YaraMatches)
		if err != nil {
			return fmt.Errorf("files.BatchInsert: marshal yara row %d: %w", i, err)
		}

		sqlStr, args, err := sq.
			Insert("file_scan_results").
			Columns(
				"machine_id", "scan_time", "file_path", "file_size", "file_hash",
				"yara_matches", "severity", "status",
				"event_type", "trigger_pid", "trigger_uid", "trigger_comm",
				"dedup_count", "notes",
			).
			Values(
				r.MachineID, r.ScanTime, r.FilePath, r.FileSize, r.FileHash,
				string(yaraJSON), string(r.Severity), string(r.Status),
				r.EventType, r.TriggerPID, r.TriggerUID, r.TriggerComm,
				r.DedupCount, r.Notes,
			).
			ToSql()
		if err != nil {
			return fmt.Errorf("files.BatchInsert: build query row %d: %w", i, err)
		}

		if _, err := tx.Exec(sqlStr, args...); err != nil {
			return fmt.Errorf("files.BatchInsert: exec row %d: %w", i, err)
		}
	}

	return tx.Commit()
}

func (q *FileQueries) IncrementDedupCount(id int64) error {
	sqlStr, args, err := sq.
		Update("file_scan_results").
		Set("dedup_count", sq.Expr("dedup_count + 1")).
		Set("updated_at", time.Now().UTC()).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("files.IncrementDedupCount: build query: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *FileQueries) UpdateStatus(id int64, status models.EventStatus, notes string) error {
	sqlStr, args, err := sq.
		Update("file_scan_results").
		Set("status", string(status)).
		Set("notes", notes).
		Set("updated_at", time.Now().UTC()).
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("files.UpdateStatus: build query: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *FileQueries) ListBySeverity(limit uint64, severities ...models.EventSeverity) ([]models.FileScanResult, error) {
	vals := make([]interface{}, len(severities))
	for i, s := range severities {
		vals[i] = string(s)
	}

	builder := sq.
		Select(
			"id", "machine_id", "scan_time", "file_path", "file_size", "file_hash",
			"yara_matches", "severity", "status",
			"event_type", "trigger_pid", "trigger_uid", "trigger_comm",
			"dedup_count", "notes", "created_at", "updated_at",
		).
		From("file_scan_results").
		Where(sq.Eq{"severity": vals}).
		OrderBy("scan_time DESC")

	if limit > 0 {
		builder = builder.Limit(limit)
	}

	sqlStr, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("files.ListBySeverity: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *FileQueries) ListByTimeRange(start, end int64) ([]models.FileScanResult, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "scan_time", "file_path", "file_size", "file_hash",
			"yara_matches", "severity", "status",
			"event_type", "trigger_pid", "trigger_uid", "trigger_comm",
			"dedup_count", "notes", "created_at", "updated_at",
		).
		From("file_scan_results").
		Where(sq.And{
			sq.GtOrEq{"scan_time": start},
			sq.LtOrEq{"scan_time": end},
		}).
		OrderBy("scan_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("files.ListByTimeRange: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *FileQueries) GetByHash(hash string) ([]models.FileScanResult, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "machine_id", "scan_time", "file_path", "file_size", "file_hash",
			"yara_matches", "severity", "status",
			"event_type", "trigger_pid", "trigger_uid", "trigger_comm",
			"dedup_count", "notes", "created_at", "updated_at",
		).
		From("file_scan_results").
		Where(sq.Eq{"file_hash": hash}).
		OrderBy("scan_time DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("files.GetByHash: build query: %w", err)
	}

	return q.scanRows(sqlStr, args...)
}

func (q *FileQueries) DeleteResolvedBefore(cutoff int64) (int64, error) {
	sqlStr, args, err := sq.
		Delete("file_scan_results").
		Where(sq.And{
			sq.Lt{"scan_time": cutoff},
			sq.Eq{"status": string(models.StatusResolved)},
		}).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf("files.DeleteResolvedBefore: build query: %w", err)
	}

	res, err := q.db.SQL().Exec(sqlStr, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (q *FileQueries) scanRows(sqlStr string, args ...interface{}) ([]models.FileScanResult, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.FileScanResult
	for rows.Next() {
		var r models.FileScanResult
		var yaraJSON string
		var createdAt, updatedAt string

		if err := rows.Scan(
			&r.ID, &r.MachineID, &r.ScanTime, &r.FilePath, &r.FileSize, &r.FileHash,
			&yaraJSON, &r.Severity, &r.Status,
			&r.EventType, &r.TriggerPID, &r.TriggerUID, &r.TriggerComm,
			&r.DedupCount, &r.Notes, &createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("files.scanRows: scan: %w", err)
		}

		if err := json.Unmarshal([]byte(yaraJSON), &r.YaraMatches); err != nil {
			r.YaraMatches = nil
		}

		results = append(results, r)
	}

	return results, rows.Err()
}
