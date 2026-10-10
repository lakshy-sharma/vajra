// internal/db/queries/evidence.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
	"vajra/shared/models"
)

type EvidenceQueries struct {
	db *shareddb.DB
}

func NewEvidenceQueries(d *shareddb.DB) *EvidenceQueries {
	return &EvidenceQueries{db: d}
}

// Insert writes a process state snapshot captured at detection time.
func (q *EvidenceQueries) Insert(e *models.EvidenceSnapshot) error {
	sqlStr, args, err := sq.
		Insert("evidence_snapshots").
		Columns("detection_id", "captured_at", "open_fds", "maps", "environ", "status").
		Values(e.DetectionID, e.CapturedAt, e.OpenFDs, e.Maps, e.Environ, e.Status).
		ToSql()
	if err != nil {
		return fmt.Errorf("evidence.Insert: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// GetByDetectionID returns the evidence snapshot for a detection.
func (q *EvidenceQueries) GetByDetectionID(detectionID int64) (*models.EvidenceSnapshot, error) {
	sqlStr, args, err := sq.
		Select("id", "detection_id", "captured_at", "open_fds", "maps", "environ", "status").
		From("evidence_snapshots").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("evidence.GetByDetectionID: build: %w", err)
	}
	row := q.db.SQL().QueryRow(sqlStr, args...)
	var e models.EvidenceSnapshot
	if err := row.Scan(
		&e.ID, &e.DetectionID, &e.CapturedAt,
		&e.OpenFDs, &e.Maps, &e.Environ, &e.Status,
	); err != nil {
		return nil, fmt.Errorf("evidence.GetByDetectionID: scan: %w", err)
	}
	return &e, nil
}
