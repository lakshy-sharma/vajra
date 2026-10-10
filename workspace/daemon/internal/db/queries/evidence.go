// internal/db/queries/evidence.go
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

type EvidenceQueries struct {
	db shareddb.DBConn
}

func NewEvidenceQueries(d shareddb.DBConn) *EvidenceQueries {
	return &EvidenceQueries{db: d}
}

func (q *EvidenceQueries) Insert(ctx context.Context, e *models.EvidenceSnapshot) error {
	sqlStr, args, err := sq.
		Insert("evidence_snapshots").
		Columns("detection_id", "captured_at", "open_fds", "maps", "environ", "status").
		Values(e.DetectionID, e.CapturedAt, e.OpenFDs, e.Maps, e.Environ, e.Status).
		ToSql()
	if err != nil {
		return fmt.Errorf("evidence.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *EvidenceQueries) GetByDetectionID(ctx context.Context, detectionID int64) (*models.EvidenceSnapshot, error) {
	sqlStr, args, err := sq.
		Select("id", "detection_id", "captured_at", "open_fds", "maps", "environ", "status").
		From("evidence_snapshots").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("evidence.GetByDetectionID: build: %w", err)
	}
	row := q.db.QueryRowContext(ctx, sqlStr, args...)
	var e models.EvidenceSnapshot
	if err := row.Scan(
		&e.ID, &e.DetectionID, &e.CapturedAt,
		&e.OpenFDs, &e.Maps, &e.Environ, &e.Status,
	); err != nil {
		return nil, fmt.Errorf("evidence.GetByDetectionID: scan: %w", err)
	}
	return &e, nil
}
