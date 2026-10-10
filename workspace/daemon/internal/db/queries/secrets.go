// internal/db/queries/secrets.go
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

type SecretQueries struct {
	db shareddb.DBConn
}

func NewSecretQueries(d shareddb.DBConn) *SecretQueries {
	return &SecretQueries{db: d}
}

func (q *SecretQueries) Insert(ctx context.Context, e *models.DetectionSecret) error {
	sqlStr, args, err := sq.
		Insert("detection_secrets").
		Columns(
			"detection_id", "rule_id", "secret_hash",
			"fingerprint", "start_line", "end_line", "match_context",
		).
		Values(
			e.DetectionID, e.RuleID, e.SecretHash,
			e.Fingerprint, e.StartLine, e.EndLine, e.MatchContext,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("secrets.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

func (q *SecretQueries) GetByDetectionID(ctx context.Context, detectionID int64) ([]models.DetectionSecret, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "detection_id", "rule_id", "secret_hash",
			"fingerprint", "start_line", "end_line", "match_context",
		).
		From("detection_secrets").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("secrets.GetByDetectionID: build: %w", err)
	}
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.DetectionSecret
	for rows.Next() {
		var e models.DetectionSecret
		if err := rows.Scan(
			&e.ID, &e.DetectionID, &e.RuleID, &e.SecretHash,
			&e.Fingerprint, &e.StartLine, &e.EndLine, &e.MatchContext,
		); err != nil {
			return nil, fmt.Errorf("secrets.GetByDetectionID: scan: %w", err)
		}
		results = append(results, e)
	}
	return results, rows.Err()
}

// ListIgnoredFingerprints returns betterleaks fingerprints for all secrets
// whose parent detection is IGNORED — used by `vajra secrets export-ignore`.
func (q *SecretQueries) ListIgnoredFingerprints(ctx context.Context) ([]string, error) {
	sqlStr, args, err := sq.
		Select("ds.fingerprint").
		From("detection_secrets ds").
		Join("detections d ON d.id = ds.detection_id").
		Where(sq.And{
			sq.Eq{"d.status": string(models.StatusIgnored)},
			sq.NotEq{"ds.fingerprint": ""},
		}).
		OrderBy("ds.fingerprint").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("secrets.ListIgnoredFingerprints: build: %w", err)
	}
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("secrets.ListIgnoredFingerprints: %w", err)
	}
	defer rows.Close()

	var fps []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("secrets.ListIgnoredFingerprints: scan: %w", err)
		}
		fps = append(fps, fp)
	}
	return fps, rows.Err()
}
