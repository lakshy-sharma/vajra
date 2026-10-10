// internal/db/queries/secrets.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"
	"vajra/shared/models"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
)

type SecretQueries struct {
	db *shareddb.DB
}

func NewSecretQueries(d *shareddb.DB) *SecretQueries {
	return &SecretQueries{db: d}
}

func (q *SecretQueries) Insert(e *models.DetectionSecret) error {
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
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *SecretQueries) GetByDetectionID(detectionID int64) ([]models.DetectionSecret, error) {
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

	rows, err := q.db.SQL().Query(sqlStr, args...)
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

// ListIgnoredFingerprints returns the betterleaks fingerprints for all
// detection_secrets whose parent detection has status = IGNORED.
// Used by `vajra secrets export-ignore` to write the ignore file.
func (q *SecretQueries) ListIgnoredFingerprints() ([]string, error) {
	sqlStr := `
		SELECT ds.fingerprint
		FROM detection_secrets ds
		JOIN detections d ON d.id = ds.detection_id
		WHERE d.status = ?
		  AND ds.fingerprint != ''
		ORDER BY ds.fingerprint`

	rows, err := q.db.SQL().Query(sqlStr, string(models.StatusIgnored))
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
