// internal/db/queries/secrets.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"vajra/internal/db"
	"vajra/shared/models"
)

type SecretQueries struct {
	db *db.DB
}

func NewSecretQueries(d *db.DB) *SecretQueries {
	return &SecretQueries{db: d}
}

// Insert writes a betterleaks finding. The raw secret value must
// never reach this function — only sha256(secret) is accepted.
func (q *SecretQueries) Insert(s *models.DetectionSecret) error {
	sqlStr, args, err := sq.
		Insert("detection_secrets").
		Columns("detection_id", "rule_id", "secret_hash", "start_line", "end_line", "match_context").
		Values(s.DetectionID, s.RuleID, s.SecretHash, s.StartLine, s.EndLine, s.MatchContext).
		ToSql()
	if err != nil {
		return fmt.Errorf("secrets.Insert: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// ListBySecretHash returns all detections for a given secret hash —
// the credential spread query across machines and time.
func (q *SecretQueries) ListBySecretHash(hash string) ([]models.DetectionSecret, error) {
	sqlStr, args, err := sq.
		Select("id", "detection_id", "rule_id", "secret_hash", "start_line", "end_line", "match_context").
		From("detection_secrets").
		Where(sq.Eq{"secret_hash": hash}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("secrets.ListBySecretHash: build: %w", err)
	}
	return q.scanRows(sqlStr, args...)
}

func (q *SecretQueries) scanRows(sqlStr string, args ...interface{}) ([]models.DetectionSecret, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.DetectionSecret
	for rows.Next() {
		var s models.DetectionSecret
		if err := rows.Scan(
			&s.ID, &s.DetectionID, &s.RuleID, &s.SecretHash,
			&s.StartLine, &s.EndLine, &s.MatchContext,
		); err != nil {
			return nil, fmt.Errorf("secrets.scanRows: scan: %w", err)
		}
		results = append(results, s)
	}
	return results, rows.Err()
}
