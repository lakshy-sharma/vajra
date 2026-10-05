// internal/db/queries/artifacts.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"encoding/json"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"vajra/internal/db"
	"vajra/shared/models"
)

type ArtifactQueries struct {
	db *db.DB
}

func NewArtifactQueries(d *db.DB) *ArtifactQueries {
	return &ArtifactQueries{db: d}
}

// Insert writes file hash and YARA matches for a detection.
func (q *ArtifactQueries) Insert(a *models.DetectionArtifact) error {
	yaraJSON, err := json.Marshal(a.YaraMatches)
	if err != nil {
		return fmt.Errorf("artifacts.Insert: marshal yara: %w", err)
	}
	sqlStr, args, err := sq.
		Insert("detection_artifacts").
		Columns("detection_id", "file_hash", "file_size", "yara_matches").
		Values(a.DetectionID, a.FileHash, a.FileSize, string(yaraJSON)).
		ToSql()
	if err != nil {
		return fmt.Errorf("artifacts.Insert: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// GetByDetectionID returns the artifact record for a detection.
func (q *ArtifactQueries) GetByDetectionID(detectionID int64) (*models.DetectionArtifact, error) {
	sqlStr, args, err := sq.
		Select("id", "detection_id", "file_hash", "file_size", "yara_matches").
		From("detection_artifacts").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("artifacts.GetByDetectionID: build: %w", err)
	}
	row := q.db.SQL().QueryRow(sqlStr, args...)
	var a models.DetectionArtifact
	var yaraJSON string
	if err := row.Scan(&a.ID, &a.DetectionID, &a.FileHash, &a.FileSize, &yaraJSON); err != nil {
		return nil, fmt.Errorf("artifacts.GetByDetectionID: scan: %w", err)
	}
	if err := json.Unmarshal([]byte(yaraJSON), &a.YaraMatches); err != nil {
		a.YaraMatches = nil
	}
	return &a, nil
}
