// internal/db/queries/extensions.go
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

type ExtensionQueries struct {
	db *shareddb.DB
}

func NewExtensionQueries(d *shareddb.DB) *ExtensionQueries {
	return &ExtensionQueries{db: d}
}

// Insert writes one key/value extension row for a detection.
func (q *ExtensionQueries) Insert(e *models.DetectionExtension) error {
	sqlStr, args, err := sq.
		Insert("detection_extensions").
		Columns("detection_id", "key", "value").
		Values(e.DetectionID, e.Key, e.Value).
		ToSql()
	if err != nil {
		return fmt.Errorf("extensions.Insert: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// InsertAll writes all extensions for a detection in one transaction.
func (q *ExtensionQueries) InsertAll(detectionID int64, extensions map[string]string) error {
	if len(extensions) == 0 {
		return nil
	}
	tx, err := q.db.SQL().Begin()
	if err != nil {
		return fmt.Errorf("extensions.InsertAll: begin: %w", err)
	}
	defer tx.Rollback()

	for key, value := range extensions {
		sqlStr, args, err := sq.
			Insert("detection_extensions").
			Columns("detection_id", "key", "value").
			Values(detectionID, key, value).
			ToSql()
		if err != nil {
			return fmt.Errorf("extensions.InsertAll: build: %w", err)
		}
		if _, err := tx.Exec(sqlStr, args...); err != nil {
			return fmt.Errorf("extensions.InsertAll: exec key %q: %w", key, err)
		}
	}
	return tx.Commit()
}

// GetByDetectionID returns all extension rows for a detection.
func (q *ExtensionQueries) GetByDetectionID(detectionID int64) ([]models.DetectionExtension, error) {
	sqlStr, args, err := sq.
		Select("id", "detection_id", "key", "value").
		From("detection_extensions").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("extensions.GetByDetectionID: build: %w", err)
	}
	rows, err := q.db.SQL().Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.DetectionExtension
	for rows.Next() {
		var e models.DetectionExtension
		if err := rows.Scan(&e.ID, &e.DetectionID, &e.Key, &e.Value); err != nil {
			return nil, fmt.Errorf("extensions.GetByDetectionID: scan: %w", err)
		}
		results = append(results, e)
	}
	return results, rows.Err()
}
