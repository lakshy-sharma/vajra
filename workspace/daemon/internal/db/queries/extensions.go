// internal/db/queries/extensions.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"context"
	"database/sql"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
	"vajra/shared/models"
)

type ExtensionQueries struct {
	db shareddb.DBConn
}

func NewExtensionQueries(d shareddb.DBConn) *ExtensionQueries {
	return &ExtensionQueries{db: d}
}

func (q *ExtensionQueries) Insert(ctx context.Context, e *models.DetectionExtension) error {
	sqlStr, args, err := sq.
		Insert("detection_extensions").
		Columns("detection_id", "key", "value").
		Values(e.DetectionID, e.Key, e.Value).
		ToSql()
	if err != nil {
		return fmt.Errorf("extensions.Insert: build: %w", err)
	}
	_, err = q.db.ExecContext(ctx, sqlStr, args...)
	return err
}

// InsertAll writes all extensions for one detection atomically.
func (q *ExtensionQueries) InsertAll(ctx context.Context, detectionID int64, extensions map[string]string) error {
	if len(extensions) == 0 {
		return nil
	}
	tx, err := q.db.BeginTx(ctx, &sql.TxOptions{})
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
			return fmt.Errorf("extensions.InsertAll: build key %q: %w", key, err)
		}
		if _, err := tx.ExecContext(ctx, sqlStr, args...); err != nil {
			return fmt.Errorf("extensions.InsertAll: exec key %q: %w", key, err)
		}
	}
	return tx.Commit()
}

func (q *ExtensionQueries) GetByDetectionID(ctx context.Context, detectionID int64) ([]models.DetectionExtension, error) {
	sqlStr, args, err := sq.
		Select("id", "detection_id", "key", "value").
		From("detection_extensions").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("extensions.GetByDetectionID: build: %w", err)
	}
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
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
