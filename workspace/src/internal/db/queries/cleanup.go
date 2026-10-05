// internal/db/queries/cleanup.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"
	"time"

	"vajra/internal/db"
)

type CleanupQueries struct {
	db *db.DB
}

func NewCleanupQueries(d *db.DB) *CleanupQueries {
	return &CleanupQueries{db: d}
}

type CleanupResult struct {
	DetectionsDeleted  int64
	NetworkRowsDeleted int64
	MemoryRowsDeleted  int64
}

func (q *CleanupQueries) RunCleanup(retentionDays int) (CleanupResult, error) {
	if retentionDays <= 0 {
		retentionDays = 90
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	var result CleanupResult
	var err error

	result.DetectionsDeleted, err = NewDetectionQueries(q.db).DeleteResolvedBefore(cutoff)
	if err != nil {
		return result, fmt.Errorf("cleanup: detections: %w", err)
	}

	result.NetworkRowsDeleted, err = NewNetworkQueries(q.db).DeleteLowSeverityBefore(cutoff)
	if err != nil {
		return result, fmt.Errorf("cleanup: network_events: %w", err)
	}

	result.MemoryRowsDeleted, err = NewMemoryQueries(q.db).DeleteBefore(cutoff)
	if err != nil {
		return result, fmt.Errorf("cleanup: memory_events: %w", err)
	}

	if _, err := q.db.SQL().Exec("VACUUM"); err != nil {
		return result, fmt.Errorf("cleanup: vacuum: %w", err)
	}

	return result, nil
}
