// internal/db/queries/cleanup.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"context"
	"fmt"

	shareddb "vajra/shared/db"
)

type CleanupQueries struct {
	db shareddb.DBConn
}

func NewCleanupQueries(d shareddb.DBConn) *CleanupQueries {
	return &CleanupQueries{db: d}
}

type CleanupResult struct {
	DetectionsDeleted   int64
	SecurityRowsDeleted int64
	NetworkRowsDeleted  int64
	MemoryRowsDeleted   int64
}

// RunCleanup deletes old rows across event tables then checkpoints the WAL.
// cutoff is the Unix epoch before which rows are eligible for removal.
// VACUUM cannot run inside a transaction; WAL checkpoint reclaims space instead.
func (q *CleanupQueries) RunCleanup(ctx context.Context, cutoff int64) (CleanupResult, error) {
	var result CleanupResult
	var err error

	result.DetectionsDeleted, err = NewDetectionQueries(q.db).DeleteResolvedBefore(ctx, cutoff)
	if err != nil {
		return result, fmt.Errorf("cleanup: detections: %w", err)
	}

	result.SecurityRowsDeleted, err = NewSecurityQueries(q.db).DeleteLowSeverityBefore(ctx, cutoff)
	if err != nil {
		return result, fmt.Errorf("cleanup: security_events: %w", err)
	}

	result.NetworkRowsDeleted, err = NewNetworkQueries(q.db).DeleteLowSeverityBefore(ctx, cutoff)
	if err != nil {
		return result, fmt.Errorf("cleanup: network_events: %w", err)
	}

	result.MemoryRowsDeleted, err = NewMemoryQueries(q.db).DeleteBefore(ctx, cutoff)
	if err != nil {
		return result, fmt.Errorf("cleanup: memory_events: %w", err)
	}

	if _, err := q.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return result, fmt.Errorf("cleanup: checkpoint: %w", err)
	}

	return result, nil
}
