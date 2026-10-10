// ui/internal/queries/queries.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License
//
// Read-only query layer for the Vajra desktop UI.
// All queries are SELECT-only; the DB is opened in WAL read-only mode by app.go.
//
// UI10: queries now use the DBConn interface methods (QueryContext,
// QueryRowContext) rather than db.SQL() which was removed in D1.

package queries

import (
	"context"

	shareddb "vajra/shared/db"
)

// Queries is the single entry point for all UI read queries.
type Queries struct {
	db *shareddb.DB
}

func New(db *shareddb.DB) *Queries {
	return &Queries{db: db}
}

// bg is a convenience alias — UI query methods are always called from
// synchronous Wails handler goroutines with no cancellation path.
func bg() context.Context { return context.Background() }
