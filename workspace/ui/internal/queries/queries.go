// ui/internal/queries/queries.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License
//
// Read-only query layer for the Vajra desktop UI.
// All queries are SELECT-only; the DB is opened in WAL read-only mode by app.go.
//
// Note: these query structs live here (ui/internal/queries) rather than
// reusing daemon/internal/db/queries because Go's `internal` directory rule
// prevents cross-module imports of internal packages.

package queries

import (
	shareddb "vajra/shared/db"
)

// Queries is the single entry point for all UI read queries.
type Queries struct {
	db *shareddb.DB
}

func New(db *shareddb.DB) *Queries {
	return &Queries{db: db}
}
