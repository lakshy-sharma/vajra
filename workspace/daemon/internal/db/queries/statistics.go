// internal/db/queries/statistics.go
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

type StatisticsQueries struct {
	db shareddb.DBConn
}

func NewStatisticsQueries(d shareddb.DBConn) *StatisticsQueries {
	return &StatisticsQueries{db: d}
}

// Aggregate re-computes event_statistics from the three raw event tables.
// Full re-aggregation on every call keeps counts correct after cleanup deletions.
func (q *StatisticsQueries) Aggregate(ctx context.Context) (int64, error) {
	sources := []struct {
		name string
		sql  string
	}{
		{"security_events", aggregateSecurityEventsSQL},
		{"network_events", aggregateNetworkEventsSQL},
		{"memory_events", aggregateMemoryEventsSQL},
	}

	var total int64
	for _, src := range sources {
		res, err := q.db.ExecContext(ctx, src.sql)
		if err != nil {
			return total, fmt.Errorf("statistics.Aggregate(%s): %w", src.name, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// ListByDateRange returns rows whose date epoch falls within [start, end] inclusive.
// start and end are Unix epoch seconds of UTC day boundaries.
func (q *StatisticsQueries) ListByDateRange(ctx context.Context, start, end int64) ([]models.EventStatistic, error) {
	sqlStr, args, err := sq.
		Select("id", "date", "event_type", "event_name", "total_count", "malicious_count", "clean_count").
		From("event_statistics").
		Where(sq.GtOrEq{"date": start}).
		Where(sq.LtOrEq{"date": end}).
		OrderBy("date ASC", "event_type ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("statistics.ListByDateRange: build: %w", err)
	}
	return q.scan(ctx, sqlStr, args...)
}

// ListByDate returns all rows for a single UTC day given as its epoch start.
func (q *StatisticsQueries) ListByDate(ctx context.Context, dayEpoch int64) ([]models.EventStatistic, error) {
	sqlStr, args, err := sq.
		Select("id", "date", "event_type", "event_name", "total_count", "malicious_count", "clean_count").
		From("event_statistics").
		Where(sq.Eq{"date": dayEpoch}).
		OrderBy("event_type ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("statistics.ListByDate: build: %w", err)
	}
	return q.scan(ctx, sqlStr, args...)
}

// Totals returns lifetime aggregates per event_type across all dates.
func (q *StatisticsQueries) Totals(ctx context.Context) ([]models.EventStatistic, error) {
	const sqlStr = `
		SELECT
			0              AS id,
			0              AS date,
			event_type,
			event_name,
			SUM(total_count)     AS total_count,
			SUM(malicious_count) AS malicious_count,
			SUM(clean_count)     AS clean_count
		FROM event_statistics
		GROUP BY event_type
		ORDER BY event_type ASC`
	return q.scan(ctx, sqlStr)
}

func (q *StatisticsQueries) scan(ctx context.Context, sqlStr string, args ...interface{}) ([]models.EventStatistic, error) {
	rows, err := q.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.EventStatistic
	for rows.Next() {
		var e models.EventStatistic
		if err := rows.Scan(
			&e.ID, &e.Date, &e.EventType, &e.EventName,
			&e.TotalCount, &e.MaliciousCount, &e.CleanCount,
		); err != nil {
			return nil, fmt.Errorf("statistics.scan: %w", err)
		}
		results = append(results, e)
	}
	return results, rows.Err()
}

// ── Aggregate SQL ─────────────────────────────────────────────────────────────
// date stored as Unix epoch of UTC day start — strftime converts event_time
// to date string then back to epoch so range queries work with integer comparisons.

const aggregateSecurityEventsSQL = `
INSERT INTO event_statistics (date, event_type, event_name, total_count, malicious_count, clean_count)
SELECT
    CAST(strftime('%s', date(event_time, 'unixepoch')) AS INTEGER) AS date,
    event_type,
    event_name,
    COUNT(*)                                                AS total_count,
    SUM(CASE WHEN severity != 'CLEAN' THEN 1 ELSE 0 END)  AS malicious_count,
    SUM(CASE WHEN severity  = 'CLEAN' THEN 1 ELSE 0 END)  AS clean_count
FROM security_events
GROUP BY date, event_type
ON CONFLICT(date, event_type) DO UPDATE SET
    event_name      = excluded.event_name,
    total_count     = excluded.total_count,
    malicious_count = excluded.malicious_count,
    clean_count     = excluded.clean_count`

// network_events has no event_name column.
const aggregateNetworkEventsSQL = `
INSERT INTO event_statistics (date, event_type, event_name, total_count, malicious_count, clean_count)
SELECT
    CAST(strftime('%s', date(event_time, 'unixepoch')) AS INTEGER) AS date,
    event_type,
    'network_event'                                        AS event_name,
    COUNT(*)                                               AS total_count,
    SUM(CASE WHEN severity != 'CLEAN' THEN 1 ELSE 0 END) AS malicious_count,
    SUM(CASE WHEN severity  = 'CLEAN' THEN 1 ELSE 0 END) AS clean_count
FROM network_events
GROUP BY date, event_type
ON CONFLICT(date, event_type) DO UPDATE SET
    total_count     = excluded.total_count,
    malicious_count = excluded.malicious_count,
    clean_count     = excluded.clean_count`

// memory_events has no event_name column.
const aggregateMemoryEventsSQL = `
INSERT INTO event_statistics (date, event_type, event_name, total_count, malicious_count, clean_count)
SELECT
    CAST(strftime('%s', date(event_time, 'unixepoch')) AS INTEGER) AS date,
    event_type,
    'memory_event'                                         AS event_name,
    COUNT(*)                                               AS total_count,
    SUM(CASE WHEN severity != 'CLEAN' THEN 1 ELSE 0 END) AS malicious_count,
    SUM(CASE WHEN severity  = 'CLEAN' THEN 1 ELSE 0 END) AS clean_count
FROM memory_events
GROUP BY date, event_type
ON CONFLICT(date, event_type) DO UPDATE SET
    total_count     = excluded.total_count,
    malicious_count = excluded.malicious_count,
    clean_count     = excluded.clean_count`
