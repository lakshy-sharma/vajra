// internal/db/queries/statistics.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"
	"vajra/shared/models"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
)

type StatisticsQueries struct {
	db *shareddb.DB
}

func NewStatisticsQueries(d *shareddb.DB) *StatisticsQueries {
	return &StatisticsQueries{db: d}
}

// Aggregate re-computes event_statistics from the three raw event tables.
// Each source is a single INSERT … ON CONFLICT DO UPDATE, so the full day
// bucket is re-aggregated on every call — counts stay correct even after
// rows are deleted by the cleanup job.
// Returns the total number of rows upserted across all sources.
func (q *StatisticsQueries) Aggregate() (int64, error) {
	sources := []struct {
		name  string
		query string
	}{
		{"security_events", aggregateSecurityEventsSQL},
		{"network_events", aggregateNetworkEventsSQL},
		{"memory_events", aggregateMemoryEventsSQL},
	}

	var total int64
	for _, src := range sources {
		res, err := q.db.SQL().Exec(src.query)
		if err != nil {
			return total, fmt.Errorf("statistics.Aggregate(%s): %w", src.name, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// ListByDateRange returns rows whose date falls within [start, end] inclusive.
// Dates are "YYYY-MM-DD" strings.
func (q *StatisticsQueries) ListByDateRange(start, end string) ([]models.EventStatistic, error) {
	sqlStr, args, err := sq.
		Select("id", "date", "event_type", "event_name",
			"total_count", "malicious_count", "clean_count").
		From("event_statistics").
		Where(sq.GtOrEq{"date": start}).
		Where(sq.LtOrEq{"date": end}).
		OrderBy("date ASC", "event_type ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("statistics.ListByDateRange: build: %w", err)
	}
	return q.scan(sqlStr, args...)
}

// ListByDate returns all rows for a single date ("YYYY-MM-DD").
func (q *StatisticsQueries) ListByDate(date string) ([]models.EventStatistic, error) {
	sqlStr, args, err := sq.
		Select("id", "date", "event_type", "event_name",
			"total_count", "malicious_count", "clean_count").
		From("event_statistics").
		Where(sq.Eq{"date": date}).
		OrderBy("event_type ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("statistics.ListByDate: build: %w", err)
	}
	return q.scan(sqlStr, args...)
}

// Totals returns one aggregated row per event_type across all dates —
// useful for the UI's all-time summary panel.
func (q *StatisticsQueries) Totals() ([]models.EventStatistic, error) {
	const sqlStr = `
		SELECT
			0                    AS id,
			''                   AS date,
			event_type,
			event_name,
			SUM(total_count)     AS total_count,
			SUM(malicious_count) AS malicious_count,
			SUM(clean_count)     AS clean_count
		FROM event_statistics
		GROUP BY event_type
		ORDER BY event_type ASC`
	return q.scan(sqlStr)
}

func (q *StatisticsQueries) scan(sqlStr string, args ...interface{}) ([]models.EventStatistic, error) {
	rows, err := q.db.SQL().Query(sqlStr, args...)
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

// ── SQL ───────────────────────────────────────────────────────────────────────

const aggregateSecurityEventsSQL = `
INSERT INTO event_statistics (date, event_type, event_name, total_count, malicious_count, clean_count)
SELECT
    strftime('%Y-%m-%d', event_time, 'unixepoch')          AS date,
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

// network_events has no event_name column — use the literal 'network_event'.
const aggregateNetworkEventsSQL = `
INSERT INTO event_statistics (date, event_type, event_name, total_count, malicious_count, clean_count)
SELECT
    strftime('%Y-%m-%d', event_time, 'unixepoch')          AS date,
    event_type,
    'network_event'                                         AS event_name,
    COUNT(*)                                                AS total_count,
    SUM(CASE WHEN severity != 'CLEAN' THEN 1 ELSE 0 END)  AS malicious_count,
    SUM(CASE WHEN severity  = 'CLEAN' THEN 1 ELSE 0 END)  AS clean_count
FROM network_events
GROUP BY date, event_type
ON CONFLICT(date, event_type) DO UPDATE SET
    total_count     = excluded.total_count,
    malicious_count = excluded.malicious_count,
    clean_count     = excluded.clean_count`

// memory_events has no event_name column — use the literal 'memory_event'.
const aggregateMemoryEventsSQL = `
INSERT INTO event_statistics (date, event_type, event_name, total_count, malicious_count, clean_count)
SELECT
    strftime('%Y-%m-%d', event_time, 'unixepoch')          AS date,
    event_type,
    'memory_event'                                          AS event_name,
    COUNT(*)                                                AS total_count,
    SUM(CASE WHEN severity != 'CLEAN' THEN 1 ELSE 0 END)  AS malicious_count,
    SUM(CASE WHEN severity  = 'CLEAN' THEN 1 ELSE 0 END)  AS clean_count
FROM memory_events
GROUP BY date, event_type
ON CONFLICT(date, event_type) DO UPDATE SET
    total_count     = excluded.total_count,
    malicious_count = excluded.malicious_count,
    clean_count     = excluded.clean_count`
