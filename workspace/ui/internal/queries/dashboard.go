// ui/internal/queries/dashboard.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import "fmt"

// StatRow mirrors models.EventStatistic for the UI chart panels.
type StatRow struct {
	Date           int64  `json:"date"` // Unix epoch of day start UTC
	EventType      uint32 `json:"eventType"`
	EventName      string `json:"eventName"`
	TotalCount     int64  `json:"totalCount"`
	MaliciousCount int64  `json:"maliciousCount"`
	CleanCount     int64  `json:"cleanCount"`
}

// Totals returns one aggregated row per event_type across all dates.
func (q *Queries) Totals() ([]StatRow, error) {
	const sql = `
		SELECT
			0 AS date,
			event_type,
			event_name,
			SUM(total_count)     AS total_count,
			SUM(malicious_count) AS malicious_count,
			SUM(clean_count)     AS clean_count
		FROM event_statistics
		GROUP BY event_type
		ORDER BY event_type ASC`
	return q.scanStats(sql)
}

// StatsByDateRange returns per-day rows within the given Unix epoch range.
// Q7: uses int64 epoch comparison — was an unvalidated string date comparison.
func (q *Queries) StatsByDateRange(startUnix, endUnix int64) ([]StatRow, error) {
	const sql = `
		SELECT date, event_type, event_name, total_count, malicious_count, clean_count
		FROM event_statistics
		WHERE date >= ? AND date <= ?
		ORDER BY date ASC, event_type ASC`
	return q.scanStats(sql, startUnix, endUnix)
}

func (q *Queries) scanStats(sqlStr string, args ...any) ([]StatRow, error) {
	rows, err := q.db.QueryContext(bg(), sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("dashboard.scanStats: %w", err)
	}
	defer rows.Close()

	var out []StatRow
	for rows.Next() {
		var r StatRow
		if err := rows.Scan(&r.Date, &r.EventType, &r.EventName,
			&r.TotalCount, &r.MaliciousCount, &r.CleanCount); err != nil {
			return nil, fmt.Errorf("dashboard.scanStats.scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
