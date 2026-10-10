// ui/internal/queries/autoruns.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import "fmt"

type AutorunRow struct {
	ID        int64  `json:"id"`
	Category  string `json:"category"`
	Location  string `json:"location"`
	ImagePath string `json:"imagePath"`
	ImageName string `json:"imageName"`
	Arguments string `json:"arguments"`
	SHA256    string `json:"sha256"`
	IsActive  bool   `json:"isActive"`
	FirstSeen int64  `json:"firstSeen"`
	LastSeen  int64  `json:"lastSeen"`
}

// Autoruns returns all autorun entries ordered by category then image name.
func (q *Queries) Autoruns() ([]AutorunRow, error) {
	rows, err := q.db.SQL().Query(`
		SELECT id, category, location, image_path, image_name,
		       arguments, sha256, is_active, first_seen, last_seen
		FROM autorun_entries
		ORDER BY category ASC, image_name ASC`)
	if err != nil {
		return nil, fmt.Errorf("autoruns.query: %w", err)
	}
	defer rows.Close()

	var out []AutorunRow
	for rows.Next() {
		var r AutorunRow
		if err := rows.Scan(
			&r.ID, &r.Category, &r.Location, &r.ImagePath, &r.ImageName,
			&r.Arguments, &r.SHA256, &r.IsActive, &r.FirstSeen, &r.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("autoruns.scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
