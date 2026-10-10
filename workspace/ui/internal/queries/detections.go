// ui/internal/queries/detections.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"
	"strings"
)

type DetectionRow struct {
	ID             int64  `json:"id"`
	DetectionTime  int64  `json:"detectionTime"`
	Source         string `json:"source"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	ProcessName    string `json:"processName"`
	ExePath        string `json:"exePath"`
	CmdLine        string `json:"cmdLine"`
	TargetPath     string `json:"targetPath"`
	RuleID         string `json:"ruleId"`
	MITRETechnique string `json:"mitreTechnique"`
	DedupCount     uint64 `json:"dedupCount"`
	Notes          string `json:"notes"`
}

// Detections returns a paginated list of detections with optional filters.
// severity, status, source may each be "" to skip that filter.
func (q *Queries) Detections(page, perPage int, severity, status, source string) ([]DetectionRow, int64, error) {
	where, args := buildDetectionFilter(severity, status, source)
	offset := (page - 1) * perPage

	// Count
	countSQL := "SELECT COUNT(*) FROM detections" + where
	var total int64
	if err := q.db.SQL().QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("detections.count: %w", err)
	}

	// Rows
	rowSQL := fmt.Sprintf(`
		SELECT id, detection_time, source, severity, status,
		       process_name, exe_path, cmd_line, target_path,
		       rule_id, mitre_technique, dedup_count, notes
		FROM detections%s
		ORDER BY detection_time DESC
		LIMIT ? OFFSET ?`, where)
	queryArgs := append(args, perPage, offset)

	rows, err := q.db.SQL().Query(rowSQL, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("detections.query: %w", err)
	}
	defer rows.Close()

	var out []DetectionRow
	for rows.Next() {
		var r DetectionRow
		if err := rows.Scan(
			&r.ID, &r.DetectionTime, &r.Source, &r.Severity, &r.Status,
			&r.ProcessName, &r.ExePath, &r.CmdLine, &r.TargetPath,
			&r.RuleID, &r.MITRETechnique, &r.DedupCount, &r.Notes,
		); err != nil {
			return nil, 0, fmt.Errorf("detections.scan: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func buildDetectionFilter(severity, status, source string) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, severity)
	}
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	if source != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, source)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
