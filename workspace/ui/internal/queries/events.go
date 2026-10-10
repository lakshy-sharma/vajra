// ui/internal/queries/events.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import "fmt"

// ── Security events ───────────────────────────────────────────────────────────

type SecurityEventRow struct {
	ID          int64  `json:"id"`
	EventTime   int64  `json:"eventTime"`
	EventType   uint32 `json:"eventType"`
	EventName   string `json:"eventName"`
	PID         uint32 `json:"pid"`
	UID         uint32 `json:"uid"`
	ProcessName string `json:"processName"`
	TargetPath  string `json:"targetPath"`
	Details     string `json:"details"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
}

func (q *Queries) SecurityEvents(page, perPage int) ([]SecurityEventRow, int64, error) {
	var total int64
	if err := q.db.SQL().QueryRow("SELECT COUNT(*) FROM security_events").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("security_events.count: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := q.db.SQL().Query(`
		SELECT id, event_time, event_type, event_name, pid, uid,
		       process_name, target_path, details, severity, status
		FROM security_events
		ORDER BY event_time DESC
		LIMIT ? OFFSET ?`, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("security_events.query: %w", err)
	}
	defer rows.Close()

	var out []SecurityEventRow
	for rows.Next() {
		var r SecurityEventRow
		if err := rows.Scan(
			&r.ID, &r.EventTime, &r.EventType, &r.EventName,
			&r.PID, &r.UID, &r.ProcessName, &r.TargetPath,
			&r.Details, &r.Severity, &r.Status,
		); err != nil {
			return nil, 0, fmt.Errorf("security_events.scan: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ── Network events ────────────────────────────────────────────────────────────

type NetworkEventRow struct {
	ID          int64  `json:"id"`
	EventTime   int64  `json:"eventTime"`
	EventType   uint32 `json:"eventType"`
	PID         uint32 `json:"pid"`
	UID         uint32 `json:"uid"`
	ProcessName string `json:"processName"`
	SrcAddr     string `json:"srcAddr"`
	DstAddr     string `json:"dstAddr"`
	SrcPort     uint16 `json:"srcPort"`
	DstPort     uint16 `json:"dstPort"`
	Protocol    string `json:"protocol"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
}

func (q *Queries) NetworkEvents(page, perPage int) ([]NetworkEventRow, int64, error) {
	var total int64
	if err := q.db.SQL().QueryRow("SELECT COUNT(*) FROM network_events").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("network_events.count: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := q.db.SQL().Query(`
		SELECT id, event_time, event_type, pid, uid,
		       process_name, src_addr, dst_addr, src_port, dst_port,
		       protocol, severity, status
		FROM network_events
		ORDER BY event_time DESC
		LIMIT ? OFFSET ?`, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("network_events.query: %w", err)
	}
	defer rows.Close()

	var out []NetworkEventRow
	for rows.Next() {
		var r NetworkEventRow
		if err := rows.Scan(
			&r.ID, &r.EventTime, &r.EventType, &r.PID, &r.UID,
			&r.ProcessName, &r.SrcAddr, &r.DstAddr, &r.SrcPort, &r.DstPort,
			&r.Protocol, &r.Severity, &r.Status,
		); err != nil {
			return nil, 0, fmt.Errorf("network_events.scan: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ── Memory events ─────────────────────────────────────────────────────────────

type MemoryEventRow struct {
	ID          int64  `json:"id"`
	EventTime   int64  `json:"eventTime"`
	EventType   uint32 `json:"eventType"`
	PID         uint32 `json:"pid"`
	UID         uint32 `json:"uid"`
	ProcessName string `json:"processName"`
	Address     uint64 `json:"address"`
	Length      uint64 `json:"length"`
	Protection  uint32 `json:"protection"`
	FilePath    string `json:"filePath"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
}

func (q *Queries) MemoryEvents(page, perPage int) ([]MemoryEventRow, int64, error) {
	var total int64
	if err := q.db.SQL().QueryRow("SELECT COUNT(*) FROM memory_events").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("memory_events.count: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := q.db.SQL().Query(`
		SELECT id, event_time, event_type, pid, uid,
		       process_name, address, length, protection, file_path,
		       severity, status
		FROM memory_events
		ORDER BY event_time DESC
		LIMIT ? OFFSET ?`, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("memory_events.query: %w", err)
	}
	defer rows.Close()

	var out []MemoryEventRow
	for rows.Next() {
		var r MemoryEventRow
		if err := rows.Scan(
			&r.ID, &r.EventTime, &r.EventType, &r.PID, &r.UID,
			&r.ProcessName, &r.Address, &r.Length, &r.Protection,
			&r.FilePath, &r.Severity, &r.Status,
		); err != nil {
			return nil, 0, fmt.Errorf("memory_events.scan: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
