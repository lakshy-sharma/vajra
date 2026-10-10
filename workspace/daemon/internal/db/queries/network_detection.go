// internal/db/queries/network_detection.go
//
// Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"
	shareddb "vajra/shared/db"
	"vajra/shared/models"
)

type DetectionNetworkQueries struct {
	db *shareddb.DB
}

func NewDetectionNetworkQueries(d *shareddb.DB) *DetectionNetworkQueries {
	return &DetectionNetworkQueries{db: d}
}

func (q *DetectionNetworkQueries) Insert(e *models.DetectionNetwork) error {
	sqlStr, args, err := sq.
		Insert("detection_network").
		Columns(
			"detection_id", "remote_addr", "remote_port", "protocol",
			"socket_inode", "old_fd", "new_fd",
		).
		Values(
			e.DetectionID, e.RemoteAddr, e.RemotePort, e.Protocol,
			e.SocketInode, e.OldFd, e.NewFd,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("network_detection.Insert: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

func (q *DetectionNetworkQueries) GetByDetectionID(detectionID int64) (*models.DetectionNetwork, error) {
	sqlStr, args, err := sq.
		Select(
			"id", "detection_id", "remote_addr", "remote_port", "protocol",
			"socket_inode", "old_fd", "new_fd",
		).
		From("detection_network").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("network_detection.GetByDetectionID: build: %w", err)
	}

	row := q.db.SQL().QueryRow(sqlStr, args...)
	var e models.DetectionNetwork
	if err := row.Scan(
		&e.ID, &e.DetectionID, &e.RemoteAddr, &e.RemotePort, &e.Protocol,
		&e.SocketInode, &e.OldFd, &e.NewFd,
	); err != nil {
		return nil, fmt.Errorf("network_detection.GetByDetectionID: scan: %w", err)
	}
	return &e, nil
}
