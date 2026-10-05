// internal/db/queries/network_detection.go
//
// Copyright © 2026 Lakshy Sharma lakshy.d.sharma@gmail.com
// AGPL-3.0 License

package queries

import (
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"vajra/internal/db"
	"vajra/shared/models"
)

type DetectionNetworkQueries struct {
	db *db.DB
}

func NewDetectionNetworkQueries(d *db.DB) *DetectionNetworkQueries {
	return &DetectionNetworkQueries{db: d}
}

// Insert writes socket details for a reverse shell detection.
func (q *DetectionNetworkQueries) Insert(n *models.DetectionNetwork) error {
	sqlStr, args, err := sq.
		Insert("detection_network").
		Columns("detection_id", "remote_addr", "remote_port", "protocol", "socket_inode", "old_fd", "new_fd").
		Values(n.DetectionID, n.RemoteAddr, n.RemotePort, n.Protocol, n.SocketInode, n.OldFd, n.NewFd).
		ToSql()
	if err != nil {
		return fmt.Errorf("detection_network.Insert: build: %w", err)
	}
	_, err = q.db.SQL().Exec(sqlStr, args...)
	return err
}

// GetByDetectionID returns the network detail for a detection.
func (q *DetectionNetworkQueries) GetByDetectionID(detectionID int64) (*models.DetectionNetwork, error) {
	sqlStr, args, err := sq.
		Select("id", "detection_id", "remote_addr", "remote_port", "protocol", "socket_inode", "old_fd", "new_fd").
		From("detection_network").
		Where(sq.Eq{"detection_id": detectionID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("detection_network.GetByDetectionID: build: %w", err)
	}
	row := q.db.SQL().QueryRow(sqlStr, args...)
	var n models.DetectionNetwork
	if err := row.Scan(
		&n.ID, &n.DetectionID, &n.RemoteAddr, &n.RemotePort,
		&n.Protocol, &n.SocketInode, &n.OldFd, &n.NewFd,
	); err != nil {
		return nil, fmt.Errorf("detection_network.GetByDetectionID: scan: %w", err)
	}
	return &n, nil
}
