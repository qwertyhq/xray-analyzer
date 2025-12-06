package storage

import (
	"context"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// CreateAlert creates a new alert
func (s *Storage) CreateAlert(ctx context.Context, alert *models.Alert) error {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts (type, node_id, user_email, source_ip, destination, count, message, created_at, sent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
	`, alert.Type, alert.NodeID, alert.UserEmail, alert.SourceIP, alert.Destination, alert.Count, alert.Message, now)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	alert.ID = id
	return nil
}

// GetUnsentAlerts gets alerts that haven't been sent yet
func (s *Storage) GetUnsentAlerts(ctx context.Context) ([]*models.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, node_id, user_email, COALESCE(source_ip, '') as source_ip, 
			   COALESCE(destination, '') as destination, count, message, 
			   COALESCE(created_at, '') as created_at
		FROM alerts
		WHERE sent = 0
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var createdAtStr string
		if err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &a.UserEmail, &a.SourceIP, &a.Destination, &a.Count, &a.Message, &createdAtStr); err != nil {
			return nil, err
		}
		a.CreatedAt = parseDateTime(createdAtStr)
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// MarkAlertSent marks an alert as sent
func (s *Storage) MarkAlertSent(ctx context.Context, alertID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET sent = 1 WHERE id = ?`, alertID)
	return err
}
