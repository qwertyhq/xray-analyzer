package storage

import (
	"context"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// CreateAlert creates a new alert.
func (s *Storage) CreateAlert(ctx context.Context, alert *models.Alert) error {
	now := time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO alerts (type, node_id, user_email, source_ip, destination, count, message, created_at, sent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0)
		RETURNING id
	`, alert.Type, alert.NodeID, alert.UserEmail, alert.SourceIP, alert.Destination, alert.Count, alert.Message, now).Scan(&alert.ID)
	return err
}

// GetUnsentAlerts gets alerts that haven't been sent yet.
func (s *Storage) GetUnsentAlerts(ctx context.Context) ([]*models.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, node_id, user_email,
		       COALESCE(source_ip, '') AS source_ip,
		       COALESCE(destination, '') AS destination,
		       count, message, created_at
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
		if err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &a.UserEmail, &a.SourceIP, &a.Destination, &a.Count, &a.Message, &a.CreatedAt); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// MarkAlertSent marks an alert as sent.
func (s *Storage) MarkAlertSent(ctx context.Context, alertID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET sent = 1 WHERE id = $1`, alertID)
	return err
}

// GetUserAlerts returns paginated alerts for a specific user.
func (s *Storage) GetUserAlerts(ctx context.Context, userEmail string, page, pageSize int) (*models.PaginatedAlertsResponse, error) {
	offset := (page - 1) * pageSize

	// Get total count
	var total int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alerts WHERE user_email = $1
	`, userEmail).Scan(&total); err != nil {
		return nil, err
	}

	// Get paginated results
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, node_id, user_email,
		       COALESCE(source_ip, '') AS source_ip,
		       COALESCE(destination, '') AS destination,
		       count, message, created_at, sent
		FROM alerts
		WHERE user_email = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, userEmail, pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		var sent int
		if err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &a.UserEmail, &a.SourceIP, &a.Destination, &a.Count, &a.Message, &a.CreatedAt, &sent); err != nil {
			return nil, err
		}
		a.Sent = sent == 1
		alerts = append(alerts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	return &models.PaginatedAlertsResponse{
		Alerts:     alerts,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}
