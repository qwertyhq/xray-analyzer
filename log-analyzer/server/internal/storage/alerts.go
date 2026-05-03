package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/models"
)

// CreateAlert creates a new alert.
// alert.NodeID is a text node name; it is resolved to the nodes(id) smallint
// FK via LookupNodeID. alert.UserEmail may be any string; non-UUID values are
// resolved via ResolveUserEmailToUUID (remna_users lookup, then SHA-1 fallback).
// alert.SourceIP is passed as text; Postgres casts it to inet.
func (s *Storage) CreateAlert(ctx context.Context, alert *models.Alert) error {
	now := time.Now().UTC()

	nodeID, err := s.LookupNodeID(ctx, alert.NodeID, "exit")
	if err != nil {
		return err
	}

	userUUID, err := s.ResolveUserEmailToUUID(ctx, alert.UserEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	// source_ip and destination are nullable; pass nil when empty.
	var sourceIP interface{}
	if alert.SourceIP != "" {
		sourceIP = alert.SourceIP
	}
	var destination interface{}
	if alert.Destination != "" {
		destination = alert.Destination
	}

	err = s.pool.QueryRow(ctx, `
		INSERT INTO alerts (type, node_id, user_email, source_ip, destination, count, message, created_at, sent, ts)
		VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, 0, $9)
		RETURNING id
	`, alert.Type, int16(nodeID), userUUID, sourceIP, destination, alert.Count, alert.Message, now, now).Scan(&alert.ID)
	return err
}

// GetUnsentAlerts gets alerts that haven't been sent yet.
func (s *Storage) GetUnsentAlerts(ctx context.Context) ([]*models.Alert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.type, n.node_id, a.user_email,
		       COALESCE(a.source_ip::text, '') AS source_ip,
		       COALESCE(a.destination, '') AS destination,
		       a.count, a.message, a.created_at
		FROM alerts a
		JOIN nodes n ON n.id = a.node_id
		WHERE a.sent = 0
		ORDER BY a.created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var userUUID uuid.UUID
		if err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &userUUID, &a.SourceIP, &a.Destination, &a.Count, &a.Message, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.UserEmail = userUUID.String()
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// MarkAlertSent marks an alert as sent.
func (s *Storage) MarkAlertSent(ctx context.Context, alertID int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE alerts SET sent = 1 WHERE id = $1`, alertID)
	return err
}

// GetUserAlerts returns paginated alerts for a specific user.
func (s *Storage) GetUserAlerts(ctx context.Context, userEmail string, page, pageSize int) (*models.PaginatedAlertsResponse, error) {
	offset := (page - 1) * pageSize

	userUUID, err := uuid.Parse(userEmail)
	if err != nil {
		// Non-UUID user email: return empty result (no rows will match uuid column).
		return &models.PaginatedAlertsResponse{
			Alerts:     []models.Alert{},
			Total:      0,
			Page:       page,
			PageSize:   pageSize,
			TotalPages: 1,
		}, nil
	}

	// Get total count
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts WHERE user_email = $1
	`, userUUID).Scan(&total); err != nil {
		return nil, err
	}

	// Get paginated results
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.type, n.node_id, a.user_email,
		       COALESCE(a.source_ip::text, '') AS source_ip,
		       COALESCE(a.destination, '') AS destination,
		       a.count, a.message, a.created_at, a.sent
		FROM alerts a
		JOIN nodes n ON n.id = a.node_id
		WHERE a.user_email = $1
		ORDER BY a.created_at DESC
		LIMIT $2 OFFSET $3
	`, userUUID, pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		var sent int
		var alertUUID uuid.UUID
		if err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &alertUUID, &a.SourceIP, &a.Destination, &a.Count, &a.Message, &a.CreatedAt, &sent); err != nil {
			return nil, err
		}
		a.UserEmail = alertUUID.String()
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
