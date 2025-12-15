package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// RecordUserDestination records or updates a user's destination visit
func (s *Storage) RecordUserDestination(ctx context.Context, userEmail, nodeID, destination string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_destinations (user_email, node_id, destination, request_count, first_seen, last_seen)
		VALUES (?, ?, ?, 1, ?, ?)
		ON CONFLICT(user_email, node_id, destination) DO UPDATE SET
			request_count = request_count + 1,
			last_seen = ?
	`, userEmail, nodeID, destination, now, now, now)

	return err
}

// extractNumericPartDest extracts numeric suffix from a string like "prefix_123"
func extractNumericPartDest(s string) string {
	if idx := strings.LastIndex(s, "_"); idx != -1 && idx < len(s)-1 {
		part := s[idx+1:]
		if _, err := strconv.Atoi(part); err == nil {
			return part
		}
	}
	if _, err := strconv.Atoi(s); err == nil {
		return s
	}
	return ""
}

// buildDestinationSearchIDs creates a list of possible user identifiers
func buildDestinationSearchIDs(userEmail string) (string, []interface{}) {
	seen := make(map[string]bool)
	var searchIDs []string

	addID := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			searchIDs = append(searchIDs, id)
		}
	}

	addID(userEmail)

	numericPart := extractNumericPartDest(userEmail)
	if numericPart != "" {
		addID(numericPart)
		addID("us_" + numericPart)
		addID("remnawave_" + numericPart)
	}

	placeholders := make([]string, len(searchIDs))
	args := make([]interface{}, len(searchIDs))
	for i, id := range searchIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	return strings.Join(placeholders, ","), args
}

// GetUserDestinations returns paginated destinations for a user
func (s *Storage) GetUserDestinations(ctx context.Context, userEmail string, since time.Time, page, pageSize int) (*models.UserDestinationsResponse, error) {
	sinceStr := since.UTC().Format(time.RFC3339)
	offset := (page - 1) * pageSize

	placeholders, searchArgs := buildDestinationSearchIDs(userEmail)

	// Get total count
	var total int
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM user_destinations
		WHERE user_email IN (%s) AND last_seen > ?
	`, placeholders)
	countArgs := append(searchArgs, sinceStr)
	err := s.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, err
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT node_id, destination, request_count, 
			   COALESCE(first_seen, '') as first_seen,
			   COALESCE(last_seen, '') as last_seen
		FROM user_destinations
		WHERE user_email IN (%s) AND last_seen > ?
		ORDER BY request_count DESC, last_seen DESC
		LIMIT ? OFFSET ?
	`, placeholders)
	queryArgs := append(searchArgs, sinceStr, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var destinations []models.UserDestination
	for rows.Next() {
		var d models.UserDestination
		var firstSeenStr, lastSeenStr string
		if err := rows.Scan(&d.NodeID, &d.Destination, &d.RequestCount, &firstSeenStr, &lastSeenStr); err != nil {
			return nil, err
		}
		d.FirstSeen = parseDateTime(firstSeenStr)
		d.LastSeen = parseDateTime(lastSeenStr)
		destinations = append(destinations, d)
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	return &models.UserDestinationsResponse{
		Destinations: destinations,
		Total:        total,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
	}, nil
}

// CleanupUserDestinations removes old destination records
func (s *Storage) CleanupUserDestinations(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_destinations WHERE last_seen < ?`, cutoff)
	return err
}
