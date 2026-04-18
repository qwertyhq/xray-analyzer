package storage

import (
	"context"
	"strconv"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// buildDestSearchIDs builds the list of user identifiers to search for in
// user_destinations. Mirrors BuildFullSearchIDs (from users.go, still fenced)
// but uses $N placeholders and the pgx pool for the remna_users lookup.
func (s *Storage) buildDestSearchIDs(ctx context.Context, userEmail string) []string {
	seen := make(map[string]bool)
	var ids []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			ids = append(ids, v)
		}
	}

	add(userEmail)

	// Try to find Remnawave numeric ID via pool ($N placeholders)
	var remnaID int64
	_ = s.pool.QueryRow(ctx,
		`SELECT COALESCE(id, 0) FROM remna_users WHERE username = $1 OR us_id = $1 LIMIT 1`,
		userEmail,
	).Scan(&remnaID)
	if remnaID > 0 {
		add(strconv.FormatInt(remnaID, 10))
	}

	return ids
}

// RecordUserDestination records or updates a user's destination visit.
func (s *Storage) RecordUserDestination(ctx context.Context, userEmail, nodeID, destination string) error {
	now := time.Now().UTC()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_destinations (user_email, node_id, destination, request_count, first_seen, last_seen)
		VALUES ($1, $2, $3, 1, $4, $5)
		ON CONFLICT (user_email, node_id, destination) DO UPDATE SET
			request_count = user_destinations.request_count + 1,
			last_seen = EXCLUDED.last_seen
	`, userEmail, nodeID, destination, now, now)

	return err
}

// GetUserDestinations returns paginated destinations for a user.
// Uses s.pool (native pgx) so []string is passed as a Postgres text[] array.
func (s *Storage) GetUserDestinations(ctx context.Context, userEmail string, since time.Time, page, pageSize int) (*models.UserDestinationsResponse, error) {
	offset := (page - 1) * pageSize
	searchIDs := s.buildDestSearchIDs(ctx, userEmail)

	// Get total count
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_destinations
		WHERE user_email = ANY($1) AND last_seen > $2
	`, searchIDs, since.UTC()).Scan(&total); err != nil {
		return nil, err
	}

	// Get paginated results — pool so []string codec works
	rows, err := s.pool.Query(ctx, `
		SELECT node_id, destination, request_count, first_seen, last_seen
		FROM user_destinations
		WHERE user_email = ANY($1) AND last_seen > $2
		ORDER BY request_count DESC, last_seen DESC
		LIMIT $3 OFFSET $4
	`, searchIDs, since.UTC(), pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var destinations []models.UserDestination
	for rows.Next() {
		var d models.UserDestination
		if err := rows.Scan(&d.NodeID, &d.Destination, &d.RequestCount, &d.FirstSeen, &d.LastSeen); err != nil {
			return nil, err
		}
		destinations = append(destinations, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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

// CleanupUserDestinations removes old destination records.
func (s *Storage) CleanupUserDestinations(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_destinations WHERE last_seen < $1`, cutoff)
	return err
}
