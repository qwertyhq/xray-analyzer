package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/models"
)

// buildDestSearchUUIDs resolves a user identifier (UUID string, username, or us_id)
// to a list of uuid.UUID values for use in user_destinations queries.
func (s *Storage) buildDestSearchUUIDs(ctx context.Context, userEmail string) []uuid.UUID {
	var uuids []uuid.UUID
	seen := make(map[uuid.UUID]bool)
	add := func(u uuid.UUID) {
		if !seen[u] {
			seen[u] = true
			uuids = append(uuids, u)
		}
	}

	// Direct UUID parse.
	if u, err := uuid.Parse(userEmail); err == nil {
		add(u)
	}

	// Look up remna_users by username or us_id to get their UUID.
	var remnaUUID string
	_ = s.pool.QueryRow(ctx,
		`SELECT COALESCE(uuid::text, '') FROM remna_users WHERE username = $1 OR us_id = $1 LIMIT 1`,
		userEmail,
	).Scan(&remnaUUID)
	if remnaUUID != "" {
		if u, err := uuid.Parse(remnaUUID); err == nil {
			add(u)
		}
	}

	return uuids
}


// RecordUserDestination records or updates a user's destination visit.
// userEmail must be a valid UUID string (Remnawave user UUID).
// nodeID is a text node name resolved to the nodes(id) smallint FK.
func (s *Storage) RecordUserDestination(ctx context.Context, userEmail, nodeID, destination string) error {
	now := time.Now().UTC()

	// Resolve text node name to smallint FK.
	nid, err := s.LookupNodeID(ctx, nodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve node_id %q: %w", nodeID, err)
	}

	// user_email is uuid NOT NULL.
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_destinations (user_email, node_id, destination, request_count, first_seen, last_seen)
		VALUES ($1, $2, $3, 1, $4, $5)
		ON CONFLICT (user_email, node_id, destination) DO UPDATE SET
			request_count = user_destinations.request_count + 1,
			last_seen = EXCLUDED.last_seen
	`, userUUID, int16(nid), destination, now, now)

	return err
}

// GetUserDestinations returns paginated destinations for a user.
// userEmail is resolved to uuid(s) via buildDestSearchUUIDs before querying.
// node_id (smallint FK) is resolved back to text via JOIN on nodes.
func (s *Storage) GetUserDestinations(ctx context.Context, userEmail string, since time.Time, page, pageSize int) (*models.UserDestinationsResponse, error) {
	offset := (page - 1) * pageSize
	searchUUIDs := s.buildDestSearchUUIDs(ctx, userEmail)
	if len(searchUUIDs) == 0 {
		// Unknown user — return empty response without error.
		return &models.UserDestinationsResponse{
			Destinations: []models.UserDestination{},
			Total:        0,
			Page:         page,
			PageSize:     pageSize,
			TotalPages:   1,
		}, nil
	}

	// Get total count.
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_destinations
		WHERE user_email = ANY($1) AND last_seen > $2
	`, searchUUIDs, since.UTC()).Scan(&total); err != nil {
		return nil, err
	}

	// Get paginated results; JOIN nodes to restore text node name.
	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, ud.destination, ud.request_count, ud.first_seen, ud.last_seen
		FROM user_destinations ud
		JOIN nodes n ON n.id = ud.node_id
		WHERE ud.user_email = ANY($1) AND ud.last_seen > $2
		ORDER BY ud.request_count DESC, ud.last_seen DESC
		LIMIT $3 OFFSET $4
	`, searchUUIDs, since.UTC(), pageSize, offset)
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
	_, err := s.pool.Exec(ctx, `DELETE FROM user_destinations WHERE last_seen < $1`, cutoff)
	return err
}
