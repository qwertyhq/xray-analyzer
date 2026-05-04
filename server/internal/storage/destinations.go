package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/models"
)

// buildDestSearchUUIDs resolves a user identifier to every plausible
// canonical UUID for user_destinations lookups. Goes through the same
// numeric-id / us_id / username / SHA-1 fallback chain as ResolveUserEmailToUUID
// so a URL like /users/us_5478 also matches data keyed by the real user's UUID.
func (s *Storage) buildDestSearchUUIDs(ctx context.Context, userEmail string) []uuid.UUID {
	seen := make(map[uuid.UUID]bool)
	var uuids []uuid.UUID
	for _, id := range buildUserSearchIDs(userEmail) {
		u, err := s.ResolveUserEmailToUUID(ctx, id)
		if err != nil || seen[u] {
			continue
		}
		seen[u] = true
		uuids = append(uuids, u)
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
	// LEFT JOIN aggregates threat categories and blacklist hits per destination
	// so each row carries its threat-intel labels (ads, tor, malware, ...).
	rows, err := s.pool.Query(ctx, `
		WITH cats AS (
			SELECT user_email, destination, ARRAY_AGG(DISTINCT threat_type) AS types
			FROM threat_matches
			WHERE user_email = ANY($1)
			GROUP BY user_email, destination
		),
		bl AS (
			SELECT user_email, destination, COUNT(*) > 0 AS hit
			FROM blacklist_matches
			WHERE user_email = ANY($1)
			GROUP BY user_email, destination
		)
		SELECT n.node_id, ud.destination, ud.request_count, ud.first_seen, ud.last_seen,
		       COALESCE(cats.types, ARRAY[]::text[]) AS threat_types,
		       COALESCE(bl.hit, false) AS blacklisted
		FROM user_destinations ud
		JOIN nodes n ON n.id = ud.node_id
		LEFT JOIN cats ON cats.user_email = ud.user_email AND cats.destination = ud.destination
		LEFT JOIN bl   ON bl.user_email   = ud.user_email AND bl.destination   = ud.destination
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
		var threatTypes []string
		var blacklisted bool
		if err := rows.Scan(&d.NodeID, &d.Destination, &d.RequestCount, &d.FirstSeen, &d.LastSeen,
			&threatTypes, &blacklisted); err != nil {
			return nil, err
		}
		d.Categories = threatTypes
		if blacklisted {
			d.Categories = append(d.Categories, "blacklist")
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
