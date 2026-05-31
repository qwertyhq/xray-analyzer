package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// MaxThreatMatchesPerUserCategory is the cap on recent threat_matches kept
// for each (user, category) combination. Aggregated counters (threat_type_stats,
// threat_hourly_stats, user_threat_stats) keep full history — this limit only
// bounds the `threat_matches` table used for recent-matches UI.
//
// Partitioning by (user, category) instead of just category prevents active
// categories (social, ads) across all users from evicting a specific user's
// older matches in quieter categories they care about.
const MaxThreatMatchesPerUserCategory = 100

// MaxThreatMatches is the total maximum for display queries (legacy, used in GetThreatMatches)
const MaxThreatMatches = 500

// SaveThreatMatch saves a threat match to the database, updates statistics, and cleans up old records.
// match.UserEmail may be any string; non-UUID values are resolved via
// ResolveUserEmailToUUID (remna_users lookup, then SHA-1 fallback).
// match.NodeID is a text node name; resolved to nodes(id) smallint FK via LookupNodeID.
// match.SourceIP is passed as text; Postgres casts to inet.
func (s *Storage) SaveThreatMatch(ctx context.Context, match *threatintel.ThreatMatch) error {
	now := time.Now()

	userUUID, err := s.ResolveUserEmailToUUID(ctx, match.UserEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	nodeID, err := s.LookupNodeID(ctx, match.NodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve node_id: %w", err)
	}

	// Insert into recent matches table
	_, err = s.pool.Exec(ctx, `
		INSERT INTO threat_matches (
			user_email, node_id, source_ip, destination,
			threat_type, source, confidence, description, matched_at, ts
		) VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10)
	`, userUUID, int16(nodeID), match.SourceIP, match.Destination,
		string(match.ThreatType), string(match.Source), match.Confidence,
		match.Description, now, now)

	if err != nil {
		return err
	}

	// Update aggregated total counter
	s.pool.Exec(ctx, `
		UPDATE threat_stats_agg SET total_matches = total_matches + 1, last_updated = $1 WHERE id = 1
	`, now)

	// Update threat type counter
	s.pool.Exec(ctx, `
		INSERT INTO threat_type_stats (threat_type, match_count, last_match)
		VALUES ($1, 1, $2)
		ON CONFLICT (threat_type) DO UPDATE SET
			match_count = threat_type_stats.match_count + 1,
			last_match = EXCLUDED.last_match
	`, string(match.ThreatType), now)

	// Update user threat stats
	s.pool.Exec(ctx, `
		INSERT INTO user_threat_stats (user_email, threat_type, match_count, last_match)
		VALUES ($1, $2, 1, $3)
		ON CONFLICT (user_email, threat_type) DO UPDATE SET
			match_count = user_threat_stats.match_count + 1,
			last_match = EXCLUDED.last_match
	`, userUUID, string(match.ThreatType), now)

	// Update user domain stats (extract domain from destination)
	domain := extractDomain(match.Destination)
	if domain != "" {
		s.pool.Exec(ctx, `
			INSERT INTO user_threat_domains (user_email, threat_type, domain, hit_count, last_seen)
			VALUES ($1, $2, $3, 1, $4)
			ON CONFLICT (user_email, threat_type, domain) DO UPDATE SET
				hit_count = user_threat_domains.hit_count + 1,
				last_seen = EXCLUDED.last_seen
		`, userUUID, string(match.ThreatType), domain, now)
	}

	// Update hourly stats with proper unique user tracking
	hourKey := now.Format("2006-01-02T15")
	dayKey := now.Format("2006-01-02")

	// Track unique users per hour/threat_type using a separate table
	s.pool.Exec(ctx, `
		INSERT INTO threat_hourly_users (hour, threat_type, user_email)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`, hourKey, string(match.ThreatType), userUUID)

	// Update hourly stats - recalculate unique_users from actual data
	s.pool.Exec(ctx, `
		INSERT INTO threat_hourly_stats (hour, threat_type, match_count, unique_users)
		VALUES ($1, $2, 1, 1)
		ON CONFLICT (hour, threat_type) DO UPDATE SET
			match_count = threat_hourly_stats.match_count + 1,
			unique_users = (SELECT COUNT(*) FROM threat_hourly_users WHERE hour = $3 AND threat_type = $4)
	`, hourKey, string(match.ThreatType), hourKey, string(match.ThreatType))

	// Track unique users per day/threat_type
	s.pool.Exec(ctx, `
		INSERT INTO threat_daily_users (day, threat_type, user_email)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`, dayKey, string(match.ThreatType), userUUID)

	// Update daily stats - recalculate unique_users from actual data
	s.pool.Exec(ctx, `
		INSERT INTO threat_daily_stats (day, threat_type, match_count, unique_users)
		VALUES ($1, $2, 1, 1)
		ON CONFLICT (day, threat_type) DO UPDATE SET
			match_count = threat_daily_stats.match_count + 1,
			unique_users = (SELECT COUNT(*) FROM threat_daily_users WHERE day = $3 AND threat_type = $4)
	`, dayKey, string(match.ThreatType), dayKey, string(match.ThreatType))

	// Trim recent records: keep only the most recent MaxThreatMatchesPerUserCategory
	// in the partition we just inserted into. Scoped to one (user_email, threat_type)
	// pair so the DELETE is bounded — it walks idx_threat_user_type_time and deletes
	// at most one row per save instead of scanning the whole table.
	_, err = s.pool.Exec(ctx, `
		DELETE FROM threat_matches
		WHERE user_email = $1 AND threat_type = $2
		  AND id NOT IN (
			SELECT id FROM threat_matches
			WHERE user_email = $1 AND threat_type = $2
			ORDER BY matched_at DESC
			LIMIT $3
		)
	`, userUUID, string(match.ThreatType), MaxThreatMatchesPerUserCategory)

	return err
}

// SaveThreatMatchesBatch persists many threat matches with aggregated counter
// writes, sent as a single pipelined pgx.Batch. The per-match SaveThreatMatch
// ran ~10 statements each — including two `unique_users = (SELECT COUNT(*) …)`
// recomputes and a DELETE-trim — which pegged postgres CPU under load. Here the
// counters are summed in Go and written once per distinct key, the unique-user
// recompute runs once per (period, threat_type) instead of once per match, and
// the trim runs once per (user, threat_type). Behaviour-equivalent, far fewer
// statements, one round trip.
func (s *Storage) SaveThreatMatchesBatch(ctx context.Context, matches []*threatintel.ThreatMatch) error {
	if len(matches) == 0 {
		return nil
	}
	now := time.Now()
	hourKey := now.Format("2006-01-02T15")
	dayKey := now.Format("2006-01-02")

	type utKey struct {
		u uuid.UUID
		t string
	}
	type udKey struct {
		u uuid.UUID
		t string
		d string
	}
	type resolvedRow struct {
		userUUID uuid.UUID
		nodeID   int16
		m        *threatintel.ThreatMatch
	}

	resolved := make([]resolvedRow, 0, len(matches))
	typeCount := map[string]int{}
	userType := map[utKey]int{}
	userDomain := map[udKey]int{}
	hourUsers := map[utKey]struct{}{}
	dayUsers := map[utKey]struct{}{}

	for _, m := range matches {
		if m == nil {
			continue
		}
		uu, err := s.ResolveUserEmailToUUID(ctx, m.UserEmail)
		if err != nil {
			continue
		}
		nid, err := s.LookupNodeID(ctx, m.NodeID, "exit")
		if err != nil {
			continue
		}
		tt := string(m.ThreatType)
		resolved = append(resolved, resolvedRow{uu, int16(nid), m})
		typeCount[tt]++
		userType[utKey{uu, tt}]++
		if d := extractDomain(m.Destination); d != "" {
			userDomain[udKey{uu, tt, d}]++
		}
		hourUsers[utKey{uu, tt}] = struct{}{}
		dayUsers[utKey{uu, tt}] = struct{}{}
	}
	if len(resolved) == 0 {
		return nil
	}

	batch := &pgx.Batch{}

	// 1. Recent-matches rows (one per match — inherent).
	for _, r := range resolved {
		batch.Queue(`
			INSERT INTO threat_matches (
				user_email, node_id, source_ip, destination,
				threat_type, source, confidence, description, matched_at, ts
			) VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10)`,
			r.userUUID, r.nodeID, r.m.SourceIP, r.m.Destination,
			string(r.m.ThreatType), string(r.m.Source), r.m.Confidence,
			r.m.Description, now, now)
	}

	// 2. Global total (one update for the whole batch).
	batch.Queue(`UPDATE threat_stats_agg SET total_matches = total_matches + $1, last_updated = $2 WHERE id = 1`,
		len(resolved), now)

	// 3. Per-type counter (summed).
	for tt, c := range typeCount {
		batch.Queue(`
			INSERT INTO threat_type_stats (threat_type, match_count, last_match)
			VALUES ($1,$2,$3)
			ON CONFLICT (threat_type) DO UPDATE SET
				match_count = threat_type_stats.match_count + EXCLUDED.match_count,
				last_match = EXCLUDED.last_match`, tt, c, now)
	}

	// 4. Per-(user,type) counter (summed).
	for k, c := range userType {
		batch.Queue(`
			INSERT INTO user_threat_stats (user_email, threat_type, match_count, last_match)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (user_email, threat_type) DO UPDATE SET
				match_count = user_threat_stats.match_count + EXCLUDED.match_count,
				last_match = EXCLUDED.last_match`, k.u, k.t, c, now)
	}

	// 5. Per-(user,type,domain) counter (summed).
	for k, c := range userDomain {
		batch.Queue(`
			INSERT INTO user_threat_domains (user_email, threat_type, domain, hit_count, last_seen)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (user_email, threat_type, domain) DO UPDATE SET
				hit_count = user_threat_domains.hit_count + EXCLUDED.hit_count,
				last_seen = EXCLUDED.last_seen`, k.u, k.t, k.d, c, now)
	}

	// 6. Unique-user membership (dedup per batch) — must precede the stats
	//    recompute below so the COUNT(*) sees this batch's users.
	for k := range hourUsers {
		batch.Queue(`INSERT INTO threat_hourly_users (hour, threat_type, user_email)
			VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, hourKey, k.t, k.u)
	}
	for k := range dayUsers {
		batch.Queue(`INSERT INTO threat_daily_users (day, threat_type, user_email)
			VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, dayKey, k.t, k.u)
	}

	// 7. Hourly/daily stats — one upsert per type, unique_users recomputed once.
	for tt, c := range typeCount {
		batch.Queue(`
			INSERT INTO threat_hourly_stats (hour, threat_type, match_count, unique_users)
			VALUES ($1,$2,$3,(SELECT COUNT(*) FROM threat_hourly_users WHERE hour=$1 AND threat_type=$2))
			ON CONFLICT (hour, threat_type) DO UPDATE SET
				match_count = threat_hourly_stats.match_count + EXCLUDED.match_count,
				unique_users = (SELECT COUNT(*) FROM threat_hourly_users WHERE hour=$1 AND threat_type=$2)`,
			hourKey, tt, c)
		batch.Queue(`
			INSERT INTO threat_daily_stats (day, threat_type, match_count, unique_users)
			VALUES ($1,$2,$3,(SELECT COUNT(*) FROM threat_daily_users WHERE day=$1 AND threat_type=$2))
			ON CONFLICT (day, threat_type) DO UPDATE SET
				match_count = threat_daily_stats.match_count + EXCLUDED.match_count,
				unique_users = (SELECT COUNT(*) FROM threat_daily_users WHERE day=$1 AND threat_type=$2)`,
			dayKey, tt, c)
	}

	// 8. Trim recent matches once per (user,type).
	for k := range userType {
		batch.Queue(`
			DELETE FROM threat_matches
			WHERE user_email = $1 AND threat_type = $2
			  AND id NOT IN (
				SELECT id FROM threat_matches
				WHERE user_email = $1 AND threat_type = $2
				ORDER BY matched_at DESC LIMIT $3)`,
			k.u, k.t, MaxThreatMatchesPerUserCategory)
	}

	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	var firstErr error
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// extractDomain extracts domain from destination (removes port)
func extractDomain(destination string) string {
	if idx := strings.LastIndex(destination, ":"); idx > 0 {
		if strings.Count(destination, ":") > 1 && !strings.HasPrefix(destination, "[") {
			return destination // IPv6 without brackets
		}
		return destination[:idx]
	}
	return destination
}

// GetThreatMatches returns all threat matches (limited by MaxThreatMatches)
func (s *Storage) GetThreatMatches(ctx context.Context, limit int) ([]*threatintel.ThreatMatch, error) {
	if limit <= 0 || limit > MaxThreatMatches {
		limit = MaxThreatMatches
	}

	rows, err := s.pool.Query(ctx, `
		SELECT tm.id, tm.user_email::text, n.node_id, tm.source_ip::text, tm.destination,
			   tm.threat_type, tm.source, tm.confidence, tm.description, tm.matched_at,
			   COALESCE(r.username, '') as display_name
		FROM threat_matches tm
		JOIN nodes n ON n.id = tm.node_id
		LEFT JOIN remna_users r ON r.uuid = tm.user_email
		ORDER BY tm.matched_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanThreatMatchesWithDisplayName(rows)
}

// GetThreatMatchesByUser returns threat matches for a specific user
func (s *Storage) GetThreatMatchesByUser(ctx context.Context, userEmail string, limit int) ([]*threatintel.ThreatMatch, error) {
	userUUID, err := uuid.Parse(userEmail)
	if err != nil {
		return nil, nil // non-UUID user, no results
	}

	rows, err := s.pool.Query(ctx, `
		SELECT tm.id, tm.user_email::text, n.node_id, tm.source_ip::text, tm.destination,
			   tm.threat_type, tm.source, tm.confidence, tm.description, tm.matched_at,
			   COALESCE(r.username, '') as display_name
		FROM threat_matches tm
		JOIN nodes n ON n.id = tm.node_id
		LEFT JOIN remna_users r ON r.uuid = tm.user_email
		WHERE tm.user_email = $1
		ORDER BY tm.matched_at DESC
		LIMIT $2
	`, userUUID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanThreatMatchesWithDisplayName(rows)
}

// GetThreatMatchesByType returns threat matches for a specific threat type
func (s *Storage) GetThreatMatchesByType(ctx context.Context, threatType string, limit int) ([]*threatintel.ThreatMatch, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	// First try to get from recent matches table
	rows, err := s.pool.Query(ctx, `
		SELECT tm.id, tm.user_email::text, n.node_id, tm.source_ip::text, tm.destination,
			   tm.threat_type, tm.source, tm.confidence, tm.description, tm.matched_at,
			   COALESCE(r.username, '') as display_name
		FROM threat_matches tm
		JOIN nodes n ON n.id = tm.node_id
		LEFT JOIN remna_users r ON r.uuid = tm.user_email
		WHERE tm.threat_type = $1
		ORDER BY tm.matched_at DESC
		LIMIT $2
	`, threatType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	matches, err := scanThreatMatchesWithDisplayName(rows)
	if err != nil {
		return nil, err
	}

	// If we have matches from recent table, return them
	if len(matches) > 0 {
		return matches, nil
	}

	// Fallback: construct matches from aggregated user_threat_domains table
	// This preserves historical data even after cleanup
	domainRows, err := s.pool.Query(ctx, `
		SELECT d.user_email::text, d.domain, d.hit_count, d.last_seen
		FROM user_threat_domains d
		WHERE d.threat_type = $1
		ORDER BY d.last_seen DESC
		LIMIT $2
	`, threatType, limit)
	if err != nil {
		return nil, err
	}
	defer domainRows.Close()

	for domainRows.Next() {
		var m threatintel.ThreatMatch
		var lastSeen time.Time
		var hitCount int

		if err := domainRows.Scan(&m.UserEmail, &m.Destination, &hitCount, &lastSeen); err != nil {
			continue
		}

		m.ThreatType = threatintel.ThreatType(threatType)
		m.Source = threatintel.ThreatSource("historical")
		m.Confidence = 85
		m.Description = fmt.Sprintf("Historical: %d hits", hitCount)
		m.MatchedAt = lastSeen

		matches = append(matches, &m)
	}

	return matches, nil
}

// GetUserThreatMatchesPaginated returns paginated threat_matches rows for a
// single user filtered by threat_type, optionally by time window. Resolves
// the user identifier through the same UUID chain as the destinations /
// blacklist endpoints so URLs like /users/us_<id> work.
func (s *Storage) GetUserThreatMatchesPaginated(
	ctx context.Context,
	userEmail, threatType string,
	since time.Time,
	page, pageSize int,
) (*models.PaginatedUserThreatsResponse, error) {
	offset := (page - 1) * pageSize
	searchUUIDs := s.buildBlacklistSearchUUIDs(ctx, userEmail)
	if len(searchUUIDs) == 0 {
		return &models.PaginatedUserThreatsResponse{
			Matches:    []models.UserThreatInfo{},
			Total:      0,
			Page:       page,
			PageSize:   pageSize,
			TotalPages: 1,
		}, nil
	}

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM threat_matches
		WHERE user_email = ANY($1) AND threat_type = $2 AND matched_at > $3
	`, searchUUIDs, threatType, since.UTC()).Scan(&total); err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, tm.destination, tm.threat_type, tm.source,
		       tm.confidence,
		       COALESCE(tm.description, '') AS description,
		       COALESCE(host(tm.source_ip), '') AS source_ip,
		       tm.matched_at
		FROM threat_matches tm
		JOIN nodes n ON n.id = tm.node_id
		WHERE tm.user_email = ANY($1) AND tm.threat_type = $2 AND tm.matched_at > $3
		ORDER BY tm.matched_at DESC
		LIMIT $4 OFFSET $5
	`, searchUUIDs, threatType, since.UTC(), pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	matches := []models.UserThreatInfo{}
	for rows.Next() {
		var m models.UserThreatInfo
		if err := rows.Scan(&m.NodeID, &m.Destination, &m.ThreatType, &m.Source,
			&m.Confidence, &m.Description, &m.SourceIP, &m.MatchedAt); err != nil {
			return nil, err
		}
		matches = append(matches, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return &models.PaginatedUserThreatsResponse{
		Matches:    matches,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// CleanupOldThreatMatches removes threat matches older than the retention period
func (s *Storage) CleanupOldThreatMatches(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)

	result, err := s.pool.Exec(ctx, `
		DELETE FROM threat_matches WHERE matched_at < $1
	`, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}

// scanThreatMatchesWithDisplayName is a helper to scan threat match rows with display_name
// Accepts pgx rows (implements sqlRows interface via duck typing).
func scanThreatMatchesWithDisplayName(rows sqlRows) ([]*threatintel.ThreatMatch, error) {
	var matches []*threatintel.ThreatMatch
	for rows.Next() {
		var m threatintel.ThreatMatch
		var threatType, source string
		var matchedAt time.Time
		var displayName string

		err := rows.Scan(&m.ID, &m.UserEmail, &m.NodeID, &m.SourceIP, &m.Destination,
			&threatType, &source, &m.Confidence, &m.Description, &matchedAt, &displayName)
		if err != nil {
			return nil, err
		}

		m.ThreatType = threatintel.ThreatType(threatType)
		m.Source = threatintel.ThreatSource(source)
		m.DisplayName = displayName
		m.MatchedAt = matchedAt

		matches = append(matches, &m)
	}

	return matches, rows.Err()
}

// sqlRows interface for testing
type sqlRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// ClearThreatIntelData clears all ThreatIntel-related tables to reset statistics
func (s *Storage) ClearThreatIntelData(ctx context.Context) error {
	tables := []string{
		"threat_matches",
		"threat_stats_agg",
		"threat_type_stats",
		"user_threat_stats",
		"user_threat_domains",
		"threat_hourly_stats",
		"threat_hourly_users",
		"threat_daily_stats",
		"threat_daily_users",
		"threat_geo_stats",
	}

	for _, table := range tables {
		_, err := s.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// Reset aggregated counter
	_, err := s.pool.Exec(ctx, `
		INSERT INTO threat_stats_agg (id, total_matches, last_updated)
		VALUES (1, 0, NOW())
		ON CONFLICT (id) DO UPDATE SET
			total_matches = 0,
			last_updated = NOW()
	`)
	if err != nil {
		return fmt.Errorf("reset threat_stats_agg: %w", err)
	}

	return nil
}

// ClearAllUserData clears all user-related tables including IP history, stats, and correlation data
func (s *Storage) ClearAllUserData(ctx context.Context) error {
	tables := []string{
		"user_stats",
		"user_ip_history",
		"user_locations",
		"user_destinations",
		"user_ai_profile",
		"ip_user_map",
		"hwid_user_map",
		"user_fingerprints",
		"blacklist_matches",
	}

	for _, table := range tables {
		_, err := s.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			// Table might not exist, skip
			continue
		}
	}

	return nil
}
