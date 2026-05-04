package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/models"
)

// UpdateUserStats updates statistics for a user.
// nodeID is a text node name resolved to the nodes(id) smallint FK.
// userEmail must be a valid UUID string; non-UUID strings are converted to SHA-1 UUID.
func (s *Storage) UpdateUserStats(ctx context.Context, nodeID, userEmail string, requests int, blacklistHits int, lastBlacklistDomain string, uniqueDestinations int, lastIP string) error {
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

	var lastHit interface{}
	if blacklistHits > 0 {
		lastHit = now
	}

	var lastIPVal interface{}
	if lastIP != "" {
		lastIPVal = lastIP
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_stats (node_id, user_email, total_requests, blacklist_hits, unique_destinations, last_seen, last_ip, last_blacklist_hit, last_blacklist_domain)
		VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, $9)
		ON CONFLICT (node_id, user_email) DO UPDATE SET
			total_requests = user_stats.total_requests + EXCLUDED.total_requests,
			blacklist_hits = user_stats.blacklist_hits + EXCLUDED.blacklist_hits,
			unique_destinations = GREATEST(user_stats.unique_destinations, EXCLUDED.unique_destinations),
			last_seen = EXCLUDED.last_seen,
			last_ip = COALESCE(EXCLUDED.last_ip, user_stats.last_ip),
			last_blacklist_hit = COALESCE(EXCLUDED.last_blacklist_hit, user_stats.last_blacklist_hit),
			last_blacklist_domain = COALESCE(EXCLUDED.last_blacklist_domain, user_stats.last_blacklist_domain)
	`, int16(nid), userUUID, requests, blacklistHits, uniqueDestinations, now, lastIPVal, lastHit, lastBlacklistDomain)
	return err
}

// GetTopBlacklistUsers gets users with most blacklist hits
func (s *Storage) GetTopBlacklistUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			n.node_id AS node_id,
			u.user_email::text,
			COALESCE(r.username, u.user_email::text) AS display_name,
			u.total_requests,
			u.blacklist_hits,
			u.last_seen,
			COALESCE(u.last_ip::text, '') AS last_ip,
			u.last_blacklist_hit,
			COALESCE(u.last_blacklist_domain, '') AS last_blacklist_domain
		FROM user_stats u
		JOIN nodes n ON n.id = u.node_id
		LEFT JOIN remna_users r ON r.uuid = u.user_email
		WHERE u.blacklist_hits > 0
		ORDER BY u.blacklist_hits DESC, u.total_requests DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.UserStats
	for rows.Next() {
		u := &models.UserStats{}
		var lastSeen, lastHit *time.Time
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.DisplayName, &u.TotalRequests, &u.BlacklistHits,
			&lastSeen, &u.LastIP, &lastHit, &u.LastBlacklistDomain)
		if err != nil {
			return nil, err
		}
		if lastSeen != nil {
			u.LastSeen = *lastSeen
		}
		if lastHit != nil {
			u.LastBlacklistHit = *lastHit
		}
		users = append(users, u)
	}
	return users, nil
}

// GetAllUsers gets all users sorted by requests (aggregated across nodes)
// Joins with remna_users to get display names. node_id is resolved to text via nodes table.
func (s *Storage) GetAllUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	cacheKey := fmt.Sprintf("all_users_%d", limit)

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]*models.UserStats), nil
	}

	rows, err := s.pool.Query(ctx, `
		WITH user_agg AS (
			SELECT
				STRING_AGG(DISTINCT n.node_id, ',') AS nodes,
				us.user_email,
				COALESCE(SUM(us.total_requests), 0) AS total_requests,
				COALESCE(SUM(us.blacklist_hits), 0) AS blacklist_hits,
				MAX(us.last_seen) AS last_seen,
				MAX(us.last_ip::text) AS last_ip,
				MAX(us.last_blacklist_hit) AS last_blacklist_hit,
				MAX(us.last_blacklist_domain) AS last_blacklist_domain
			FROM user_stats us
			JOIN nodes n ON n.id = us.node_id
			GROUP BY us.user_email
		)
		SELECT
			u.nodes,
			u.user_email::text,
			COALESCE(r.username, u.user_email::text) AS display_name,
			u.total_requests,
			u.blacklist_hits,
			u.last_seen,
			COALESCE(u.last_ip, '') AS last_ip,
			u.last_blacklist_hit,
			COALESCE(u.last_blacklist_domain, '') AS last_blacklist_domain
		FROM user_agg u
		LEFT JOIN remna_users r ON r.uuid = u.user_email
		ORDER BY u.total_requests DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []*models.UserStats
	for rows.Next() {
		u := &models.UserStats{}
		var lastSeen, lastHit *time.Time
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.DisplayName, &u.TotalRequests, &u.BlacklistHits,
			&lastSeen, &u.LastIP, &lastHit, &u.LastBlacklistDomain)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if lastSeen != nil {
			u.LastSeen = *lastSeen
		}
		if lastHit != nil {
			u.LastBlacklistHit = *lastHit
		}
		users = append(users, u)
	}

	s.cache.Set(cacheKey, users, CacheTTLShort)
	return users, nil
}

// extractNumericPart extracts numeric suffix from a string like "prefix_123" or "abc123"
func extractNumericPart(s string) string {
	// Try to find underscore and get part after it
	if idx := strings.LastIndex(s, "_"); idx != -1 && idx < len(s)-1 {
		part := s[idx+1:]
		if _, err := strconv.Atoi(part); err == nil {
			return part
		}
	}
	// Try to extract trailing digits
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] < '0' || s[i] > '9' {
			if i < len(s)-1 {
				return s[i+1:]
			}
			break
		}
	}
	// Check if entire string is numeric
	if _, err := strconv.Atoi(s); err == nil {
		return s
	}
	return ""
}

// buildUserSearchIDs creates a list of possible user identifiers to search for
// This handles cases where user might be stored with different formats (e.g., "1301" vs "us_demo" vs "remna_user" vs "anything_1301")
func buildUserSearchIDs(userEmail string) []string {
	seen := make(map[string]bool)
	var searchIDs []string

	addID := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			searchIDs = append(searchIDs, id)
		}
	}

	// Always include original
	addID(userEmail)

	// Extract numeric part and add variations
	numericPart := extractNumericPart(userEmail)
	if numericPart != "" {
		addID(numericPart)
		// Common prefixes used in the system
		addID("us_" + numericPart)
		addID("remnawave_" + numericPart)
	}

	return searchIDs
}

// GetRemnaIDForUser finds the Remnawave numeric ID for a user by username, us_id, or existing numeric ID
// This is needed because Xray logs contain Remnawave numeric ID in the email field
func (s *Storage) GetRemnaIDForUser(ctx context.Context, userEmail string) (int64, error) {
	var remnaID int64

	// Check if userEmail is already a numeric ID
	if numericID, err := strconv.ParseInt(userEmail, 10, 64); err == nil {
		// Verify it exists in remna_users
		row := s.db.QueryRowContext(ctx, `SELECT id FROM remna_users WHERE id = $1`, numericID)
		if err := row.Scan(&remnaID); err == nil {
			return remnaID, nil
		}
	}

	// Try to find by username
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(id, 0) FROM remna_users WHERE username = $1`, userEmail)
	if err := row.Scan(&remnaID); err == nil && remnaID > 0 {
		return remnaID, nil
	}

	// Try to find by us_id
	row = s.db.QueryRowContext(ctx, `SELECT COALESCE(id, 0) FROM remna_users WHERE us_id = $1`, userEmail)
	if err := row.Scan(&remnaID); err == nil && remnaID > 0 {
		return remnaID, nil
	}

	return 0, nil // Not found, but not an error
}

// BuildFullSearchIDs creates a comprehensive list of user identifiers including Remnawave ID
func (s *Storage) BuildFullSearchIDs(ctx context.Context, userEmail string) []string {
	searchIDs := buildUserSearchIDs(userEmail)

	// Add Remnawave numeric ID if we can find it
	if remnaID, err := s.GetRemnaIDForUser(ctx, userEmail); err == nil && remnaID > 0 {
		remnaIDStr := strconv.FormatInt(remnaID, 10)
		found := false
		for _, id := range searchIDs {
			if id == remnaIDStr {
				found = true
				break
			}
		}
		if !found {
			searchIDs = append(searchIDs, remnaIDStr)
		}
	}

	return searchIDs
}

// GetUserDetails gets detailed stats for a specific user
func (s *Storage) GetUserDetails(ctx context.Context, userEmail string) (*models.UserDetails, error) {
	user := &models.UserDetails{
		UserEmail: userEmail,
		Nodes:     []models.UserNodeStats{},
	}

	// Build list of possible identifiers to search for
	searchIDs := buildUserSearchIDs(userEmail)

	// Debug log
	fmt.Printf("[DEBUG] GetUserDetails: email=%s, searchIDs=%v\n", userEmail, searchIDs)

	// Try to find user in remna_users
	var remnaUserExists bool
	var remnaUUID, username, status string
	var remnaID int64
	var usedTraffic, trafficLimit int64
	var hwidCount int
	var hwidLimit sql.NullInt64
	var onlineAt, expireAt *time.Time
	var telegramID sql.NullInt64
	var description string
	var usID sql.NullString

	// Check if userEmail is a numeric ID
	if numericID, err := strconv.ParseInt(userEmail, 10, 64); err == nil {
		row := s.db.QueryRowContext(ctx, `
			SELECT uuid, COALESCE(id, 0), username, status,
				   COALESCE(used_traffic_bytes, 0),
				   COALESCE(traffic_limit_bytes, 0),
				   COALESCE(hwid_device_count, 0),
				   hwid_device_limit,
				   online_at,
				   expire_at,
				   telegram_id,
				   COALESCE(description, ''),
				   us_id
			FROM remna_users WHERE id = $1
		`, numericID)

		err := row.Scan(&remnaUUID, &remnaID, &username, &status, &usedTraffic, &trafficLimit,
			&hwidCount, &hwidLimit, &onlineAt, &expireAt, &telegramID, &description, &usID)
		if err == nil {
			remnaUserExists = true
		}
	}

	// If not found by ID, try by us_id
	if !remnaUserExists {
		row := s.db.QueryRowContext(ctx, `
			SELECT uuid, COALESCE(id, 0), username, status,
				   COALESCE(used_traffic_bytes, 0),
				   COALESCE(traffic_limit_bytes, 0),
				   COALESCE(hwid_device_count, 0),
				   hwid_device_limit,
				   online_at,
				   expire_at,
				   telegram_id,
				   COALESCE(description, ''),
				   us_id
			FROM remna_users WHERE us_id = $1
		`, userEmail)

		err := row.Scan(&remnaUUID, &remnaID, &username, &status, &usedTraffic, &trafficLimit,
			&hwidCount, &hwidLimit, &onlineAt, &expireAt, &telegramID, &description, &usID)
		if err == nil {
			remnaUserExists = true
		}
	}

	// If not found by us_id, try by username
	if !remnaUserExists {
		row := s.db.QueryRowContext(ctx, `
			SELECT uuid, COALESCE(id, 0), username, status,
				   COALESCE(used_traffic_bytes, 0),
				   COALESCE(traffic_limit_bytes, 0),
				   COALESCE(hwid_device_count, 0),
				   hwid_device_limit,
				   online_at,
				   expire_at,
				   telegram_id,
				   COALESCE(description, ''),
				   us_id
			FROM remna_users WHERE username = $1
		`, userEmail)

		err := row.Scan(&remnaUUID, &remnaID, &username, &status, &usedTraffic, &trafficLimit,
			&hwidCount, &hwidLimit, &onlineAt, &expireAt, &telegramID, &description, &usID)
		if err == nil {
			remnaUserExists = true
		}
	}

	// If found user, add their Remnawave ID to search IDs for stats lookup
	if remnaUserExists && remnaID > 0 {
		remnaIDStr := strconv.FormatInt(remnaID, 10)
		found := false
		for _, id := range searchIDs {
			if id == remnaIDStr {
				found = true
				break
			}
		}
		if !found {
			searchIDs = append(searchIDs, remnaIDStr)
			fmt.Printf("[DEBUG] GetUserDetails: added remnaID=%s to searchIDs, now=%v\n", remnaIDStr, searchIDs)
		}
	}

	// Also add us_id if present (for backwards compatibility)
	if remnaUserExists && usID.Valid && usID.String != "" {
		found := false
		for _, id := range searchIDs {
			if id == usID.String {
				found = true
				break
			}
		}
		if !found {
			searchIDs = append(searchIDs, usID.String)
			fmt.Printf("[DEBUG] GetUserDetails: added us_id=%s to searchIDs, now=%v\n", usID.String, searchIDs)
		}
	}

	// Populate user fields if found
	if remnaUserExists {
		user.RemnaUUID = remnaUUID
		user.DisplayName = username
		user.RemnaStatus = status
		user.RemnaUsedTraffic = usedTraffic
		user.RemnaTrafficLimit = trafficLimit
		if trafficLimit > 0 {
			user.RemnaTrafficPct = float64(usedTraffic) / float64(trafficLimit) * 100
		}
		user.RemnaHwidCount = hwidCount
		if hwidLimit.Valid {
			limit := int(hwidLimit.Int64)
			user.RemnaHwidLimit = &limit
		}
		if onlineAt != nil {
			user.RemnaOnlineAt = onlineAt.Format(time.RFC3339)
		}
		if expireAt != nil {
			user.RemnaExpireAt = expireAt.Format(time.RFC3339)
		}
		if telegramID.Valid {
			user.RemnaTelegramID = &telegramID.Int64
		}
		user.RemnaDescription = description
	}

	// If not found by exact username or ID, try to find by description with US_ID
	if !remnaUserExists {
		var displayName sql.NullString
		searchPattern := "%US_ID: " + userEmail + "%"
		_ = s.db.QueryRowContext(ctx, `
			SELECT username FROM remna_users
			WHERE description LIKE $1
		`, searchPattern).Scan(&displayName)
		if displayName.Valid && displayName.String != "" {
			user.DisplayName = displayName.String
		}
	}

	// Resolve every text identifier in searchIDs to its canonical UUID for
	// querying the schema-v2 stat tables (user_stats, blacklist_matches,
	// threat_matches, user_threat_stats, user_risk_profiles — all have
	// user_email as uuid). Without this, a text array against a uuid column
	// returns zero rows because Postgres does uuid::text = ANY(text[]).
	seenUUID := make(map[uuid.UUID]bool, len(searchIDs))
	searchUUIDs := make([]uuid.UUID, 0, len(searchIDs))
	for _, id := range searchIDs {
		u, err := s.ResolveUserEmailToUUID(ctx, id)
		if err != nil || seenUUID[u] {
			continue
		}
		seenUUID[u] = true
		searchUUIDs = append(searchUUIDs, u)
	}

	// Per-node user stats
	nodeRows, err := s.pool.Query(ctx, `
		SELECT node_id, total_requests, blacklist_hits, unique_destinations,
			   last_seen,
			   last_blacklist_hit,
			   COALESCE(last_blacklist_domain, '') as last_blacklist_domain
		FROM user_stats
		WHERE user_email = ANY($1)
		ORDER BY total_requests DESC
	`, searchUUIDs)
	if err != nil {
		return nil, err
	}
	defer nodeRows.Close()

	for nodeRows.Next() {
		var ns models.UserNodeStats
		var lastSeen, lastHit *time.Time
		if err := nodeRows.Scan(&ns.NodeID, &ns.TotalRequests, &ns.BlacklistHits, &ns.UniqueDestinations,
			&lastSeen, &lastHit, &ns.LastBlacklistDomain); err != nil {
			return nil, err
		}
		if lastSeen != nil {
			ns.LastSeen = *lastSeen
		}
		if lastHit != nil {
			ns.LastBlacklistHit = *lastHit
		}
		user.TotalRequests += ns.TotalRequests
		user.TotalBlacklistHits += ns.BlacklistHits
		user.Nodes = append(user.Nodes, ns)
	}

	// Recent blacklist matches. source_ip is inet — cast to text for the
	// string scan target.
	matchRows, err := s.pool.Query(ctx, `
		SELECT node_id, COALESCE(host(source_ip), '') AS source_ip,
		       destination, matched_rule, timestamp
		FROM blacklist_matches
		WHERE user_email = ANY($1)
		ORDER BY timestamp DESC
		LIMIT 50
	`, searchUUIDs)
	if err != nil {
		return nil, err
	}
	defer matchRows.Close()

	for matchRows.Next() {
		var m models.BlacklistMatchInfo
		if err := matchRows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &m.Timestamp); err != nil {
			return nil, err
		}
		user.RecentMatches = append(user.RecentMatches, m)
	}

	// Threat matches aggregate (per-category counts)
	if aggRows, err := s.pool.Query(ctx, `
		SELECT threat_type, SUM(match_count) as cnt
		FROM user_threat_stats
		WHERE user_email = ANY($1)
		GROUP BY threat_type
		ORDER BY cnt DESC
	`, searchUUIDs); err == nil {
		user.ThreatsByType = map[string]int64{}
		for aggRows.Next() {
			var tt string
			var cnt int64
			if err := aggRows.Scan(&tt, &cnt); err == nil {
				user.ThreatsByType[tt] = cnt
				user.TotalThreats += cnt
			}
		}
		aggRows.Close()
	}

	// Recent threat matches — top 30 per category
	if tRows, err := s.pool.Query(ctx, `
		WITH ranked AS (
			SELECT node_id, destination, threat_type, source, confidence,
			       COALESCE(description, '') as description,
			       COALESCE(host(source_ip), '') as source_ip,
			       matched_at,
			       ROW_NUMBER() OVER (PARTITION BY threat_type ORDER BY matched_at DESC) AS rn
			FROM threat_matches
			WHERE user_email = ANY($1)
		)
		SELECT node_id, destination, threat_type, source, confidence,
		       description, source_ip, matched_at
		FROM ranked
		WHERE rn <= 30
		ORDER BY matched_at DESC
	`, searchUUIDs); err == nil {
		for tRows.Next() {
			var t models.UserThreatInfo
			if err := tRows.Scan(&t.NodeID, &t.Destination, &t.ThreatType, &t.Source, &t.Confidence,
				&t.Description, &t.SourceIP, &t.MatchedAt); err == nil {
				user.RecentThreats = append(user.RecentThreats, t)
			}
		}
		tRows.Close()
	}

	// Risk profile
	var rl sql.NullString
	var rs sql.NullInt64
	if err := s.pool.QueryRow(ctx, `
		SELECT risk_level, risk_score
		FROM user_risk_profiles
		WHERE user_email = ANY($1)
		ORDER BY risk_score DESC
		LIMIT 1
	`, searchUUIDs).Scan(&rl, &rs); err == nil {
		if rl.Valid {
			user.RiskLevel = rl.String
		}
		if rs.Valid {
			user.RiskScore = int(rs.Int64)
		}
	}

	return user, nil
}

// GetUserBlacklistCount gets the count of blacklist hits for a user since a given time
func (s *Storage) GetUserBlacklistCount(ctx context.Context, nodeID, userEmail string, since time.Time) (int, error) {
	nid, err := s.LookupNodeID(ctx, nodeID, "exit")
	if err != nil {
		return 0, nil // node not found → no matches
	}
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return 0, fmt.Errorf("resolve user_email: %w", err)
	}
	var count int
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM blacklist_matches
		WHERE node_id = $1 AND user_email = $2 AND timestamp > $3
	`, int16(nid), userUUID, since.UTC()).Scan(&count)
	return count, err
}

// GetGlobalStats gets aggregated stats across all nodes (cached)
func (s *Storage) GetGlobalStats(ctx context.Context) (*models.GlobalStats, error) {
	cacheKey := "global_stats"

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.(*models.GlobalStats), nil
	}

	stats := &models.GlobalStats{}

	oneMinAgo := time.Now().UTC().Add(-1 * time.Minute)

	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(total_requests), 0), COALESCE(SUM(blacklist_hits), 0), COUNT(*)
		FROM node_stats
	`).Scan(&stats.TotalRequests, &stats.TotalBlacklistHits, &stats.TotalNodes)
	if err != nil {
		return nil, err
	}

	// Prefer Remnawave's authoritative user counts (synced from panel API).
	// Single round-trip via FILTER pushes all status + online-recency
	// counts together. Falls back to access-log heuristic if remna_users
	// is empty (sync hasn't run / Remnawave integration disabled).
	var (
		remnaTotal, remnaActive, remnaDisabled, remnaExpired, remnaLimited int
		online1h, online24h, neverOnline                                   int
	)
	err = s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'ACTIVE'),
			COUNT(*) FILTER (WHERE status = 'DISABLED'),
			COUNT(*) FILTER (WHERE status = 'EXPIRED'),
			COUNT(*) FILTER (WHERE status = 'LIMITED'),
			COUNT(*) FILTER (WHERE online_at > now() - interval '1 hour'),
			COUNT(*) FILTER (WHERE online_at > now() - interval '24 hours'),
			COUNT(*) FILTER (WHERE online_at IS NULL)
		FROM remna_users
	`).Scan(&remnaTotal, &remnaActive, &remnaDisabled, &remnaExpired, &remnaLimited,
		&online1h, &online24h, &neverOnline)
	if err != nil {
		return nil, err
	}

	// OnlineUsers = real-time XTLS-tracked sum across all Remnawave nodes.
	// Updated every sync cycle from Remnawave panel; sums per-node
	// users_online (so multi-device users on different nodes count once
	// per node — same as Remnawave panel's per-node display).
	var nodesOnline sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(users_online), 0) FROM remna_nodes
	`).Scan(&nodesOnline)
	if err != nil {
		return nil, err
	}

	if remnaTotal > 0 {
		stats.TotalUniqueUsers = remnaTotal
		stats.ActiveUsers = remnaActive
		stats.DisabledUsers = remnaDisabled
		stats.ExpiredUsers = remnaExpired
		stats.LimitedUsers = remnaLimited
		stats.OnlineUsers = int(nodesOnline.Int64)
		stats.OnlineLastHour = online1h
		stats.OnlineLast24h = online24h
		stats.NeverOnline = neverOnline
	} else {
		// Fallback: traffic-based heuristic when remna_users is empty.
		err = s.db.QueryRowContext(ctx, `
			SELECT COUNT(DISTINCT user_email) FROM user_stats
		`).Scan(&stats.TotalUniqueUsers)
		if err != nil {
			return nil, err
		}
		err = s.db.QueryRowContext(ctx, `
			SELECT COUNT(DISTINCT user_email) FROM user_stats
			WHERE last_seen > $1
		`, oneMinAgo).Scan(&stats.OnlineUsers)
		if err != nil {
			return nil, err
		}
	}

	s.cache.Set(cacheKey, stats, CacheTTLShort)
	return stats, nil
}

// GetUserAnomalies finds users with unusual activity spikes
func (s *Storage) GetUserAnomalies(ctx context.Context, limit int) ([]models.Anomaly, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			us.user_email::text,
			n.node_id,
			us.blacklist_hits,
			us.total_requests,
			COALESCE(us.last_blacklist_domain, '') AS last_blacklist_domain,
			us.last_seen
		FROM user_stats us
		JOIN nodes n ON n.id = us.node_id
		WHERE us.blacklist_hits > 10
		ORDER BY us.blacklist_hits DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anomalies []models.Anomaly
	for rows.Next() {
		var userEmail, nodeID, lastDomain string
		var blacklistHits, totalRequests int64
		var lastSeen *time.Time
		if err := rows.Scan(&userEmail, &nodeID, &blacklistHits, &totalRequests, &lastDomain, &lastSeen); err != nil {
			return nil, err
		}

		ratio := float64(blacklistHits) / float64(totalRequests) * 100
		if ratio > 5 || blacklistHits > 50 {
			a := models.Anomaly{
				Type:      "user_blacklist_spike",
				NodeID:    nodeID,
				UserEmail: userEmail,
				Value:     blacklistHits,
				Baseline:  50,
				Deviation: ratio,
				Message:   fmt.Sprintf("User %s has %d blacklist hits (%.1f%% of traffic)", userEmail, blacklistHits, ratio),
			}
			if lastSeen != nil {
				a.Hour = *lastSeen
			}
			anomalies = append(anomalies, a)
		}
	}
	return anomalies, nil
}

// GetRecentAlerts gets recent alerts
func (s *Storage) GetRecentAlerts(ctx context.Context, limit int) ([]*models.Alert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.type, n.node_id, a.user_email::text,
			   COALESCE(a.source_ip::text, '') AS source_ip,
			   COALESCE(a.destination, '') AS destination,
			   a.count, a.message,
			   a.created_at,
			   a.sent
		FROM alerts a
		JOIN nodes n ON n.id = a.node_id
		ORDER BY a.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var sourceIP, destination string
		var createdAt *time.Time
		if err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &a.UserEmail, &sourceIP, &destination, &a.Count, &a.Message, &createdAt, &a.Sent); err != nil {
			return nil, err
		}
		a.SourceIP = sourceIP
		a.Destination = destination
		if createdAt != nil {
			a.CreatedAt = *createdAt
		}
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// UserIPHistory represents a user's IP address history entry
type UserIPHistory struct {
	IPAddress    string    `json:"ip_address"`
	NodeID       string    `json:"node_id,omitempty"`
	CountryCode  string    `json:"country_code,omitempty"`
	CountryName  string    `json:"country_name,omitempty"`
	City         string    `json:"city,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestCount int64     `json:"request_count"`
}

// RecordUserIP records or updates a user's IP address in history.
// userEmail is parsed to UUID; nodeID is resolved to smallint FK.
func (s *Storage) RecordUserIP(ctx context.Context, userEmail, ipAddress, nodeID, countryCode, countryName, city string) error {
	if ipAddress == "" {
		return nil
	}

	now := time.Now().UTC()

	// user_email is uuid NOT NULL.
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	// node_id is nullable smallint FK — resolve if non-empty.
	var nodeIntID interface{}
	if nodeID != "" {
		nid, err := s.LookupNodeID(ctx, nodeID, "exit")
		if err == nil {
			nodeIntID = int16(nid)
		}
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_ip_history (user_email, ip_address, node_id, country_code, country_name, city, first_seen, last_seen, request_count)
		VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, 1)
		ON CONFLICT (user_email, ip_address) DO UPDATE SET
			node_id = COALESCE(EXCLUDED.node_id, user_ip_history.node_id),
			country_code = COALESCE(EXCLUDED.country_code, user_ip_history.country_code),
			country_name = COALESCE(EXCLUDED.country_name, user_ip_history.country_name),
			city = COALESCE(EXCLUDED.city, user_ip_history.city),
			last_seen = EXCLUDED.last_seen,
			request_count = user_ip_history.request_count + 1
	`, userUUID, ipAddress, nodeIntID, countryCode, countryName, city, now, now)

	if err != nil {
		return err
	}

	// Keep only last 20 IPs per user (delete oldest)
	_, err = s.pool.Exec(ctx, `
		DELETE FROM user_ip_history
		WHERE user_email = $1 AND id NOT IN (
			SELECT id FROM user_ip_history
			WHERE user_email = $2
			ORDER BY last_seen DESC
			LIMIT 20
		)
	`, userUUID, userUUID)

	return err
}

// GetUserIPHistory gets the IP history for a user (last 20 IPs).
// ip_address (inet) and node_id (smallint FK) are cast/joined to text.
func (s *Storage) GetUserIPHistory(ctx context.Context, userEmail string) ([]*UserIPHistory, error) {
	// Resolve userEmail to UUID(s).
	resolvedUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("resolve user_email: %w", err)
	}
	searchUUIDs := []uuid.UUID{resolvedUUID}

	rows, err := s.pool.Query(ctx, `
		SELECT host(h.ip_address),
			   COALESCE(n.node_id, '') AS node_id,
			   COALESCE(h.country_code, '') AS country_code,
			   COALESCE(h.country_name, '') AS country_name,
			   COALESCE(h.city, '') AS city,
			   h.first_seen,
			   h.last_seen,
			   h.request_count
		FROM user_ip_history h
		LEFT JOIN nodes n ON n.id = h.node_id
		WHERE h.user_email = ANY($1)
		ORDER BY h.last_seen DESC
		LIMIT 20
	`, searchUUIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*UserIPHistory
	for rows.Next() {
		h := &UserIPHistory{}
		if err := rows.Scan(&h.IPAddress, &h.NodeID, &h.CountryCode, &h.CountryName, &h.City,
			&h.FirstSeen, &h.LastSeen, &h.RequestCount); err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, nil
}

// GetSubscriptionAbusers finds users with suspiciously many unique IPs (potential account sharing)
func (s *Storage) GetSubscriptionAbusers(ctx context.Context, since time.Time, minIPs int) ([]*models.SubscriptionAbuse, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			h.user_email::text,
			COALESCE(r.username, h.user_email::text) AS display_name,
			COUNT(DISTINCT h.ip_address) AS unique_ips,
			COUNT(DISTINCT h.node_id) AS unique_nodes,
			COUNT(DISTINCT h.country_code) AS unique_countries,
			COALESCE(STRING_AGG(DISTINCT h.country_code, ','), '') AS countries,
			COALESCE(STRING_AGG(DISTINCT n.node_id, ','), '') AS nodes,
			SUM(h.request_count) AS total_requests,
			MAX(h.last_seen) AS last_seen
		FROM user_ip_history h
		LEFT JOIN nodes n ON n.id = h.node_id
		LEFT JOIN remna_users r ON r.uuid = h.user_email
		WHERE h.last_seen >= $1
		GROUP BY h.user_email, r.username
		HAVING COUNT(DISTINCT h.ip_address) >= $2
		ORDER BY COUNT(DISTINCT h.ip_address) DESC, COUNT(DISTINCT h.node_id) DESC, SUM(h.request_count) DESC
	`, since.UTC(), minIPs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var abusers []*models.SubscriptionAbuse
	for rows.Next() {
		a := &models.SubscriptionAbuse{}
		var countriesStr, nodesStr string
		var lastSeen *time.Time
		if err := rows.Scan(&a.UserEmail, &a.Username, &a.UniqueIPs, &a.UniqueNodes, &a.UniqueCountries,
			&countriesStr, &nodesStr, &a.TotalRequests, &lastSeen); err != nil {
			return nil, err
		}
		if lastSeen != nil {
			a.LastSeen = *lastSeen
		}
		if countriesStr != "" {
			a.Countries = splitAndTrim(countriesStr, ",")
		}
		if nodesStr != "" {
			a.Nodes = splitAndTrim(nodesStr, ",")
		}
		abusers = append(abusers, a)
	}

	// Load IP details for each abuser
	for _, abuser := range abusers {
		ips, err := s.getAbuserIPs(ctx, abuser.UserEmail, since.UTC())
		if err != nil {
			continue
		}
		abuser.IPs = ips
	}

	return abusers, nil
}

// getAbuserIPs gets IP details for a suspected abuser
func (s *Storage) getAbuserIPs(ctx context.Context, userEmail string, since time.Time) ([]models.IPInfo, error) {
	// Resolve userEmail to UUID.
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("resolve user_email: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			host(h.ip_address),
			COALESCE(h.country_code, '') AS country_code,
			COALESCE(h.city, '') AS city,
			COALESCE(n.node_id, '') AS node_id,
			h.request_count,
			h.last_seen
		FROM user_ip_history h
		LEFT JOIN nodes n ON n.id = h.node_id
		WHERE h.user_email = $1 AND h.last_seen >= $2
		ORDER BY h.request_count DESC
		LIMIT 10
	`, userUUID, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []models.IPInfo
	for rows.Next() {
		ip := models.IPInfo{}
		if err := rows.Scan(&ip.IP, &ip.CountryCode, &ip.City, &ip.NodeID, &ip.RequestCount, &ip.LastSeen); err != nil {
			continue
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// splitAndTrim splits a string and trims whitespace
func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, p := range strings.Split(s, sep) {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// DebugGetAllUserEmails returns all unique user_email values from the database
func (s *Storage) DebugGetAllUserEmails(ctx context.Context, search string, limit int) ([]string, error) {
	query := `SELECT DISTINCT user_email FROM user_stats`
	args := []interface{}{}
	argN := 1

	if search != "" {
		query += fmt.Sprintf(` WHERE user_email ILIKE $%d`, argN)
		args = append(args, "%"+search+"%")
		argN++
	}

	query += fmt.Sprintf(` ORDER BY user_email LIMIT $%d`, argN)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			continue
		}
		emails = append(emails, email)
	}
	return emails, nil
}
