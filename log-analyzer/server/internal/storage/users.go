package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// UpdateUserStats updates statistics for a user
func (s *Storage) UpdateUserStats(ctx context.Context, nodeID, userEmail string, requests int, blacklistHits int, lastBlacklistDomain string, uniqueDestinations int, lastIP string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var lastHit interface{}
	if blacklistHits > 0 {
		lastHit = now
	} else {
		lastHit = nil
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_stats (node_id, user_email, total_requests, blacklist_hits, unique_destinations, last_seen, last_ip, last_blacklist_hit, last_blacklist_domain)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id, user_email) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blacklist_hits = blacklist_hits + excluded.blacklist_hits,
			unique_destinations = MAX(unique_destinations, excluded.unique_destinations),
			last_seen = excluded.last_seen,
			last_ip = COALESCE(excluded.last_ip, last_ip),
			last_blacklist_hit = COALESCE(excluded.last_blacklist_hit, last_blacklist_hit),
			last_blacklist_domain = COALESCE(excluded.last_blacklist_domain, last_blacklist_domain)
	`, nodeID, userEmail, requests, blacklistHits, uniqueDestinations, now, lastIP, lastHit, lastBlacklistDomain)
	return err
}

// GetTopBlacklistUsers gets users with most blacklist hits
func (s *Storage) GetTopBlacklistUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			u.node_id, 
			u.user_email, 
			COALESCE(r.username, u.user_email) as display_name,
			u.total_requests, 
			u.blacklist_hits, 
			COALESCE(u.last_seen, '') as last_seen, 
			COALESCE(u.last_ip, '') as last_ip,
			COALESCE(u.last_blacklist_hit, '') as last_blacklist_hit, 
			COALESCE(u.last_blacklist_domain, '') as last_blacklist_domain
		FROM user_stats u
		LEFT JOIN remna_users r ON (
			r.username = u.user_email 
			OR CAST(r.id AS TEXT) = u.user_email
			OR r.us_id = u.user_email
		)
		WHERE u.blacklist_hits > 0
		ORDER BY u.blacklist_hits DESC, u.total_requests DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.UserStats
	for rows.Next() {
		u := &models.UserStats{}
		var lastSeenStr, lastHitStr string
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.DisplayName, &u.TotalRequests, &u.BlacklistHits, &lastSeenStr, &u.LastIP, &lastHitStr, &u.LastBlacklistDomain)
		if err != nil {
			return nil, err
		}
		u.LastSeen = parseDateTime(lastSeenStr)
		u.LastBlacklistHit = parseDateTime(lastHitStr)
		users = append(users, u)
	}
	return users, nil
}

// GetAllUsers gets all users sorted by requests (aggregated across nodes)
// Joins with remna_users to get display names for numeric user IDs
func (s *Storage) GetAllUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		WITH user_agg AS (
			SELECT 
				COALESCE(GROUP_CONCAT(DISTINCT node_id), '') as nodes,
				user_email, 
				COALESCE(SUM(total_requests), 0) as total_requests, 
				COALESCE(SUM(blacklist_hits), 0) as blacklist_hits, 
				COALESCE(MAX(last_seen), '') as last_seen, 
				COALESCE(MAX(last_ip), '') as last_ip,
				COALESCE(MAX(last_blacklist_hit), '') as last_blacklist_hit, 
				COALESCE(MAX(last_blacklist_domain), '') as last_blacklist_domain
			FROM user_stats
			GROUP BY user_email
		)
		SELECT 
			u.nodes,
			u.user_email,
			COALESCE(r.username, u.user_email) as display_name,
			u.total_requests,
			u.blacklist_hits,
			u.last_seen,
			u.last_ip,
			u.last_blacklist_hit,
			u.last_blacklist_domain
		FROM user_agg u
		LEFT JOIN remna_users r ON (
			r.username = u.user_email 
			OR CAST(r.id AS TEXT) = u.user_email
			OR r.us_id = u.user_email
		)
		ORDER BY u.total_requests DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []*models.UserStats
	for rows.Next() {
		u := &models.UserStats{}
		var lastSeenStr, lastHitStr string
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.DisplayName, &u.TotalRequests, &u.BlacklistHits, &lastSeenStr, &u.LastIP, &lastHitStr, &u.LastBlacklistDomain)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.LastSeen = parseDateTime(lastSeenStr)
		u.LastBlacklistHit = parseDateTime(lastHitStr)
		users = append(users, u)
	}
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
// This handles cases where user might be stored with different formats (e.g., "1301" vs "us_1301" vs "remnawave_1301" vs "anything_1301")
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

// buildUserSearchQuery creates a WHERE clause and args for searching by multiple user IDs
func buildUserSearchQuery(searchIDs []string) (string, []interface{}) {
	placeholders := make([]string, len(searchIDs))
	args := make([]interface{}, len(searchIDs))
	for i, id := range searchIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	return strings.Join(placeholders, ","), args
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
	// First try by numeric ID (if userEmail is a number, e.g., from Xray logs)
	// Then by username, then by us_id field
	var remnaUserExists bool
	var uuid, username, status string
	var remnaID int64 // Remnawave numeric ID - this is what appears in Xray logs as email:
	var usedTraffic, trafficLimit int64
	var hwidCount int
	var hwidLimit sql.NullInt64
	var onlineAt, expireAt sql.NullString
	var telegramID sql.NullInt64
	var description string
	var usID sql.NullString // us_id from description (legacy, not used in Xray logs)

	// Check if userEmail is a numeric ID
	if numericID, err := strconv.ParseInt(userEmail, 10, 64); err == nil {
		// Try to find by numeric ID first
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
			FROM remna_users WHERE id = ?
		`, numericID)

		err := row.Scan(&uuid, &remnaID, &username, &status, &usedTraffic, &trafficLimit,
			&hwidCount, &hwidLimit, &onlineAt, &expireAt, &telegramID, &description, &usID)
		if err == nil {
			remnaUserExists = true
		}
	}

	// If not found by ID, try by us_id (legacy Xray log user ID from description)
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
			FROM remna_users WHERE us_id = ?
		`, userEmail)

		err := row.Scan(&uuid, &remnaID, &username, &status, &usedTraffic, &trafficLimit,
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
			FROM remna_users WHERE username = ?
		`, userEmail)

		err := row.Scan(&uuid, &remnaID, &username, &status, &usedTraffic, &trafficLimit,
			&hwidCount, &hwidLimit, &onlineAt, &expireAt, &telegramID, &description, &usID)
		if err == nil {
			remnaUserExists = true
		}
	}

	// If found user, add their Remnawave ID to search IDs for stats lookup
	// The Remnawave ID is what appears in Xray logs as "email: <number>"
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

	placeholders, args := buildUserSearchQuery(searchIDs)

	// Populate user fields if found
	if remnaUserExists {
		user.RemnaUUID = uuid
		user.DisplayName = username
		user.RemnaStatus = status
		user.RemnaUsedTraffic = usedTraffic
		user.RemnaTrafficLimit = trafficLimit
		// Calculate traffic percent
		if trafficLimit > 0 {
			user.RemnaTrafficPct = float64(usedTraffic) / float64(trafficLimit) * 100
		}
		user.RemnaHwidCount = hwidCount
		if hwidLimit.Valid {
			limit := int(hwidLimit.Int64)
			user.RemnaHwidLimit = &limit
		}
		if onlineAt.Valid {
			user.RemnaOnlineAt = onlineAt.String
		}
		if expireAt.Valid {
			user.RemnaExpireAt = expireAt.String
		}
		if telegramID.Valid {
			user.RemnaTelegramID = &telegramID.Int64
		}
		user.RemnaDescription = description
	}

	// If not found by exact username or ID, try to find by description with US_ID
	if !remnaUserExists {
		var displayName sql.NullString
		_ = s.db.QueryRowContext(ctx, `
			SELECT username FROM remna_users 
			WHERE description LIKE '%US_ID: ' || ? || '%'
		`, userEmail).Scan(&displayName)
		if displayName.Valid && displayName.String != "" {
			user.DisplayName = displayName.String
		}
	}

	query := fmt.Sprintf(`
		SELECT node_id, total_requests, blacklist_hits, unique_destinations, 
			   COALESCE(last_seen, '') as last_seen, 
			   COALESCE(last_blacklist_hit, '') as last_blacklist_hit, 
			   COALESCE(last_blacklist_domain, '') as last_blacklist_domain
		FROM user_stats
		WHERE user_email IN (%s)
		ORDER BY total_requests DESC
	`, placeholders)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ns models.UserNodeStats
		var lastSeenStr, lastHitStr string
		if err := rows.Scan(&ns.NodeID, &ns.TotalRequests, &ns.BlacklistHits, &ns.UniqueDestinations, &lastSeenStr, &lastHitStr, &ns.LastBlacklistDomain); err != nil {
			return nil, err
		}
		ns.LastSeen = parseDateTime(lastSeenStr)
		ns.LastBlacklistHit = parseDateTime(lastHitStr)
		user.TotalRequests += ns.TotalRequests
		user.TotalBlacklistHits += ns.BlacklistHits
		user.Nodes = append(user.Nodes, ns)
	}

	// Get recent blacklist matches with all possible identifiers
	matchQuery := fmt.Sprintf(`
		SELECT node_id, source_ip, destination, matched_rule, COALESCE(timestamp, '') as timestamp
		FROM blacklist_matches
		WHERE user_email IN (%s)
		ORDER BY timestamp DESC
		LIMIT 50
	`, placeholders)

	matchRows, err := s.db.QueryContext(ctx, matchQuery, args...)
	if err != nil {
		return nil, err
	}
	defer matchRows.Close()

	for matchRows.Next() {
		var m models.BlacklistMatchInfo
		var tsStr string
		if err := matchRows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &tsStr); err != nil {
			return nil, err
		}
		m.Timestamp = parseDateTime(tsStr)
		user.RecentMatches = append(user.RecentMatches, m)
	}

	return user, nil
}

// GetUserBlacklistCount gets the count of blacklist hits for a user since a given time
func (s *Storage) GetUserBlacklistCount(ctx context.Context, nodeID, userEmail string, since time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM blacklist_matches
		WHERE node_id = ? AND user_email = ? AND timestamp > ?
	`, nodeID, userEmail, since).Scan(&count)
	return count, err
}

// GetGlobalStats gets aggregated stats across all nodes
func (s *Storage) GetGlobalStats(ctx context.Context) (*models.GlobalStats, error) {
	stats := &models.GlobalStats{}

	// Get node stats and sum online users from nodes (same 1-minute window as GetNodeStats)
	oneMinAgo := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)

	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(total_requests), 0), COALESCE(SUM(blacklist_hits), 0), COUNT(*)
		FROM node_stats
	`).Scan(&stats.TotalRequests, &stats.TotalBlacklistHits, &stats.TotalNodes)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM user_stats
	`).Scan(&stats.TotalUniqueUsers)
	if err != nil {
		return nil, err
	}

	// Use same time format as GetNodeStats for consistency
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM user_stats
		WHERE last_seen > ?
	`, oneMinAgo).Scan(&stats.OnlineUsers)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetUserAnomalies finds users with unusual activity spikes
func (s *Storage) GetUserAnomalies(ctx context.Context, limit int) ([]models.Anomaly, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			user_email,
			node_id,
			blacklist_hits,
			total_requests,
			COALESCE(last_blacklist_domain, '') as last_blacklist_domain,
			COALESCE(last_seen, '') as last_seen
		FROM user_stats
		WHERE blacklist_hits > 10
		ORDER BY blacklist_hits DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anomalies []models.Anomaly
	for rows.Next() {
		var userEmail, nodeID, lastDomain, lastSeenStr string
		var blacklistHits, totalRequests int64
		if err := rows.Scan(&userEmail, &nodeID, &blacklistHits, &totalRequests, &lastDomain, &lastSeenStr); err != nil {
			return nil, err
		}

		ratio := float64(blacklistHits) / float64(totalRequests) * 100
		if ratio > 5 || blacklistHits > 50 {
			anomalies = append(anomalies, models.Anomaly{
				Type:      "user_blacklist_spike",
				NodeID:    nodeID,
				UserEmail: userEmail,
				Value:     blacklistHits,
				Baseline:  50, // threshold for comparison
				Deviation: ratio,
				Message:   fmt.Sprintf("User %s has %d blacklist hits (%.1f%% of traffic)", userEmail, blacklistHits, ratio),
				Hour:      parseDateTime(lastSeenStr),
			})
		}
	}
	return anomalies, nil
}

// GetRecentAlerts gets recent alerts
func (s *Storage) GetRecentAlerts(ctx context.Context, limit int) ([]*models.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, node_id, user_email, 
			   COALESCE(source_ip, '') as source_ip, 
			   COALESCE(destination, '') as destination, 
			   count, message, 
			   COALESCE(created_at, '') as created_at, 
			   sent
		FROM alerts
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var sourceIP, destination, createdAtStr string
		if err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &a.UserEmail, &sourceIP, &destination, &a.Count, &a.Message, &createdAtStr, &a.Sent); err != nil {
			return nil, err
		}
		a.SourceIP = sourceIP
		a.Destination = destination
		a.CreatedAt = parseDateTime(createdAtStr)
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

// RecordUserIP records or updates a user's IP address in history
func (s *Storage) RecordUserIP(ctx context.Context, userEmail, ipAddress, nodeID, countryCode, countryName, city string) error {
	if ipAddress == "" {
		return nil
	}

	now := time.Now().UTC().Format(time.RFC3339)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_ip_history (user_email, ip_address, node_id, country_code, country_name, city, first_seen, last_seen, request_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(user_email, ip_address) DO UPDATE SET
			node_id = COALESCE(excluded.node_id, node_id),
			country_code = COALESCE(excluded.country_code, country_code),
			country_name = COALESCE(excluded.country_name, country_name),
			city = COALESCE(excluded.city, city),
			last_seen = excluded.last_seen,
			request_count = request_count + 1
	`, userEmail, ipAddress, nodeID, countryCode, countryName, city, now, now)

	if err != nil {
		return err
	}

	// Keep only last 20 IPs per user (delete oldest)
	_, err = s.db.ExecContext(ctx, `
		DELETE FROM user_ip_history 
		WHERE user_email = ? AND id NOT IN (
			SELECT id FROM user_ip_history 
			WHERE user_email = ? 
			ORDER BY last_seen DESC 
			LIMIT 20
		)
	`, userEmail, userEmail)

	return err
}

// GetUserIPHistory gets the IP history for a user (last 20 IPs)
func (s *Storage) GetUserIPHistory(ctx context.Context, userEmail string) ([]*UserIPHistory, error) {
	searchIDs := buildUserSearchIDs(userEmail)
	placeholders, args := buildUserSearchQuery(searchIDs)

	query := fmt.Sprintf(`
		SELECT ip_address, COALESCE(node_id, '') as node_id, 
			   COALESCE(country_code, '') as country_code,
			   COALESCE(country_name, '') as country_name,
			   COALESCE(city, '') as city,
			   COALESCE(first_seen, '') as first_seen,
			   COALESCE(last_seen, '') as last_seen,
			   request_count
		FROM user_ip_history
		WHERE user_email IN (%s)
		ORDER BY last_seen DESC
		LIMIT 20
	`, placeholders)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*UserIPHistory
	for rows.Next() {
		h := &UserIPHistory{}
		var firstSeenStr, lastSeenStr string
		if err := rows.Scan(&h.IPAddress, &h.NodeID, &h.CountryCode, &h.CountryName, &h.City, &firstSeenStr, &lastSeenStr, &h.RequestCount); err != nil {
			return nil, err
		}
		h.FirstSeen = parseDateTime(firstSeenStr)
		h.LastSeen = parseDateTime(lastSeenStr)
		history = append(history, h)
	}
	return history, nil
}

// GetSubscriptionAbusers finds users with suspiciously many unique IPs (potential account sharing)
func (s *Storage) GetSubscriptionAbusers(ctx context.Context, since time.Time, minIPs int) ([]*models.SubscriptionAbuse, error) {
	sinceStr := since.UTC().Format(time.RFC3339)

	// Find users with many unique IPs in the time period, also count unique nodes
	// Join with remna_users to get username for display
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			h.user_email,
			COALESCE(r.username, h.user_email) as display_name,
			COUNT(DISTINCT h.ip_address) as unique_ips,
			COUNT(DISTINCT h.node_id) as unique_nodes,
			COUNT(DISTINCT h.country_code) as unique_countries,
			GROUP_CONCAT(DISTINCT h.country_code) as countries,
			GROUP_CONCAT(DISTINCT h.node_id) as nodes,
			SUM(h.request_count) as total_requests,
			MAX(h.last_seen) as last_seen
		FROM user_ip_history h
		LEFT JOIN remna_users r ON (
			r.username = h.user_email 
			OR r.description LIKE '%US_ID: ' || h.user_email
		)
		WHERE h.last_seen >= ?
		GROUP BY h.user_email
		HAVING unique_ips >= ?
		ORDER BY unique_ips DESC, unique_nodes DESC, total_requests DESC
	`, sinceStr, minIPs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var abusers []*models.SubscriptionAbuse
	for rows.Next() {
		a := &models.SubscriptionAbuse{}
		var countriesStr, nodesStr, lastSeenStr string
		var nodesStrPtr *string
		if err := rows.Scan(&a.UserEmail, &a.Username, &a.UniqueIPs, &a.UniqueNodes, &a.UniqueCountries, &countriesStr, &nodesStrPtr, &a.TotalRequests, &lastSeenStr); err != nil {
			return nil, err
		}
		a.LastSeen = parseDateTime(lastSeenStr)
		if countriesStr != "" {
			a.Countries = splitAndTrim(countriesStr, ",")
		}
		if nodesStrPtr != nil {
			nodesStr = *nodesStrPtr
			a.Nodes = splitAndTrim(nodesStr, ",")
		}
		abusers = append(abusers, a)
	}

	// Load IP details for each abuser (now includes node_id)
	for _, abuser := range abusers {
		ips, err := s.getAbuserIPs(ctx, abuser.UserEmail, sinceStr)
		if err != nil {
			continue
		}
		abuser.IPs = ips
	}

	return abusers, nil
}

// getAbuserIPs gets IP details for a suspected abuser
func (s *Storage) getAbuserIPs(ctx context.Context, userEmail, sinceStr string) ([]models.IPInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			ip_address,
			COALESCE(country_code, '') as country_code,
			COALESCE(city, '') as city,
			COALESCE(node_id, '') as node_id,
			request_count,
			last_seen
		FROM user_ip_history
		WHERE user_email = ? AND last_seen >= ?
		ORDER BY request_count DESC
		LIMIT 10
	`, userEmail, sinceStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []models.IPInfo
	for rows.Next() {
		ip := models.IPInfo{}
		var lastSeenStr string
		if err := rows.Scan(&ip.IP, &ip.CountryCode, &ip.City, &ip.NodeID, &ip.RequestCount, &lastSeenStr); err != nil {
			continue
		}
		ip.LastSeen = parseDateTime(lastSeenStr)
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

	if search != "" {
		query += ` WHERE user_email LIKE ?`
		args = append(args, "%"+search+"%")
	}

	query += ` ORDER BY user_email LIMIT ?`
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
