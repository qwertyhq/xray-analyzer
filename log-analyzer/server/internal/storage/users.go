package storage

import (
	"context"
	"fmt"
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
		SELECT node_id, user_email, total_requests, blacklist_hits, 
			   COALESCE(last_seen, '') as last_seen, 
			   COALESCE(last_ip, '') as last_ip,
			   COALESCE(last_blacklist_hit, '') as last_blacklist_hit, 
			   COALESCE(last_blacklist_domain, '') as last_blacklist_domain
		FROM user_stats
		WHERE blacklist_hits > 0
		ORDER BY blacklist_hits DESC, total_requests DESC
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
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.TotalRequests, &u.BlacklistHits, &lastSeenStr, &u.LastIP, &lastHitStr, &u.LastBlacklistDomain)
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
func (s *Storage) GetAllUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	rows, err := s.db.QueryContext(ctx, `
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
		ORDER BY total_requests DESC
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
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.TotalRequests, &u.BlacklistHits, &lastSeenStr, &u.LastIP, &lastHitStr, &u.LastBlacklistDomain)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.LastSeen = parseDateTime(lastSeenStr)
		u.LastBlacklistHit = parseDateTime(lastHitStr)
		users = append(users, u)
	}
	return users, nil
}

// GetUserDetails gets detailed stats for a specific user
func (s *Storage) GetUserDetails(ctx context.Context, userEmail string) (*models.UserDetails, error) {
	user := &models.UserDetails{
		UserEmail: userEmail,
		Nodes:     []models.UserNodeStats{},
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, total_requests, blacklist_hits, unique_destinations, 
			   COALESCE(last_seen, '') as last_seen, 
			   COALESCE(last_blacklist_hit, '') as last_blacklist_hit, 
			   COALESCE(last_blacklist_domain, '') as last_blacklist_domain
		FROM user_stats
		WHERE user_email = ?
		ORDER BY total_requests DESC
	`, userEmail)
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

	// Get recent blacklist matches
	matchRows, err := s.db.QueryContext(ctx, `
		SELECT node_id, source_ip, destination, matched_rule, COALESCE(timestamp, '') as timestamp
		FROM blacklist_matches
		WHERE user_email = ?
		ORDER BY timestamp DESC
		LIMIT 50
	`, userEmail)
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

	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM user_stats
		WHERE last_seen > datetime('now', '-5 minutes')
	`).Scan(&stats.OnlineUsers)
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
