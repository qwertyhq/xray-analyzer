package storage

import (
	"context"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// MaxThreatMatches is the maximum number of recent threat matches to keep for display
const MaxThreatMatches = 20

// SaveThreatMatch saves a threat match to the database, updates statistics, and cleans up old records
func (s *Storage) SaveThreatMatch(ctx context.Context, match *threatintel.ThreatMatch) error {
	now := time.Now().Format(time.RFC3339)

	// Insert into recent matches table
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_matches (
			user_email, node_id, source_ip, destination,
			threat_type, source, confidence, description, matched_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, match.UserEmail, match.NodeID, match.SourceIP, match.Destination,
		string(match.ThreatType), string(match.Source), match.Confidence,
		match.Description, now)

	if err != nil {
		return err
	}

	// Update aggregated total counter
	s.db.ExecContext(ctx, `
		UPDATE threat_stats_agg SET total_matches = total_matches + 1, last_updated = ? WHERE id = 1
	`, now)

	// Update threat type counter
	s.db.ExecContext(ctx, `
		INSERT INTO threat_type_stats (threat_type, match_count, last_match) 
		VALUES (?, 1, ?)
		ON CONFLICT(threat_type) DO UPDATE SET 
			match_count = match_count + 1,
			last_match = excluded.last_match
	`, string(match.ThreatType), now)

	// Update user threat stats
	s.db.ExecContext(ctx, `
		INSERT INTO user_threat_stats (user_email, threat_type, match_count, last_match)
		VALUES (?, ?, 1, ?)
		ON CONFLICT(user_email, threat_type) DO UPDATE SET
			match_count = match_count + 1,
			last_match = excluded.last_match
	`, match.UserEmail, string(match.ThreatType), now)

	// Update user domain stats (extract domain from destination)
	domain := extractDomain(match.Destination)
	if domain != "" {
		s.db.ExecContext(ctx, `
			INSERT INTO user_threat_domains (user_email, threat_type, domain, hit_count, last_seen)
			VALUES (?, ?, ?, 1, ?)
			ON CONFLICT(user_email, threat_type, domain) DO UPDATE SET
				hit_count = hit_count + 1,
				last_seen = excluded.last_seen
		`, match.UserEmail, string(match.ThreatType), domain, now)
	}

	// Delete old recent records keeping only MaxThreatMatches most recent
	_, err = s.db.ExecContext(ctx, `
		DELETE FROM threat_matches 
		WHERE id NOT IN (
			SELECT id FROM threat_matches 
			ORDER BY matched_at DESC 
			LIMIT ?
		)
	`, MaxThreatMatches)

	return err
}

// extractDomain extracts domain from destination (removes port)
func extractDomain(destination string) string {
	// Remove port if present
	if idx := strings.LastIndex(destination, ":"); idx > 0 {
		// Check if it's IPv6 (contains multiple colons)
		if strings.Count(destination, ":") > 1 && !strings.HasPrefix(destination, "[") {
			return destination // IPv6 without brackets, keep as is
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

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_email, node_id, source_ip, destination,
			   threat_type, source, confidence, description, matched_at
		FROM threat_matches
		ORDER BY matched_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []*threatintel.ThreatMatch
	for rows.Next() {
		var m threatintel.ThreatMatch
		var threatType, source string
		var matchedAt string

		err := rows.Scan(&m.ID, &m.UserEmail, &m.NodeID, &m.SourceIP, &m.Destination,
			&threatType, &source, &m.Confidence, &m.Description, &matchedAt)
		if err != nil {
			return nil, err
		}

		m.ThreatType = threatintel.ThreatType(threatType)
		m.Source = threatintel.ThreatSource(source)
		if t, err := time.Parse(time.RFC3339, matchedAt); err == nil {
			m.MatchedAt = t
		}

		matches = append(matches, &m)
	}

	return matches, rows.Err()
}

// GetThreatMatchesByUser returns threat matches for a specific user
func (s *Storage) GetThreatMatchesByUser(ctx context.Context, userEmail string, limit int) ([]*threatintel.ThreatMatch, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_email, node_id, source_ip, destination,
			   threat_type, source, confidence, description, matched_at
		FROM threat_matches
		WHERE user_email = ?
		ORDER BY matched_at DESC
		LIMIT ?
	`, userEmail, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []*threatintel.ThreatMatch
	for rows.Next() {
		var m threatintel.ThreatMatch
		var threatType, source string
		var matchedAt string

		err := rows.Scan(&m.ID, &m.UserEmail, &m.NodeID, &m.SourceIP, &m.Destination,
			&threatType, &source, &m.Confidence, &m.Description, &matchedAt)
		if err != nil {
			return nil, err
		}

		m.ThreatType = threatintel.ThreatType(threatType)
		m.Source = threatintel.ThreatSource(source)
		if t, err := time.Parse(time.RFC3339, matchedAt); err == nil {
			m.MatchedAt = t
		}

		matches = append(matches, &m)
	}

	return matches, rows.Err()
}

// GetThreatStats returns threat intelligence statistics from aggregated tables
func (s *Storage) GetThreatStats(ctx context.Context) (*threatintel.ThreatStats, error) {
	stats := &threatintel.ThreatStats{
		IndicatorsByType:   make(map[string]int64),
		IndicatorsBySource: make(map[string]int64),
	}

	// Total matches from aggregated table
	row := s.db.QueryRowContext(ctx, `SELECT total_matches FROM threat_stats_agg WHERE id = 1`)
	row.Scan(&stats.TotalMatches)

	// Matches in last 24h - count from recent matches + estimate from type stats
	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threat_matches WHERE matched_at >= ?
	`, since)
	row.Scan(&stats.MatchesLast24h)

	// If we have few recent matches but many total, estimate based on rate
	// For now, also count from threat_type_stats where last_match is within 24h
	var recentTypeMatches int64
	row = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(match_count), 0) FROM threat_type_stats WHERE last_match >= ?
	`, since)
	row.Scan(&recentTypeMatches)

	// Use the larger value (recent table limited to 20, but type stats have full count for recent types)
	if recentTypeMatches > stats.MatchesLast24h {
		stats.MatchesLast24h = recentTypeMatches
	}

	// Matches by type from aggregated table
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, match_count 
		FROM threat_type_stats 
		ORDER BY match_count DESC
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var threatType string
			var cnt int64
			if rows.Scan(&threatType, &cnt) == nil {
				stats.IndicatorsByType[threatType] = cnt
			}
		}
	}

	// Matches by source - still from recent matches (less important for aggregation)
	rows, err = s.db.QueryContext(ctx, `
		SELECT source, COUNT(*) as cnt 
		FROM threat_matches 
		GROUP BY source
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var source string
			var cnt int64
			if rows.Scan(&source, &cnt) == nil {
				stats.IndicatorsBySource[source] = cnt
			}
		}
	}

	stats.LastUpdated = time.Now()
	return stats, nil
}

// CleanupOldThreatMatches removes threat matches older than the retention period
func (s *Storage) CleanupOldThreatMatches(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention).Format(time.RFC3339)

	result, err := s.db.ExecContext(ctx, `
		DELETE FROM threat_matches WHERE matched_at < ?
	`, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// GetTopUsersByCategory returns top users by content category violations with their visited domains
func (s *Storage) GetTopUsersByCategory(ctx context.Context, category string, limit int) ([]*threatintel.CategoryUserStats, error) {
	// Get top users from aggregated table
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, threat_type, match_count
		FROM user_threat_stats
		WHERE threat_type = ?
		ORDER BY match_count DESC
		LIMIT ?
	`, category, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*threatintel.CategoryUserStats
	for rows.Next() {
		var st threatintel.CategoryUserStats
		if err := rows.Scan(&st.UserEmail, &st.Category, &st.MatchCount); err != nil {
			return nil, err
		}
		stats = append(stats, &st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Get top domains for each user from aggregated table
	for _, st := range stats {
		domainRows, err := s.db.QueryContext(ctx, `
			SELECT domain, hit_count
			FROM user_threat_domains
			WHERE user_email = ? AND threat_type = ?
			ORDER BY hit_count DESC
			LIMIT 5
		`, st.UserEmail, category)
		if err != nil {
			continue
		}

		for domainRows.Next() {
			var domain string
			var cnt int
			if domainRows.Scan(&domain, &cnt) == nil {
				st.Domains = append(st.Domains, domain)
			}
		}
		domainRows.Close()
	}

	return stats, nil
}

// lastIndex returns last index of sep in s, or -1
func lastIndex(s string, sep byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == sep {
			return i
		}
	}
	return -1
}

// GetTopUsersByAllCategories returns top users for all content categories (porn, gambling, social, fakenews, torrent, tor)
func (s *Storage) GetTopUsersByAllCategories(ctx context.Context, limit int) (map[string][]*threatintel.CategoryUserStats, error) {
	categories := []string{"porn", "gambling", "social", "fakenews", "torrent", "tor"}
	result := make(map[string][]*threatintel.CategoryUserStats)

	for _, cat := range categories {
		stats, err := s.GetTopUsersByCategory(ctx, cat, limit)
		if err != nil {
			return nil, err
		}
		result[cat] = stats
	}

	return result, nil
}
