package storage

import (
	"context"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// SaveThreatMatch saves a threat match to the database
func (s *Storage) SaveThreatMatch(ctx context.Context, match *threatintel.ThreatMatch) error {
	now := time.Now().Format(time.RFC3339)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_matches (
			user_email, node_id, source_ip, destination,
			threat_type, source, confidence, description, matched_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, match.UserEmail, match.NodeID, match.SourceIP, match.Destination,
		string(match.ThreatType), string(match.Source), match.Confidence,
		match.Description, now)

	return err
}

// GetThreatMatches returns threat matches since a given time
func (s *Storage) GetThreatMatches(ctx context.Context, since time.Time, limit int) ([]*threatintel.ThreatMatch, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_email, node_id, source_ip, destination,
			   threat_type, source, confidence, description, matched_at
		FROM threat_matches
		WHERE matched_at >= ?
		ORDER BY matched_at DESC
		LIMIT ?
	`, since.Format(time.RFC3339), limit)
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

// GetThreatStats returns threat intelligence statistics from the database
func (s *Storage) GetThreatStats(ctx context.Context) (*threatintel.ThreatStats, error) {
	stats := &threatintel.ThreatStats{
		IndicatorsByType:   make(map[string]int64),
		IndicatorsBySource: make(map[string]int64),
	}

	// Total matches
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM threat_matches`)
	row.Scan(&stats.TotalMatches)

	// Matches in last 24h
	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	row = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM threat_matches WHERE matched_at >= ?`, since)
	row.Scan(&stats.MatchesLast24h)

	// Matches by type
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, COUNT(*) as cnt 
		FROM threat_matches 
		GROUP BY threat_type
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

	// Matches by source
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
	// First get top users
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, threat_type, COUNT(*) as cnt
		FROM threat_matches
		WHERE threat_type = ?
		GROUP BY user_email
		ORDER BY cnt DESC
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

	// Now get top domains for each user
	for _, st := range stats {
		domainRows, err := s.db.QueryContext(ctx, `
			SELECT destination, COUNT(*) as cnt
			FROM threat_matches
			WHERE user_email = ? AND threat_type = ?
			GROUP BY destination
			ORDER BY cnt DESC
			LIMIT 5
		`, st.UserEmail, category)
		if err != nil {
			continue
		}

		for domainRows.Next() {
			var domain string
			var cnt int
			if domainRows.Scan(&domain, &cnt) == nil {
				// Extract just the host part (remove port)
				if idx := lastIndex(domain, ':'); idx > 0 {
					domain = domain[:idx]
				}
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

// GetTopUsersByAllCategories returns top users for all content categories (porn, gambling, social, fakenews)
func (s *Storage) GetTopUsersByAllCategories(ctx context.Context, limit int) (map[string][]*threatintel.CategoryUserStats, error) {
	categories := []string{"porn", "gambling", "social", "fakenews"}
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
