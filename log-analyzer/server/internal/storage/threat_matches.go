package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// MaxThreatMatchesPerCategory is the maximum number of recent threat matches to keep per category.
// Aggregated counters (threat_type_stats, threat_hourly_stats, user_threat_stats) keep full history —
// this limit only bounds the `threat_matches` table used for the recent-matches UI list.
// Raised from 100 to 1000 so active categories don't lose visible history within seconds.
const MaxThreatMatchesPerCategory = 1000

// MaxThreatMatches is the total maximum for display queries (legacy, used in GetThreatMatches)
const MaxThreatMatches = 500

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

	// Update hourly stats with proper unique user tracking
	t := time.Now()
	hourKey := t.Format("2006-01-02T15")
	dayKey := t.Format("2006-01-02")

	// Track unique users per hour/threat_type using a separate table
	s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO threat_hourly_users (hour, threat_type, user_email)
		VALUES (?, ?, ?)
	`, hourKey, string(match.ThreatType), match.UserEmail)

	// Update hourly stats - recalculate unique_users from actual data
	s.db.ExecContext(ctx, `
		INSERT INTO threat_hourly_stats (hour, threat_type, match_count, unique_users)
		VALUES (?, ?, 1, 1)
		ON CONFLICT(hour, threat_type) DO UPDATE SET
			match_count = match_count + 1,
			unique_users = (SELECT COUNT(*) FROM threat_hourly_users WHERE hour = ? AND threat_type = ?)
	`, hourKey, string(match.ThreatType), hourKey, string(match.ThreatType))

	// Track unique users per day/threat_type
	s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO threat_daily_users (day, threat_type, user_email)
		VALUES (?, ?, ?)
	`, dayKey, string(match.ThreatType), match.UserEmail)

	// Update daily stats - recalculate unique_users from actual data
	s.db.ExecContext(ctx, `
		INSERT INTO threat_daily_stats (day, threat_type, match_count, unique_users)
		VALUES (?, ?, 1, 1)
		ON CONFLICT(day, threat_type) DO UPDATE SET
			match_count = match_count + 1,
			unique_users = (SELECT COUNT(*) FROM threat_daily_users WHERE day = ? AND threat_type = ?)
	`, dayKey, string(match.ThreatType), dayKey, string(match.ThreatType))

	// Delete old recent records keeping only MaxThreatMatchesPerCategory most recent PER CATEGORY
	// This ensures each category maintains its own history without being displaced by other categories
	_, err = s.db.ExecContext(ctx, `
		DELETE FROM threat_matches 
		WHERE id NOT IN (
			SELECT id FROM (
				SELECT id, ROW_NUMBER() OVER (PARTITION BY threat_type ORDER BY matched_at DESC) as rn
				FROM threat_matches
			) ranked
			WHERE rn <= ?
		)
	`, MaxThreatMatchesPerCategory)

	return err
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

	rows, err := s.db.QueryContext(ctx, `
		SELECT tm.id, tm.user_email, tm.node_id, tm.source_ip, tm.destination,
			   tm.threat_type, tm.source, tm.confidence, tm.description, tm.matched_at,
			   COALESCE(r.username, '') as display_name
		FROM threat_matches tm
		LEFT JOIN remna_users r ON r.username = tm.user_email 
			OR r.description LIKE '%US_ID: ' || tm.user_email
		ORDER BY tm.matched_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanThreatMatchesWithDisplayName(rows)
}

// GetThreatMatchesByUser returns threat matches for a specific user
func (s *Storage) GetThreatMatchesByUser(ctx context.Context, userEmail string, limit int) ([]*threatintel.ThreatMatch, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT tm.id, tm.user_email, tm.node_id, tm.source_ip, tm.destination,
			   tm.threat_type, tm.source, tm.confidence, tm.description, tm.matched_at,
			   COALESCE(r.username, '') as display_name
		FROM threat_matches tm
		LEFT JOIN remna_users r ON r.username = tm.user_email 
			OR r.description LIKE '%US_ID: ' || tm.user_email
		WHERE tm.user_email = ?
		ORDER BY tm.matched_at DESC
		LIMIT ?
	`, userEmail, limit)
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
	rows, err := s.db.QueryContext(ctx, `
		SELECT tm.id, tm.user_email, tm.node_id, tm.source_ip, tm.destination,
			   tm.threat_type, tm.source, tm.confidence, tm.description, tm.matched_at,
			   COALESCE(r.username, '') as display_name
		FROM threat_matches tm
		LEFT JOIN remna_users r ON r.username = tm.user_email 
			OR r.description LIKE '%US_ID: ' || tm.user_email
		WHERE tm.threat_type = ?
		ORDER BY tm.matched_at DESC
		LIMIT ?
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
	domainRows, err := s.db.QueryContext(ctx, `
		SELECT d.user_email, d.domain, d.hit_count, d.last_seen
		FROM user_threat_domains d
		WHERE d.threat_type = ?
		ORDER BY d.last_seen DESC
		LIMIT ?
	`, threatType, limit)
	if err != nil {
		return nil, err
	}
	defer domainRows.Close()

	for domainRows.Next() {
		var m threatintel.ThreatMatch
		var lastSeen string
		var hitCount int

		if err := domainRows.Scan(&m.UserEmail, &m.Destination, &hitCount, &lastSeen); err != nil {
			continue
		}

		m.ThreatType = threatintel.ThreatType(threatType)
		m.Source = threatintel.ThreatSource("historical")
		m.Confidence = 85
		m.Description = fmt.Sprintf("Historical: %d hits", hitCount)
		if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
			m.MatchedAt = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", lastSeen); err == nil {
			m.MatchedAt = t
		}

		matches = append(matches, &m)
	}

	return matches, nil
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

// scanThreatMatches is a helper to scan threat match rows
func scanThreatMatches(rows sqlRows) ([]*threatintel.ThreatMatch, error) {
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

// scanThreatMatchesWithDisplayName is a helper to scan threat match rows with display_name
func scanThreatMatchesWithDisplayName(rows sqlRows) ([]*threatintel.ThreatMatch, error) {
	var matches []*threatintel.ThreatMatch
	for rows.Next() {
		var m threatintel.ThreatMatch
		var threatType, source string
		var matchedAt string
		var displayName string

		err := rows.Scan(&m.ID, &m.UserEmail, &m.NodeID, &m.SourceIP, &m.Destination,
			&threatType, &source, &m.Confidence, &m.Description, &matchedAt, &displayName)
		if err != nil {
			return nil, err
		}

		m.ThreatType = threatintel.ThreatType(threatType)
		m.Source = threatintel.ThreatSource(source)
		m.DisplayName = displayName
		if t, err := time.Parse(time.RFC3339, matchedAt); err == nil {
			m.MatchedAt = t
		}

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
		_, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// Reset aggregated counter
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO threat_stats_agg (id, total_matches, last_updated) 
		VALUES (1, 0, datetime('now'))
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
		"user_ai_profiles",
		"ip_hwid_correlation",
		"blacklist_matches",
	}

	for _, table := range tables {
		_, err := s.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			// Table might not exist, skip
			continue
		}
	}

	return nil
}
