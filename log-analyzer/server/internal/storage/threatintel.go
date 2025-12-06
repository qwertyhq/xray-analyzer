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
