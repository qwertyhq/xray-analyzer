package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// RecordBlacklistMatch records a blacklist match
func (s *Storage) RecordBlacklistMatch(ctx context.Context, match *models.BlacklistMatch) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO blacklist_matches (node_id, user_email, source_ip, destination, matched_rule, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`, match.NodeID, match.UserEmail, match.SourceIP, match.Destination, match.MatchedRule, match.Timestamp.UTC().Format(time.RFC3339))
	return err
}

// GetBlacklistAnalytics returns detailed blacklist analytics for a time period
func (s *Storage) GetBlacklistAnalytics(ctx context.Context, since time.Time) (*models.BlacklistAnalytics, error) {
	analytics := &models.BlacklistAnalytics{
		TopDomains:    []models.DomainStats{},
		TopUsers:      []models.UserBlacklistStats{},
		RecentMatches: []models.BlacklistMatchInfo{},
		HourlyStats:   []models.HourlyBlacklistStats{},
	}

	sinceStr := since.UTC().Format(time.RFC3339)

	// Total hits in period
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM blacklist_matches WHERE timestamp > ?
	`, sinceStr).Scan(&analytics.TotalHits)
	if err != nil {
		return nil, fmt.Errorf("count total hits: %w", err)
	}

	// Unique users
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM blacklist_matches WHERE timestamp > ?
	`, sinceStr).Scan(&analytics.UniqueUsers)
	if err != nil {
		return nil, fmt.Errorf("count unique users: %w", err)
	}

	// Unique domains
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT destination) FROM blacklist_matches WHERE timestamp > ?
	`, sinceStr).Scan(&analytics.UniqueDomains)
	if err != nil {
		return nil, fmt.Errorf("count unique domains: %w", err)
	}

	// Top domains
	if err := s.loadTopDomains(ctx, sinceStr, analytics); err != nil {
		return nil, err
	}

	// Top users
	if err := s.loadTopUsers(ctx, sinceStr, analytics); err != nil {
		return nil, err
	}

	// Recent matches
	if err := s.loadRecentMatches(ctx, sinceStr, analytics); err != nil {
		return nil, err
	}

	// Hourly stats
	if err := s.loadHourlyBlacklistStats(ctx, sinceStr, analytics); err != nil {
		return nil, err
	}

	return analytics, nil
}

func (s *Storage) loadTopDomains(ctx context.Context, sinceStr string, analytics *models.BlacklistAnalytics) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT destination, matched_rule, COUNT(*) as hits, COUNT(DISTINCT user_email) as users
		FROM blacklist_matches
		WHERE timestamp > ?
		GROUP BY destination
		ORDER BY hits DESC
		LIMIT 50
	`, sinceStr)
	if err != nil {
		return fmt.Errorf("query top domains: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var d models.DomainStats
		if err := rows.Scan(&d.Domain, &d.MatchedRule, &d.HitCount, &d.UniqueUsers); err != nil {
			return fmt.Errorf("scan domain: %w", err)
		}
		analytics.TopDomains = append(analytics.TopDomains, d)
	}
	return nil
}

func (s *Storage) loadTopUsers(ctx context.Context, sinceStr string, analytics *models.BlacklistAnalytics) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			bm.user_email, 
			COUNT(*) as hits, 
			COUNT(DISTINCT bm.destination) as domains,
			GROUP_CONCAT(DISTINCT bm.destination) as top_domains,
			COALESCE(MAX(bm.source_ip), '') as last_ip
		FROM blacklist_matches bm
		WHERE bm.timestamp > ?
		GROUP BY bm.user_email
		ORDER BY hits DESC
		LIMIT 50
	`, sinceStr)
	if err != nil {
		return fmt.Errorf("query top users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u models.UserBlacklistStats
		var topDomainsStr string
		if err := rows.Scan(&u.UserEmail, &u.HitCount, &u.UniqueDomains, &topDomainsStr, &u.LastIP); err != nil {
			return fmt.Errorf("scan user: %w", err)
		}
		if topDomainsStr != "" {
			domains := strings.Split(topDomainsStr, ",")
			if len(domains) > 5 {
				domains = domains[:5]
			}
			u.TopDomains = domains
		}
		analytics.TopUsers = append(analytics.TopUsers, u)
	}
	return nil
}

func (s *Storage) loadRecentMatches(ctx context.Context, sinceStr string, analytics *models.BlacklistAnalytics) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, user_email, source_ip, destination, matched_rule, COALESCE(timestamp, '') as timestamp
		FROM blacklist_matches
		WHERE timestamp > ?
		ORDER BY timestamp DESC
		LIMIT 100
	`, sinceStr)
	if err != nil {
		return fmt.Errorf("query recent matches: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m models.BlacklistMatchInfo
		var tsStr string
		if err := rows.Scan(&m.NodeID, &m.UserEmail, &m.SourceIP, &m.Destination, &m.MatchedRule, &tsStr); err != nil {
			return fmt.Errorf("scan match: %w", err)
		}
		m.Timestamp = parseDateTime(tsStr)
		analytics.RecentMatches = append(analytics.RecentMatches, m)
	}
	return nil
}

func (s *Storage) loadHourlyBlacklistStats(ctx context.Context, sinceStr string, analytics *models.BlacklistAnalytics) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as hits
		FROM blacklist_matches
		WHERE timestamp > ? AND timestamp IS NOT NULL
		GROUP BY hour
		HAVING hour IS NOT NULL
		ORDER BY hour
	`, sinceStr)
	if err != nil {
		return fmt.Errorf("query hourly stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h models.HourlyBlacklistStats
		var hourStr string
		if err := rows.Scan(&hourStr, &h.HitCount); err != nil {
			return fmt.Errorf("scan hourly: %w", err)
		}
		h.Hour = parseDateTime(hourStr)
		analytics.HourlyStats = append(analytics.HourlyStats, h)
	}
	return nil
}

// GetUserBlacklistDetails returns detailed blacklist info for a user
func (s *Storage) GetUserBlacklistDetails(ctx context.Context, userEmail string, since time.Time) ([]models.BlacklistMatchInfo, error) {
	sinceStr := since.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, source_ip, destination, matched_rule, COALESCE(timestamp, '') as timestamp
		FROM blacklist_matches
		WHERE user_email = ? AND timestamp > ?
		ORDER BY timestamp DESC
		LIMIT 500
	`, userEmail, sinceStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []models.BlacklistMatchInfo
	for rows.Next() {
		var m models.BlacklistMatchInfo
		var tsStr string
		if err := rows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &tsStr); err != nil {
			return nil, err
		}
		m.Timestamp = parseDateTime(tsStr)
		matches = append(matches, m)
	}
	return matches, nil
}
