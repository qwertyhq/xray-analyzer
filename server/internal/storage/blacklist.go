package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/models"
)

// RecordBlacklistMatch records a blacklist match.
// match.NodeID is resolved to nodes(id) smallint FK via LookupNodeID.
// match.UserEmail may be any string; non-UUID values are resolved via
// ResolveUserEmailToUUID (remna_users lookup, then SHA-1 fallback).
// match.SourceIP is passed as text; Postgres casts to inet.
func (s *Storage) RecordBlacklistMatch(ctx context.Context, match *models.BlacklistMatch) error {
	nodeID, err := s.LookupNodeID(ctx, match.NodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve node_id: %w", err)
	}

	userUUID, err := s.ResolveUserEmailToUUID(ctx, match.UserEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO blacklist_matches (node_id, user_email, source_ip, destination, matched_rule, timestamp, ts)
		VALUES ($1, $2, $3::inet, $4, $5, $6, $7)
	`, int16(nodeID), userUUID, match.SourceIP, match.Destination, match.MatchedRule, match.Timestamp.UTC(), now)
	return err
}

// GetBlacklistAnalytics returns detailed blacklist analytics for a time period (cached)
func (s *Storage) GetBlacklistAnalytics(ctx context.Context, since time.Time) (*models.BlacklistAnalytics, error) {
	// Cache key based on hours since epoch (cache per hour window)
	hours := int(time.Since(since).Hours())
	cacheKey := fmt.Sprintf("blacklist_analytics_%d", hours)

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.(*models.BlacklistAnalytics), nil
	}

	analytics := &models.BlacklistAnalytics{
		TopDomains:    []models.DomainStats{},
		TopUsers:      []models.UserBlacklistStats{},
		RecentMatches: []models.BlacklistMatchInfo{},
		HourlyStats:   []models.HourlyBlacklistStats{},
	}

	// Total hits in period
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM blacklist_matches WHERE timestamp > $1
	`, since.UTC()).Scan(&analytics.TotalHits)
	if err != nil {
		return nil, fmt.Errorf("count total hits: %w", err)
	}

	// Unique users
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM blacklist_matches WHERE timestamp > $1
	`, since.UTC()).Scan(&analytics.UniqueUsers)
	if err != nil {
		return nil, fmt.Errorf("count unique users: %w", err)
	}

	// Unique domains
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT destination) FROM blacklist_matches WHERE timestamp > $1
	`, since.UTC()).Scan(&analytics.UniqueDomains)
	if err != nil {
		return nil, fmt.Errorf("count unique domains: %w", err)
	}

	// Top domains
	if err := s.loadTopDomains(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	// Top users
	if err := s.loadTopUsers(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	// Recent matches
	if err := s.loadRecentMatches(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	// Hourly stats
	if err := s.loadHourlyBlacklistStats(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	s.cache.Set(cacheKey, analytics, CacheTTLMedium)
	return analytics, nil
}

func (s *Storage) loadTopDomains(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	rows, err := s.pool.Query(ctx, `
		SELECT destination, MAX(matched_rule) as matched_rule, COUNT(*) as hits, COUNT(DISTINCT user_email) as users
		FROM blacklist_matches
		WHERE timestamp > $1
		GROUP BY destination
		ORDER BY hits DESC
		LIMIT 50
	`, since)
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
	return rows.Err()
}

func (s *Storage) loadTopUsers(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	rows, err := s.pool.Query(ctx, `
		SELECT
			bm.user_email::text,
			COALESCE(r.username, bm.user_email::text) as display_name,
			COUNT(*) as hits,
			COUNT(DISTINCT bm.destination) as domains,
			STRING_AGG(DISTINCT bm.destination, ', ') as top_domains,
			COALESCE(MAX(bm.source_ip::text), '') as last_ip
		FROM blacklist_matches bm
		LEFT JOIN remna_users r ON r.uuid = bm.user_email
		WHERE bm.timestamp > $1
		GROUP BY bm.user_email, r.username
		ORDER BY hits DESC
		LIMIT 50
	`, since)
	if err != nil {
		return fmt.Errorf("query top users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u models.UserBlacklistStats
		var topDomainsStr string
		var displayName string
		if err := rows.Scan(&u.UserEmail, &displayName, &u.HitCount, &u.UniqueDomains, &topDomainsStr, &u.LastIP); err != nil {
			return fmt.Errorf("scan user: %w", err)
		}
		u.Username = displayName
		if topDomainsStr != "" {
			domains := strings.Split(topDomainsStr, ", ")
			if len(domains) > 5 {
				domains = domains[:5]
			}
			u.TopDomains = domains
		}
		analytics.TopUsers = append(analytics.TopUsers, u)
	}
	return rows.Err()
}

func (s *Storage) loadRecentMatches(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, bm.user_email::text, bm.source_ip::text, bm.destination, bm.matched_rule, bm.timestamp
		FROM blacklist_matches bm
		JOIN nodes n ON n.id = bm.node_id
		WHERE bm.timestamp > $1
		ORDER BY bm.timestamp DESC
		LIMIT 100
	`, since)
	if err != nil {
		return fmt.Errorf("query recent matches: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m models.BlacklistMatchInfo
		var ts *time.Time
		if err := rows.Scan(&m.NodeID, &m.UserEmail, &m.SourceIP, &m.Destination, &m.MatchedRule, &ts); err != nil {
			return fmt.Errorf("scan match: %w", err)
		}
		if ts != nil {
			m.Timestamp = *ts
		}
		analytics.RecentMatches = append(analytics.RecentMatches, m)
	}
	return rows.Err()
}

func (s *Storage) loadHourlyBlacklistStats(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	rows, err := s.pool.Query(ctx, `
		SELECT date_trunc('hour', timestamp) AS hour, COUNT(*) as hits
		FROM blacklist_matches
		WHERE timestamp > $1 AND timestamp IS NOT NULL
		GROUP BY hour
		ORDER BY hour
	`, since)
	if err != nil {
		return fmt.Errorf("query hourly stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h models.HourlyBlacklistStats
		if err := rows.Scan(&h.Hour, &h.HitCount); err != nil {
			return fmt.Errorf("scan hourly: %w", err)
		}
		analytics.HourlyStats = append(analytics.HourlyStats, h)
	}
	return rows.Err()
}

// GetUserBlacklistDetails returns detailed blacklist info for a user
func (s *Storage) GetUserBlacklistDetails(ctx context.Context, userEmail string, since time.Time) ([]models.BlacklistMatchInfo, error) {
	userUUID, err := uuid.Parse(userEmail)
	if err != nil {
		return nil, nil // non-UUID user, no results
	}

	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, bm.source_ip::text, bm.destination, bm.matched_rule, bm.timestamp
		FROM blacklist_matches bm
		JOIN nodes n ON n.id = bm.node_id
		WHERE bm.user_email = $1 AND bm.timestamp > $2
		ORDER BY bm.timestamp DESC
		LIMIT 500
	`, userUUID, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []models.BlacklistMatchInfo
	for rows.Next() {
		var m models.BlacklistMatchInfo
		var ts *time.Time
		if err := rows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &ts); err != nil {
			return nil, err
		}
		if ts != nil {
			m.Timestamp = *ts
		}
		matches = append(matches, m)
	}
	return matches, rows.Err()
}

// extractNumericPartBl extracts numeric suffix from a string like "prefix_123"
func extractNumericPartBl(s string) string {
	if idx := strings.LastIndex(s, "_"); idx != -1 && idx < len(s)-1 {
		part := s[idx+1:]
		if _, err := strconv.Atoi(part); err == nil {
			return part
		}
	}
	if _, err := strconv.Atoi(s); err == nil {
		return s
	}
	return ""
}

// buildBlacklistSearchUUIDs builds user UUID list to search for in blacklist_matches.
// user_email is now uuid in the DB.
func (s *Storage) buildBlacklistSearchUUIDs(ctx context.Context, userEmail string) []uuid.UUID {
	var uuids []uuid.UUID
	// Try direct UUID parse first
	if u, err := uuid.Parse(userEmail); err == nil {
		uuids = append(uuids, u)
	}
	// Try to find UUID via remna_users username
	var remnaUUID uuid.UUID
	if err := s.pool.QueryRow(ctx,
		`SELECT uuid FROM remna_users WHERE username = $1 OR us_id = $1 LIMIT 1`,
		userEmail,
	).Scan(&remnaUUID); err == nil {
		found := false
		for _, u := range uuids {
			if u == remnaUUID {
				found = true
				break
			}
		}
		if !found {
			uuids = append(uuids, remnaUUID)
		}
	}
	return uuids
}

// GetUserBlacklistMatches returns paginated blacklist matches for a user
func (s *Storage) GetUserBlacklistMatches(ctx context.Context, userEmail string, since time.Time, page, pageSize int) (*models.PaginatedBlacklistMatchesResponse, error) {
	offset := (page - 1) * pageSize

	searchUUIDs := s.buildBlacklistSearchUUIDs(ctx, userEmail)
	if len(searchUUIDs) == 0 {
		return &models.PaginatedBlacklistMatchesResponse{
			Matches:    []models.BlacklistMatchInfo{},
			Total:      0,
			Page:       page,
			PageSize:   pageSize,
			TotalPages: 1,
		}, nil
	}

	// Get total count
	var total int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM blacklist_matches
		WHERE user_email = ANY($1) AND timestamp > $2
	`, searchUUIDs, since.UTC()).Scan(&total)
	if err != nil {
		return nil, err
	}

	// Get paginated results
	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, bm.source_ip::text, bm.destination, bm.matched_rule, bm.timestamp
		FROM blacklist_matches bm
		JOIN nodes n ON n.id = bm.node_id
		WHERE bm.user_email = ANY($1) AND bm.timestamp > $2
		ORDER BY bm.timestamp DESC
		LIMIT $3 OFFSET $4
	`, searchUUIDs, since.UTC(), pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []models.BlacklistMatchInfo
	for rows.Next() {
		var m models.BlacklistMatchInfo
		var ts *time.Time
		if err := rows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &ts); err != nil {
			return nil, err
		}
		if ts != nil {
			m.Timestamp = *ts
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

	return &models.PaginatedBlacklistMatchesResponse{
		Matches:    matches,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}
