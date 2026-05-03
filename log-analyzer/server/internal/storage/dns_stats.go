package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// ==================== DNS Analysis Functions ====================

// UpdateDNSDomainStats updates statistics for a domain
func (s *Storage) UpdateDNSDomainStats(ctx context.Context, domain string, threatType string, source string) error {
	// Check if domain exists
	var existingTypes, existingSources sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT threat_types, sources FROM dns_domain_stats WHERE domain = $1
	`, domain).Scan(&existingTypes, &existingSources)

	if err == sql.ErrNoRows {
		// New domain
		types, _ := json.Marshal([]string{threatType})
		sources, _ := json.Marshal([]string{source})
		categoryHits, _ := json.Marshal(map[string]int{threatType: 1})

		_, err = s.db.ExecContext(ctx, `
			INSERT INTO dns_domain_stats (domain, total_hits, unique_users, threat_types, sources, first_seen, last_seen, category_hits)
			VALUES ($1, 1, 1, $2, $3, NOW(), NOW(), $4)
		`, domain, string(types), string(sources), string(categoryHits))
		return err
	}
	if err != nil {
		return err
	}

	// Update existing
	var threatTypes []string
	var sourcesList []string
	if existingTypes.Valid {
		json.Unmarshal([]byte(existingTypes.String), &threatTypes)
	}
	if existingSources.Valid {
		json.Unmarshal([]byte(existingSources.String), &sourcesList)
	}

	// Add new type/source if not present
	if !contains(threatTypes, threatType) {
		threatTypes = append(threatTypes, threatType)
	}
	if !contains(sourcesList, source) {
		sourcesList = append(sourcesList, source)
	}

	typesJSON, _ := json.Marshal(threatTypes)
	sourcesJSON, _ := json.Marshal(sourcesList)

	_, err = s.db.ExecContext(ctx, `
		UPDATE dns_domain_stats SET
			total_hits = total_hits + 1,
			threat_types = $1,
			sources = $2,
			last_seen = NOW()
		WHERE domain = $3
	`, string(typesJSON), string(sourcesJSON), domain)

	return err
}

// contains is a helper function to check if a slice contains an item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// UpdateDNSHourlyStats updates hourly DNS statistics
func (s *Storage) UpdateDNSHourlyStats(ctx context.Context, blocked bool) error {
	hour := time.Now().Format("2006-01-02T15")

	blockedInc := 0
	if blocked {
		blockedInc = 1
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dns_hourly_stats (hour, total_queries, blocked_queries, unique_users)
		VALUES ($1, 1, $2, 1)
		ON CONFLICT (hour) DO UPDATE SET
			total_queries = dns_hourly_stats.total_queries + 1,
			blocked_queries = dns_hourly_stats.blocked_queries + $3
	`, hour, blockedInc, blockedInc)

	return err
}

// UpdateDNSDailyStats updates daily DNS statistics
func (s *Storage) UpdateDNSDailyStats(ctx context.Context, blocked bool) error {
	day := time.Now().Format("2006-01-02")

	blockedInc := 0
	if blocked {
		blockedInc = 1
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dns_daily_stats (day, total_queries, blocked_queries, unique_users)
		VALUES ($1, 1, $2, 1)
		ON CONFLICT (day) DO UPDATE SET
			total_queries = dns_daily_stats.total_queries + 1,
			blocked_queries = dns_daily_stats.blocked_queries + $3
	`, day, blockedInc, blockedInc)

	return err
}

// UpdateUserDNSStats updates DNS statistics for a user
func (s *Storage) UpdateUserDNSStats(ctx context.Context, email string, domain string, blocked bool) error {
	blockedInc := 0
	if blocked {
		blockedInc = 1
	}

	// user_dns_stats.user_email is uuid NOT NULL.
	userUUID, err := s.ResolveUserEmailToUUID(ctx, email)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	// Get existing top domains
	var existingDomains sql.NullString
	s.pool.QueryRow(ctx, `SELECT top_domains FROM user_dns_stats WHERE user_email = $1`, userUUID).Scan(&existingDomains)

	var topDomains []string
	if existingDomains.Valid {
		json.Unmarshal([]byte(existingDomains.String), &topDomains)
	}

	// Add domain if blocked and not already in top 10
	if blocked && !contains(topDomains, domain) {
		if len(topDomains) < 10 {
			topDomains = append(topDomains, domain)
		}
	}

	domainsJSON, _ := json.Marshal(topDomains)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_dns_stats (user_email, total_queries, blocked_queries, top_domains, updated_at)
		VALUES ($1, 1, $2, $3, NOW())
		ON CONFLICT (user_email) DO UPDATE SET
			total_queries = user_dns_stats.total_queries + 1,
			blocked_queries = user_dns_stats.blocked_queries + $4,
			top_domains = $5,
			updated_at = NOW()
	`, userUUID, blockedInc, string(domainsJSON), blockedInc, string(domainsJSON))

	return err
}

// RecordDNSQuery records a DNS query for analytics
func (s *Storage) RecordDNSQuery(ctx context.Context, email, domain, threatType, source string, blocked bool) error {
	// Update all relevant stats
	if blocked {
		s.UpdateDNSDomainStats(ctx, domain, threatType, source)
	}
	s.UpdateDNSHourlyStats(ctx, blocked)
	s.UpdateDNSDailyStats(ctx, blocked)
	if email != "" {
		s.UpdateUserDNSStats(ctx, email, domain, blocked)
	}
	return nil
}

// GetDNSQueryStats returns DNS query statistics
func (s *Storage) GetDNSQueryStats(ctx context.Context) (*threatintel.DNSQueryStats, error) {
	stats := &threatintel.DNSQueryStats{
		TopBlockedTypes: make(map[string]int),
		TopDomains:      []*threatintel.DomainStats{},
		HourlyStats:     []*threatintel.HourlyDNS{},
		DailyStats:      []*threatintel.DailyDNS{},
	}

	// Get totals from daily stats (sum last 30 days)
	row := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(total_queries), 0), COALESCE(SUM(blocked_queries), 0)
		FROM dns_daily_stats
		WHERE day > TO_CHAR(NOW() - INTERVAL '30 days', 'YYYY-MM-DD')
	`)
	row.Scan(&stats.TotalQueries, &stats.BlockedQueries)

	if stats.TotalQueries > 0 {
		stats.BlockRate = float64(stats.BlockedQueries) / float64(stats.TotalQueries) * 100
	}

	// Get unique domains count
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_domain_stats`).Scan(&stats.UniqueDomainsBad)

	// Get top blocked domains
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain, total_hits, unique_users, threat_types, sources, first_seen, last_seen, risk_level
		FROM dns_domain_stats
		ORDER BY total_hits DESC
		LIMIT 20
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			ds := &threatintel.DomainStats{
				ThreatTypes:  []string{},
				Sources:      []string{},
				CategoryHits: make(map[string]int),
			}
			var threatTypes, sources sql.NullString
			var firstSeen, lastSeen sql.NullTime
			var riskLevel string

			if rows.Scan(&ds.Domain, &ds.TotalHits, &ds.UniqueUsers, &threatTypes, &sources, &firstSeen, &lastSeen, &riskLevel) == nil {
				if threatTypes.Valid {
					json.Unmarshal([]byte(threatTypes.String), &ds.ThreatTypes)
				}
				if sources.Valid {
					json.Unmarshal([]byte(sources.String), &ds.Sources)
				}
				if firstSeen.Valid {
					ds.FirstSeen = firstSeen.Time
				}
				if lastSeen.Valid {
					ds.LastSeen = lastSeen.Time
				}
				ds.RiskLevel = threatintel.RiskLevel(riskLevel)
				stats.TopDomains = append(stats.TopDomains, ds)
			}
		}
	}

	// Get top blocked types from threat_type_stats
	typeRows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, match_count FROM threat_type_stats ORDER BY match_count DESC LIMIT 10
	`)
	if err == nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var threatType string
			var count int
			if typeRows.Scan(&threatType, &count) == nil {
				stats.TopBlockedTypes[threatType] = count
			}
		}
	}

	// Get hourly stats (last 24 hours)
	hourlyRows, err := s.db.QueryContext(ctx, `
		SELECT hour, total_queries, blocked_queries, unique_users
		FROM dns_hourly_stats
		WHERE hour >= TO_CHAR(NOW() - INTERVAL '24 hours', 'YYYY-MM-DD"T"HH24')
		ORDER BY hour ASC
	`)
	if err == nil {
		defer hourlyRows.Close()
		for hourlyRows.Next() {
			h := &threatintel.HourlyDNS{}
			hourlyRows.Scan(&h.Hour, &h.TotalQueries, &h.BlockedQueries, &h.UniqueUsers)
			stats.HourlyStats = append(stats.HourlyStats, h)
		}
	}

	// Get daily stats (last 30 days)
	dailyRows, err := s.db.QueryContext(ctx, `
		SELECT day, total_queries, blocked_queries, unique_users
		FROM dns_daily_stats
		WHERE day >= TO_CHAR(NOW() - INTERVAL '30 days', 'YYYY-MM-DD')
		ORDER BY day ASC
	`)
	if err == nil {
		defer dailyRows.Close()
		for dailyRows.Next() {
			d := &threatintel.DailyDNS{}
			dailyRows.Scan(&d.Day, &d.TotalQueries, &d.BlockedQueries, &d.UniqueUsers)
			stats.DailyStats = append(stats.DailyStats, d)
		}
	}

	return stats, nil
}

// GetTopUsersByDNS returns users with most DNS activity
func (s *Storage) GetTopUsersByDNS(ctx context.Context, limit int) ([]*threatintel.UserDNSStats, error) {
	var users []*threatintel.UserDNSStats

	rows, err := s.pool.Query(ctx, `
		SELECT user_email::text, total_queries, blocked_queries, COALESCE(top_domains, '')
		FROM user_dns_stats
		ORDER BY blocked_queries DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		u := &threatintel.UserDNSStats{
			TopDomains: []string{},
		}
		var topDomainsStr string

		if rows.Scan(&u.UserEmail, &u.TotalQueries, &u.BlockedQueries, &topDomainsStr) == nil {
			if u.TotalQueries > 0 {
				u.BlockRate = float64(u.BlockedQueries) / float64(u.TotalQueries) * 100
			}
			if topDomainsStr != "" {
				json.Unmarshal([]byte(topDomainsStr), &u.TopDomains)
			}
			// Calculate risk level based on block rate
			switch {
			case u.BlockRate >= 30:
				u.RiskLevel = threatintel.RiskLevelCritical
			case u.BlockRate >= 15:
				u.RiskLevel = threatintel.RiskLevelHigh
			case u.BlockRate >= 5:
				u.RiskLevel = threatintel.RiskLevelMedium
			default:
				u.RiskLevel = threatintel.RiskLevelLow
			}
			users = append(users, u)
		}
	}

	return users, nil
}

// GetDNSAnalysisSummary returns comprehensive DNS analysis summary
func (s *Storage) GetDNSAnalysisSummary(ctx context.Context) (*threatintel.DNSAnalysisSummary, error) {
	summary := &threatintel.DNSAnalysisSummary{
		CategoryBreakdown: make(map[string]int),
	}

	// Get query stats
	queryStats, err := s.GetDNSQueryStats(ctx)
	if err != nil {
		return nil, err
	}
	summary.QueryStats = queryStats
	summary.TopBadDomains = queryStats.TopDomains

	// Get top users by DNS
	topUsers, err := s.GetTopUsersByDNS(ctx, 10)
	if err == nil {
		summary.TopUsersByDNS = topUsers
	}

	// Get category breakdown
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, match_count FROM threat_type_stats ORDER BY match_count DESC
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var category string
			var count int
			if rows.Scan(&category, &count) == nil {
				summary.CategoryBreakdown[category] = count
			}
		}
	}

	// Calculate trend
	var recent, previous int64
	s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(blocked_queries), 0) FROM dns_daily_stats
		WHERE day >= TO_CHAR(NOW() - INTERVAL '7 days', 'YYYY-MM-DD')
	`).Scan(&recent)
	s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(blocked_queries), 0) FROM dns_daily_stats
		WHERE day >= TO_CHAR(NOW() - INTERVAL '14 days', 'YYYY-MM-DD')
		  AND day < TO_CHAR(NOW() - INTERVAL '7 days', 'YYYY-MM-DD')
	`).Scan(&previous)

	if recent > previous+100 {
		summary.TrendDirection = "up"
	} else if recent < previous-100 {
		summary.TrendDirection = "down"
	} else {
		summary.TrendDirection = "stable"
	}

	// Calculate overall DNS risk score
	if queryStats.BlockRate > 0 {
		summary.RiskScore = min(int(queryStats.BlockRate*2), 100)
	}

	return summary, nil
}
