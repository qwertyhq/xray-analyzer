//go:build sqlite_legacy

package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// GetThreatStats returns threat intelligence statistics from aggregated tables (cached)
func (s *Storage) GetThreatStats(ctx context.Context) (*threatintel.ThreatStats, error) {
	cacheKey := "threat_stats"

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.(*threatintel.ThreatStats), nil
	}

	stats := &threatintel.ThreatStats{
		IndicatorsByType:   make(map[string]int64),
		IndicatorsBySource: make(map[string]int64),
	}

	// Total matches from aggregated table
	row := s.db.QueryRowContext(ctx, `SELECT total_matches FROM threat_stats_agg WHERE id = 1`)
	row.Scan(&stats.TotalMatches)

	// Matches in last 24h
	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threat_matches WHERE matched_at >= ?
	`, since)
	row.Scan(&stats.MatchesLast24h)

	// Estimate from type stats if more accurate
	var recentTypeMatches int64
	row = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(match_count), 0) FROM threat_type_stats WHERE last_match >= ?
	`, since)
	row.Scan(&recentTypeMatches)

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

	// Matches by source from recent matches
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
	s.cache.Set(cacheKey, stats, CacheTTLMedium)
	return stats, nil
}

// GetTopUsersByCategory returns top users by content category violations with their visited domains (cached)
func (s *Storage) GetTopUsersByCategory(ctx context.Context, category string, limit int) ([]*threatintel.CategoryUserStats, error) {
	cacheKey := fmt.Sprintf("top_users_category_%s_%d", category, limit)

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]*threatintel.CategoryUserStats), nil
	}

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

	// Get top domains for each user
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

// GetTopUsersByAllCategories returns top users for all content categories
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

// GetRecentUsersByCategory returns the most recent unique users who accessed a specific category
// with their latest accessed domains
func (s *Storage) GetRecentUsersByCategory(ctx context.Context, category string, limit int) ([]*threatintel.CategoryUserStats, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	// First try user_threat_stats table (persisted aggregated stats)
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, match_count, last_match
		FROM user_threat_stats
		WHERE threat_type = ?
		ORDER BY last_match DESC
		LIMIT ?
	`, category, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []*threatintel.CategoryUserStats
	for rows.Next() {
		var st threatintel.CategoryUserStats
		var lastMatch string
		if err := rows.Scan(&st.UserEmail, &st.MatchCount, &lastMatch); err != nil {
			return nil, err
		}
		st.Category = category
		stats = append(stats, &st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// If no results from user_threat_stats, fallback to threat_matches table
	if len(stats) == 0 {
		fallbackRows, err := s.db.QueryContext(ctx, `
			SELECT user_email, COUNT(*) as match_count, MAX(matched_at) as last_match
			FROM threat_matches
			WHERE threat_type = ?
			GROUP BY user_email
			ORDER BY last_match DESC
			LIMIT ?
		`, category, limit)
		if err != nil {
			return nil, err
		}
		defer fallbackRows.Close()

		for fallbackRows.Next() {
			var st threatintel.CategoryUserStats
			var lastMatch string
			if err := fallbackRows.Scan(&st.UserEmail, &st.MatchCount, &lastMatch); err != nil {
				return nil, err
			}
			st.Category = category
			stats = append(stats, &st)
		}
	}

	// Get top 5 domains for each user
	for _, st := range stats {
		// First try user_threat_domains
		domainRows, err := s.db.QueryContext(ctx, `
			SELECT domain FROM user_threat_domains
			WHERE user_email = ? AND threat_type = ?
			ORDER BY hit_count DESC
			LIMIT 5
		`, st.UserEmail, category)
		if err != nil {
			continue
		}

		for domainRows.Next() {
			var domain string
			if domainRows.Scan(&domain) == nil {
				st.Domains = append(st.Domains, domain)
			}
		}
		domainRows.Close()

		// If no domains from user_threat_domains, get from threat_matches
		if len(st.Domains) == 0 {
			matchDomainRows, err := s.db.QueryContext(ctx, `
				SELECT DISTINCT destination FROM threat_matches
				WHERE user_email = ? AND threat_type = ?
				ORDER BY matched_at DESC
				LIMIT 5
			`, st.UserEmail, category)
			if err != nil {
				continue
			}

			for matchDomainRows.Next() {
				var domain string
				if matchDomainRows.Scan(&domain) == nil {
					st.Domains = append(st.Domains, domain)
				}
			}
			matchDomainRows.Close()
		}
	}

	return stats, nil
}

// GetUsersByCategory returns users for a category with pagination
func (s *Storage) GetUsersByCategory(ctx context.Context, category string, page, pageSize int) ([]*threatintel.CategoryUserStats, int, error) {
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// Get total count
	var total int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM (
			SELECT user_email FROM user_threat_stats WHERE threat_type = ?
			UNION
			SELECT user_email FROM threat_matches WHERE threat_type = ?
		)
	`, category, category).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get users with pagination - merge from both tables
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, SUM(match_count) as total_matches, MAX(last_match) as last_match
		FROM (
			SELECT user_email, match_count, last_match FROM user_threat_stats WHERE threat_type = ?
			UNION ALL
			SELECT user_email, 1 as match_count, matched_at as last_match FROM threat_matches 
			WHERE threat_type = ? AND user_email NOT IN (SELECT user_email FROM user_threat_stats WHERE threat_type = ?)
		)
		GROUP BY user_email
		ORDER BY last_match DESC
		LIMIT ? OFFSET ?
	`, category, category, category, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var stats []*threatintel.CategoryUserStats
	for rows.Next() {
		var st threatintel.CategoryUserStats
		var lastMatch string
		if err := rows.Scan(&st.UserEmail, &st.MatchCount, &lastMatch); err != nil {
			return nil, 0, err
		}
		st.Category = category
		stats = append(stats, &st)
	}

	// Get domains for each user
	for _, st := range stats {
		domainRows, err := s.db.QueryContext(ctx, `
			SELECT domain FROM user_threat_domains
			WHERE user_email = ? AND threat_type = ?
			ORDER BY hit_count DESC
			LIMIT 5
		`, st.UserEmail, category)
		if err != nil {
			continue
		}

		for domainRows.Next() {
			var domain string
			if domainRows.Scan(&domain) == nil {
				st.Domains = append(st.Domains, domain)
			}
		}
		domainRows.Close()

		// Fallback to threat_matches
		if len(st.Domains) == 0 {
			matchDomainRows, _ := s.db.QueryContext(ctx, `
				SELECT DISTINCT destination FROM threat_matches
				WHERE user_email = ? AND threat_type = ?
				LIMIT 5
			`, st.UserEmail, category)
			if matchDomainRows != nil {
				for matchDomainRows.Next() {
					var domain string
					if matchDomainRows.Scan(&domain) == nil {
						st.Domains = append(st.Domains, domain)
					}
				}
				matchDomainRows.Close()
			}
		}
	}

	return stats, total, nil
}

// GetRecentUsersByAllCategories returns recent users for all content categories
func (s *Storage) GetRecentUsersByAllCategories(ctx context.Context, limit int) (map[string][]*threatintel.CategoryUserStats, error) {
	categories := []string{"porn", "gambling", "social", "fakenews", "torrent", "tor"}
	result := make(map[string][]*threatintel.CategoryUserStats)

	for _, cat := range categories {
		stats, err := s.GetRecentUsersByCategory(ctx, cat, limit)
		if err != nil {
			return nil, err
		}
		result[cat] = stats
	}

	return result, nil
}

// GetHourlyThreatStats returns hourly threat statistics for the last N hours
func (s *Storage) GetHourlyThreatStats(ctx context.Context, hours int) ([]*threatintel.HourlyThreatStats, error) {
	if hours <= 0 {
		hours = 24
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT hour, threat_type, match_count, unique_users
		FROM threat_hourly_stats
		WHERE hour >= datetime('now', '-' || ? || ' hours')
		ORDER BY hour DESC
	`, hours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Aggregate by hour
	hourMap := make(map[string]*threatintel.HourlyThreatStats)
	for rows.Next() {
		var hour, threatType string
		var count, uniqueUsers int64
		if err := rows.Scan(&hour, &threatType, &count, &uniqueUsers); err != nil {
			continue
		}

		if _, ok := hourMap[hour]; !ok {
			hourMap[hour] = &threatintel.HourlyThreatStats{
				Hour:   hour,
				ByType: make(map[string]int64),
			}
		}
		hourMap[hour].ByType[threatType] = count
		hourMap[hour].TotalCount += count
		hourMap[hour].UniqueUsers += uniqueUsers
	}

	return sortHourlyStats(hourMap), nil
}

// GetDailyThreatStats returns daily threat statistics for the last N days
func (s *Storage) GetDailyThreatStats(ctx context.Context, days int) ([]*threatintel.DailyThreatStats, error) {
	if days <= 0 {
		days = 30
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT day, threat_type, match_count, unique_users
		FROM threat_daily_stats
		WHERE day >= date('now', '-' || ? || ' days')
		ORDER BY day DESC
	`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Aggregate by day
	dayMap := make(map[string]*threatintel.DailyThreatStats)
	for rows.Next() {
		var day, threatType string
		var count, uniqueUsers int64
		if err := rows.Scan(&day, &threatType, &count, &uniqueUsers); err != nil {
			continue
		}

		if _, ok := dayMap[day]; !ok {
			dayMap[day] = &threatintel.DailyThreatStats{
				Day:    day,
				ByType: make(map[string]int64),
			}
		}
		dayMap[day].ByType[threatType] = count
		dayMap[day].TotalCount += count
		dayMap[day].UniqueUsers += uniqueUsers
	}

	return sortDailyStats(dayMap), nil
}

// GetTimeAnalytics returns comprehensive time-based analytics
func (s *Storage) GetTimeAnalytics(ctx context.Context) (*threatintel.TimeAnalytics, error) {
	hourly, err := s.GetHourlyThreatStats(ctx, 48)
	if err != nil {
		return nil, err
	}

	daily, err := s.GetDailyThreatStats(ctx, 30)
	if err != nil {
		return nil, err
	}

	analytics := &threatintel.TimeAnalytics{
		HourlyStats: hourly,
		DailyStats:  daily,
		Trends:      make(map[string]float64),
	}

	// Find peak hour
	var maxHourCount int64
	for _, h := range hourly {
		if h.TotalCount > maxHourCount {
			maxHourCount = h.TotalCount
			analytics.PeakHour = h.Hour
		}
	}

	// Find peak day
	var maxDayCount int64
	for _, d := range daily {
		if d.TotalCount > maxDayCount {
			maxDayCount = d.TotalCount
			analytics.PeakDay = d.Day
		}
	}

	// Calculate trends (last 7 days vs previous 7 days)
	analytics.Trends = calculateTrends(daily)

	return analytics, nil
}

// sortHourlyStats converts map to sorted slice
func sortHourlyStats(hourMap map[string]*threatintel.HourlyThreatStats) []*threatintel.HourlyThreatStats {
	result := make([]*threatintel.HourlyThreatStats, 0, len(hourMap))
	for _, stats := range hourMap {
		result = append(result, stats)
	}

	// Sort by hour descending
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Hour < result[j].Hour {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// sortDailyStats converts map to sorted slice
func sortDailyStats(dayMap map[string]*threatintel.DailyThreatStats) []*threatintel.DailyThreatStats {
	result := make([]*threatintel.DailyThreatStats, 0, len(dayMap))
	for _, stats := range dayMap {
		result = append(result, stats)
	}

	// Sort by day descending
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Day < result[j].Day {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// calculateTrends compares last 7 days vs previous 7 days
func calculateTrends(daily []*threatintel.DailyThreatStats) map[string]float64 {
	trends := make(map[string]float64)

	if len(daily) < 14 {
		return trends
	}

	categoryTotals := make(map[string][2]int64) // [recent, previous]
	for i, d := range daily {
		for cat, count := range d.ByType {
			if _, ok := categoryTotals[cat]; !ok {
				categoryTotals[cat] = [2]int64{}
			}
			totals := categoryTotals[cat]
			if i < 7 {
				totals[0] += count // Recent week
			} else if i < 14 {
				totals[1] += count // Previous week
			}
			categoryTotals[cat] = totals
		}
	}

	for cat, totals := range categoryTotals {
		if totals[1] > 0 {
			trends[cat] = float64(totals[0]-totals[1]) / float64(totals[1]) * 100
		} else if totals[0] > 0 {
			trends[cat] = 100
		}
	}

	return trends
}
