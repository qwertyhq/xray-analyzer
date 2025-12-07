package storage

import (
	"context"
	"database/sql"
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

	// Update hourly stats (format: 2025-12-07T14)
	t := time.Now()
	hourKey := t.Format("2006-01-02T15")
	dayKey := t.Format("2006-01-02")

	s.db.ExecContext(ctx, `
		INSERT INTO threat_hourly_stats (hour, threat_type, match_count, unique_users)
		VALUES (?, ?, 1, 1)
		ON CONFLICT(hour, threat_type) DO UPDATE SET
			match_count = match_count + 1
	`, hourKey, string(match.ThreatType))

	// Update daily stats
	s.db.ExecContext(ctx, `
		INSERT INTO threat_daily_stats (day, threat_type, match_count, unique_users)
		VALUES (?, ?, 1, 1)
		ON CONFLICT(day, threat_type) DO UPDATE SET
			match_count = match_count + 1
	`, dayKey, string(match.ThreatType))

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

// GetHourlyThreatStats returns hourly threat statistics for the last N hours
func (s *Storage) GetHourlyThreatStats(ctx context.Context, hours int) ([]*threatintel.HourlyThreatStats, error) {
	if hours <= 0 {
		hours = 24
	}

	// Get all hourly data within the range
	rows, err := s.db.QueryContext(ctx, `
		SELECT hour, threat_type, match_count
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
		var count int64
		if err := rows.Scan(&hour, &threatType, &count); err != nil {
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
	}

	// Convert to slice and sort
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

	return result, nil
}

// GetDailyThreatStats returns daily threat statistics for the last N days
func (s *Storage) GetDailyThreatStats(ctx context.Context, days int) ([]*threatintel.DailyThreatStats, error) {
	if days <= 0 {
		days = 30
	}

	// Get all daily data within the range
	rows, err := s.db.QueryContext(ctx, `
		SELECT day, threat_type, match_count
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
		var count int64
		if err := rows.Scan(&day, &threatType, &count); err != nil {
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
	}

	// Convert to slice and sort
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

	return result, nil
}

// GetTimeAnalytics returns comprehensive time-based analytics
func (s *Storage) GetTimeAnalytics(ctx context.Context) (*threatintel.TimeAnalytics, error) {
	hourly, err := s.GetHourlyThreatStats(ctx, 48) // Last 48 hours
	if err != nil {
		return nil, err
	}

	daily, err := s.GetDailyThreatStats(ctx, 30) // Last 30 days
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

	// Calculate trends (compare last 7 days vs previous 7 days)
	if len(daily) >= 14 {
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
				analytics.Trends[cat] = float64(totals[0]-totals[1]) / float64(totals[1]) * 100
			} else if totals[0] > 0 {
				analytics.Trends[cat] = 100 // New category
			}
		}
	}

	return analytics, nil
}

// SaveGeoStats updates geographic statistics for a threat match
func (s *Storage) SaveGeoStats(ctx context.Context, countryCode, countryName, threatType, userEmail string) error {
	if countryCode == "" {
		return nil // Skip if no geo data
	}

	// Update threat_geo_stats
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_geo_stats (country_code, country_name, threat_type, match_count, unique_users, last_match)
		VALUES (?, ?, ?, 1, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(country_code, threat_type) DO UPDATE SET
			match_count = match_count + 1,
			unique_users = (
				SELECT COUNT(DISTINCT user_email) FROM threat_matches 
				WHERE threat_type = ? 
				AND source_ip IN (SELECT DISTINCT source_ip FROM user_locations WHERE country_code = ?)
			),
			last_match = CURRENT_TIMESTAMP
	`, countryCode, countryName, threatType, threatType, countryCode)

	return err
}

// SaveUserLocation tracks user access from a specific location
func (s *Storage) SaveUserLocation(ctx context.Context, userEmail, countryCode, countryName, city string) error {
	if countryCode == "" || userEmail == "" {
		return nil
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_locations (user_email, country_code, country_name, city, last_seen, request_count)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
		ON CONFLICT(user_email, country_code) DO UPDATE SET
			city = COALESCE(?, city),
			last_seen = CURRENT_TIMESTAMP,
			request_count = request_count + 1
	`, userEmail, countryCode, countryName, city, city)

	return err
}

// GetGeoStats returns geographic threat statistics
func (s *Storage) GetGeoStats(ctx context.Context, limit int) ([]*threatintel.GeoStats, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT country_code, country_name, threat_type, match_count, unique_users, last_match
		FROM threat_geo_stats
		ORDER BY match_count DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*threatintel.GeoStats
	for rows.Next() {
		stat := &threatintel.GeoStats{}
		var lastMatch sql.NullTime
		if err := rows.Scan(&stat.CountryCode, &stat.CountryName, &stat.ThreatType,
			&stat.MatchCount, &stat.UniqueUsers, &lastMatch); err != nil {
			continue
		}
		if lastMatch.Valid {
			stat.LastMatch = lastMatch.Time
		}
		result = append(result, stat)
	}

	return result, nil
}

// GetGeoSummary returns aggregated geographic analysis
func (s *Storage) GetGeoSummary(ctx context.Context) (*threatintel.GeoSummary, error) {
	summary := &threatintel.GeoSummary{
		TopCountries: []*threatintel.CountryStats{},
		ByThreatType: make(map[string][]*threatintel.GeoStats),
	}

	// Get total unique countries
	var totalCountries int
	s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT country_code) FROM threat_geo_stats`).Scan(&totalCountries)
	summary.TotalCountries = totalCountries

	// Get top countries (aggregated across all threat types)
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			country_code, 
			country_name,
			SUM(match_count) as total_matches,
			SUM(unique_users) as unique_users,
			(SELECT threat_type FROM threat_geo_stats g2 
			 WHERE g2.country_code = threat_geo_stats.country_code 
			 ORDER BY match_count DESC LIMIT 1) as top_threat
		FROM threat_geo_stats
		GROUP BY country_code, country_name
		ORDER BY total_matches DESC
		LIMIT 10
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			cs := &threatintel.CountryStats{}
			var topThreat sql.NullString
			if err := rows.Scan(&cs.CountryCode, &cs.CountryName, &cs.TotalMatches, &cs.UniqueUsers, &topThreat); err != nil {
				continue
			}
			if topThreat.Valid {
				cs.TopThreat = topThreat.String
			}
			summary.TopCountries = append(summary.TopCountries, cs)
		}
	}

	// Get stats by threat type
	rows2, err := s.db.QueryContext(ctx, `
		SELECT country_code, country_name, threat_type, match_count, unique_users, last_match
		FROM threat_geo_stats
		ORDER BY threat_type, match_count DESC
	`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			stat := &threatintel.GeoStats{}
			var lastMatch sql.NullTime
			if err := rows2.Scan(&stat.CountryCode, &stat.CountryName, &stat.ThreatType,
				&stat.MatchCount, &stat.UniqueUsers, &lastMatch); err != nil {
				continue
			}
			if lastMatch.Valid {
				stat.LastMatch = lastMatch.Time
			}
			summary.ByThreatType[stat.ThreatType] = append(summary.ByThreatType[stat.ThreatType], stat)
		}
	}

	return summary, nil
}

// GetUserLocations returns location history for users
func (s *Storage) GetUserLocations(ctx context.Context, userEmail string, limit int) ([]*threatintel.UserLocation, error) {
	if limit <= 0 {
		limit = 10
	}

	var rows *sql.Rows
	var err error

	if userEmail != "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT user_email, country_code, country_name, city, last_seen, request_count
			FROM user_locations
			WHERE user_email = ?
			ORDER BY last_seen DESC
			LIMIT ?
		`, userEmail, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT user_email, country_code, country_name, city, last_seen, request_count
			FROM user_locations
			ORDER BY last_seen DESC
			LIMIT ?
		`, limit)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*threatintel.UserLocation
	for rows.Next() {
		loc := &threatintel.UserLocation{}
		var city sql.NullString
		if err := rows.Scan(&loc.UserEmail, &loc.CountryCode, &loc.CountryName, &city, &loc.LastSeen, &loc.RequestCount); err != nil {
			continue
		}
		if city.Valid {
			loc.City = city.String
		}
		result = append(result, loc)
	}

	return result, nil
}
