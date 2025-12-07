package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

// SaveAnomaly saves a detected anomaly to the database
func (s *Storage) SaveAnomaly(ctx context.Context, anomaly *threatintel.Anomaly) error {
	detailsJSON := "{}"
	if anomaly.Details != nil {
		if data, err := json.Marshal(anomaly.Details); err == nil {
			detailsJSON = string(data)
		}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO anomalies (id, type, severity, user_email, description, details, detected_at, resolved)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, anomaly.ID, anomaly.Type, anomaly.Severity, anomaly.UserEmail, anomaly.Description, detailsJSON, anomaly.DetectedAt, anomaly.Resolved)

	return err
}

// GetAnomalies returns recent anomalies
func (s *Storage) GetAnomalies(ctx context.Context, limit int, includeResolved bool) ([]*threatintel.Anomaly, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, type, severity, user_email, description, details, detected_at, resolved
		FROM anomalies
	`
	if !includeResolved {
		query += " WHERE resolved = 0"
	}
	query += " ORDER BY detected_at DESC LIMIT ?"

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*threatintel.Anomaly
	for rows.Next() {
		a := &threatintel.Anomaly{}
		var userEmail sql.NullString
		var detailsJSON string
		var resolved int

		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &userEmail, &a.Description, &detailsJSON, &a.DetectedAt, &resolved); err != nil {
			continue
		}

		if userEmail.Valid {
			a.UserEmail = userEmail.String
		}
		a.Resolved = resolved == 1

		if detailsJSON != "" && detailsJSON != "{}" {
			json.Unmarshal([]byte(detailsJSON), &a.Details)
		}

		result = append(result, a)
	}

	return result, nil
}

// GetAnomalySummary returns anomaly statistics
func (s *Storage) GetAnomalySummary(ctx context.Context) (*threatintel.AnomalySummary, error) {
	summary := &threatintel.AnomalySummary{
		BySeverity:      make(map[string]int),
		ByType:          make(map[string]int),
		RecentAnomalies: []*threatintel.Anomaly{},
	}

	// Count by severity
	rows, err := s.db.QueryContext(ctx, `
		SELECT severity, COUNT(*) FROM anomalies WHERE resolved = 0 GROUP BY severity
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var severity string
			var count int
			if rows.Scan(&severity, &count) == nil {
				summary.BySeverity[severity] = count
				summary.TotalAnomalies += count
			}
		}
	}

	// Count by type
	rows2, err := s.db.QueryContext(ctx, `
		SELECT type, COUNT(*) FROM anomalies WHERE resolved = 0 GROUP BY type
	`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var anomalyType string
			var count int
			if rows2.Scan(&anomalyType, &count) == nil {
				summary.ByType[anomalyType] = count
			}
		}
	}

	// Affected users
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM anomalies WHERE resolved = 0 AND user_email IS NOT NULL
	`).Scan(&summary.AffectedUsers)

	// Recent anomalies
	summary.RecentAnomalies, _ = s.GetAnomalies(ctx, 10, false)

	return summary, nil
}

// DetectAnomalies runs anomaly detection and returns new anomalies
func (s *Storage) DetectAnomalies(ctx context.Context) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly
	now := time.Now()

	// 1. Detect activity spikes (users with 5x normal activity in last hour)
	spikes, _ := s.detectActivitySpikes(ctx, now)
	anomalies = append(anomalies, spikes...)

	// 2. Detect night activity (activity between 1-5 AM local)
	nightAnomalies, _ := s.detectNightActivity(ctx, now)
	anomalies = append(anomalies, nightAnomalies...)

	// 3. Detect new users with high volume
	newUserAnomalies, _ := s.detectNewUserHighVolume(ctx, now)
	anomalies = append(anomalies, newUserAnomalies...)

	// 4. Detect threat bursts (multiple threats from same user in short time)
	burstAnomalies, _ := s.detectThreatBursts(ctx, now)
	anomalies = append(anomalies, burstAnomalies...)

	// 5. Detect users from multiple countries
	geoAnomalies, _ := s.detectMultipleCountries(ctx, now)
	anomalies = append(anomalies, geoAnomalies...)

	// Save all new anomalies
	for _, a := range anomalies {
		s.SaveAnomaly(ctx, a)
	}

	return anomalies, nil
}

func (s *Storage) detectActivitySpikes(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

	// Find users with significantly higher activity in last hour vs their average
	rows, err := s.db.QueryContext(ctx, `
		WITH hourly AS (
			SELECT user_email, COUNT(*) as count
			FROM threat_matches
			WHERE matched_at > datetime('now', '-1 hour')
			GROUP BY user_email
			HAVING count >= 10
		),
		daily_avg AS (
			SELECT user_email, COUNT(*) * 1.0 / 24 as avg_hourly
			FROM threat_matches
			WHERE matched_at > datetime('now', '-7 days')
			GROUP BY user_email
		)
		SELECT h.user_email, h.count, COALESCE(d.avg_hourly, 1) as avg
		FROM hourly h
		LEFT JOIN daily_avg d ON h.user_email = d.user_email
		WHERE h.count > COALESCE(d.avg_hourly, 1) * 5
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		var count int
		var avg float64
		if rows.Scan(&email, &count, &avg) == nil {
			id := fmt.Sprintf("spike_%s_%d", email, now.Unix())
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          id,
				Type:        threatintel.AnomalyActivitySpike,
				Severity:    threatintel.SeverityHigh,
				UserEmail:   email,
				Description: fmt.Sprintf("Activity spike: %d matches in last hour (avg: %.1f/hour)", count, avg),
				Details: map[string]any{
					"current_count": count,
					"avg_hourly":    avg,
					"multiplier":    float64(count) / avg,
				},
				DetectedAt: now,
			})
		}
	}

	return anomalies, nil
}

func (s *Storage) detectNightActivity(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

	// Find users with activity between 1-5 AM (assuming server timezone)
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, COUNT(*) as count
		FROM threat_matches
		WHERE matched_at > datetime('now', '-6 hours')
		AND CAST(strftime('%H', matched_at) AS INTEGER) BETWEEN 1 AND 5
		GROUP BY user_email
		HAVING count >= 5
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		var count int
		if rows.Scan(&email, &count) == nil {
			id := fmt.Sprintf("night_%s_%d", email, now.Unix())
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          id,
				Type:        threatintel.AnomalyNightActivity,
				Severity:    threatintel.SeverityMedium,
				UserEmail:   email,
				Description: fmt.Sprintf("Unusual night activity: %d matches between 1-5 AM", count),
				Details: map[string]any{
					"match_count": count,
					"time_range":  "01:00-05:00",
				},
				DetectedAt: now,
			})
		}
	}

	return anomalies, nil
}

func (s *Storage) detectNewUserHighVolume(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

	// Find users first seen in last 24h with high activity
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, COUNT(*) as count, MIN(matched_at) as first_seen
		FROM threat_matches
		GROUP BY user_email
		HAVING MIN(matched_at) > datetime('now', '-24 hours')
		AND count >= 20
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		var count int
		var firstSeen time.Time
		if rows.Scan(&email, &count, &firstSeen) == nil {
			id := fmt.Sprintf("newuser_%s_%d", email, now.Unix())
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          id,
				Type:        threatintel.AnomalyNewUserHighVolume,
				Severity:    threatintel.SeverityMedium,
				UserEmail:   email,
				Description: fmt.Sprintf("New user with high activity: %d matches in first 24h", count),
				Details: map[string]any{
					"match_count": count,
					"first_seen":  firstSeen.Format(time.RFC3339),
				},
				DetectedAt: now,
			})
		}
	}

	return anomalies, nil
}

func (s *Storage) detectThreatBursts(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

	// Find users with 5+ different threat types in last hour
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, COUNT(DISTINCT threat_type) as types, COUNT(*) as total
		FROM threat_matches
		WHERE matched_at > datetime('now', '-1 hour')
		GROUP BY user_email
		HAVING types >= 3 AND total >= 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		var types, total int
		if rows.Scan(&email, &types, &total) == nil {
			id := fmt.Sprintf("burst_%s_%d", email, now.Unix())
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          id,
				Type:        threatintel.AnomalyThreatBurst,
				Severity:    threatintel.SeverityHigh,
				UserEmail:   email,
				Description: fmt.Sprintf("Threat burst: %d threats of %d types in last hour", total, types),
				Details: map[string]any{
					"total_matches": total,
					"unique_types":  types,
				},
				DetectedAt: now,
			})
		}
	}

	return anomalies, nil
}

func (s *Storage) detectMultipleCountries(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

	// Find users accessing from 3+ countries in last 24h
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, COUNT(DISTINCT country_code) as countries, 
			   GROUP_CONCAT(DISTINCT country_code) as country_list
		FROM user_locations
		WHERE last_seen > datetime('now', '-24 hours')
		GROUP BY user_email
		HAVING countries >= 3
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		var countries int
		var countryList string
		if rows.Scan(&email, &countries, &countryList) == nil {
			id := fmt.Sprintf("geo_%s_%d", email, now.Unix())
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          id,
				Type:        threatintel.AnomalyMultipleCountries,
				Severity:    threatintel.SeverityCritical,
				UserEmail:   email,
				Description: fmt.Sprintf("Access from %d countries in 24h: %s", countries, countryList),
				Details: map[string]any{
					"country_count": countries,
					"countries":     strings.Split(countryList, ","),
				},
				DetectedAt: now,
			})
		}
	}

	return anomalies, nil
}

// ResolveAnomaly marks an anomaly as resolved
func (s *Storage) ResolveAnomaly(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE anomalies SET resolved = 1 WHERE id = ?`, id)
	return err
}

// CalculateUserRiskProfile calculates and saves risk profile for a user
func (s *Storage) CalculateUserRiskProfile(ctx context.Context, email string) (*threatintel.UserRiskProfile, error) {
	profile := &threatintel.UserRiskProfile{
		UserEmail:     email,
		ThreatsByType: make(map[string]int),
		RiskFactors:   []threatintel.RiskFactor{},
	}

	// Get basic match stats
	row := s.db.QueryRowContext(ctx, `
		SELECT 
			COUNT(*) as total_matches,
			MIN(matched_at) as first_seen,
			MAX(matched_at) as last_activity,
			COUNT(DISTINCT DATE(matched_at)) as days_active
		FROM threat_matches 
		WHERE user_email = ?
	`, email)

	var firstSeenStr, lastActivityStr sql.NullString
	if err := row.Scan(&profile.TotalMatches, &firstSeenStr, &lastActivityStr, &profile.DaysActive); err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if firstSeenStr.Valid {
		profile.FirstSeen, _ = time.Parse(time.RFC3339, firstSeenStr.String)
	}
	if lastActivityStr.Valid {
		profile.LastActivity, _ = time.Parse(time.RFC3339, lastActivityStr.String)
	}

	// Get threats by type
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, COUNT(*) as cnt 
		FROM threat_matches 
		WHERE user_email = ?
		GROUP BY threat_type
	`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var threatType string
		var count int
		if rows.Scan(&threatType, &count) == nil {
			profile.ThreatsByType[threatType] = count
		}
	}

	// Get unique countries
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT country_code) 
		FROM user_locations 
		WHERE user_email = ?
	`, email)
	row.Scan(&profile.UniqueCountries)

	// Get anomaly count
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) 
		FROM anomalies 
		WHERE user_email = ? AND resolved = 0
	`, email)
	row.Scan(&profile.AnomalyCount)

	// Get top domains
	domainRows, err := s.db.QueryContext(ctx, `
		SELECT destination, COUNT(*) as cnt 
		FROM threat_matches 
		WHERE user_email = ?
		GROUP BY destination 
		ORDER BY cnt DESC 
		LIMIT 5
	`, email)
	if err == nil {
		defer domainRows.Close()
		for domainRows.Next() {
			var domain string
			var cnt int
			if domainRows.Scan(&domain, &cnt) == nil {
				profile.TopDomains = append(profile.TopDomains, domain)
			}
		}
	}

	// Calculate risk score and factors
	profile.RiskScore, profile.RiskFactors = s.calculateRiskScore(profile)
	profile.RiskLevel = getRiskLevel(profile.RiskScore)

	// Calculate trend
	profile.TrendDirection = s.calculateRiskTrend(ctx, email)

	// Save profile
	if err := s.SaveUserRiskProfile(ctx, profile); err != nil {
		return nil, err
	}

	return profile, nil
}

// calculateRiskScore calculates risk score based on various factors
func (s *Storage) calculateRiskScore(profile *threatintel.UserRiskProfile) (int, []threatintel.RiskFactor) {
	var score int
	var factors []threatintel.RiskFactor
	now := time.Now().Format("2006-01-02")

	// Factor 1: Total matches (max 30 points)
	matchScore := min(profile.TotalMatches*2, 30)
	if matchScore > 0 {
		score += matchScore
		factors = append(factors, threatintel.RiskFactor{
			Type:        "total_matches",
			Description: fmt.Sprintf("%d total threat matches", profile.TotalMatches),
			Weight:      matchScore,
			DetectedAt:  now,
		})
	}

	// Factor 2: Diversity of threat types (max 20 points)
	typeCount := len(profile.ThreatsByType)
	if typeCount >= 3 {
		typeScore := min(typeCount*5, 20)
		score += typeScore
		factors = append(factors, threatintel.RiskFactor{
			Type:        "threat_diversity",
			Description: fmt.Sprintf("Activity across %d threat categories", typeCount),
			Weight:      typeScore,
			DetectedAt:  now,
		})
	}

	// Factor 3: Tor usage (10 points)
	if profile.ThreatsByType["tor"] > 0 {
		score += 10
		factors = append(factors, threatintel.RiskFactor{
			Type:        "tor_usage",
			Description: fmt.Sprintf("Tor network usage detected (%d times)", profile.ThreatsByType["tor"]),
			Weight:      10,
			DetectedAt:  now,
		})
	}

	// Factor 4: Torrent usage (5 points)
	if profile.ThreatsByType["torrent"] > 0 {
		score += 5
		factors = append(factors, threatintel.RiskFactor{
			Type:        "torrent_usage",
			Description: fmt.Sprintf("Torrent activity detected (%d times)", profile.ThreatsByType["torrent"]),
			Weight:      5,
			DetectedAt:  now,
		})
	}

	// Factor 5: Multiple countries (15 points for 3+)
	if profile.UniqueCountries >= 3 {
		score += 15
		factors = append(factors, threatintel.RiskFactor{
			Type:        "geo_anomaly",
			Description: fmt.Sprintf("Access from %d different countries", profile.UniqueCountries),
			Weight:      15,
			DetectedAt:  now,
		})
	}

	// Factor 6: Active anomalies (10 points each, max 20)
	if profile.AnomalyCount > 0 {
		anomalyScore := min(profile.AnomalyCount*10, 20)
		score += anomalyScore
		factors = append(factors, threatintel.RiskFactor{
			Type:        "active_anomalies",
			Description: fmt.Sprintf("%d unresolved anomalies", profile.AnomalyCount),
			Weight:      anomalyScore,
			DetectedAt:  now,
		})
	}

	// Factor 7: Recent activity (within 24h adds 5 points)
	if time.Since(profile.LastActivity) < 24*time.Hour {
		score += 5
		factors = append(factors, threatintel.RiskFactor{
			Type:        "recent_activity",
			Description: "Activity within last 24 hours",
			Weight:      5,
			DetectedAt:  now,
		})
	}

	return min(score, 100), factors
}

// getRiskLevel returns risk level based on score
func getRiskLevel(score int) threatintel.RiskLevel {
	switch {
	case score >= 70:
		return threatintel.RiskLevelCritical
	case score >= 50:
		return threatintel.RiskLevelHigh
	case score >= 25:
		return threatintel.RiskLevelMedium
	default:
		return threatintel.RiskLevelLow
	}
}

// calculateRiskTrend compares current activity with previous period
func (s *Storage) calculateRiskTrend(ctx context.Context, email string) string {
	var recent, previous int

	// Count matches in last 7 days
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threat_matches 
		WHERE user_email = ? AND matched_at > datetime('now', '-7 days')
	`, email).Scan(&recent)

	// Count matches in previous 7 days
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threat_matches 
		WHERE user_email = ? 
		AND matched_at > datetime('now', '-14 days') 
		AND matched_at <= datetime('now', '-7 days')
	`, email).Scan(&previous)

	if recent > previous+2 {
		return "up"
	} else if recent < previous-2 {
		return "down"
	}
	return "stable"
}

// SaveUserRiskProfile saves user risk profile to database
func (s *Storage) SaveUserRiskProfile(ctx context.Context, profile *threatintel.UserRiskProfile) error {
	threatsByType, _ := json.Marshal(profile.ThreatsByType)
	topDomains, _ := json.Marshal(profile.TopDomains)
	riskFactors, _ := json.Marshal(profile.RiskFactors)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_risk_profiles (
			user_email, risk_level, risk_score, total_matches, threats_by_type,
			unique_countries, anomaly_count, first_seen, last_activity,
			days_active, top_domains, risk_factors, trend_direction, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(user_email) DO UPDATE SET
			risk_level = excluded.risk_level,
			risk_score = excluded.risk_score,
			total_matches = excluded.total_matches,
			threats_by_type = excluded.threats_by_type,
			unique_countries = excluded.unique_countries,
			anomaly_count = excluded.anomaly_count,
			last_activity = excluded.last_activity,
			days_active = excluded.days_active,
			top_domains = excluded.top_domains,
			risk_factors = excluded.risk_factors,
			trend_direction = excluded.trend_direction,
			updated_at = datetime('now')
	`, profile.UserEmail, string(profile.RiskLevel), profile.RiskScore,
		profile.TotalMatches, string(threatsByType), profile.UniqueCountries,
		profile.AnomalyCount, profile.FirstSeen.Format(time.RFC3339),
		profile.LastActivity.Format(time.RFC3339), profile.DaysActive,
		string(topDomains), string(riskFactors), profile.TrendDirection)

	return err
}

// GetUserRiskProfile retrieves a user's risk profile
func (s *Storage) GetUserRiskProfile(ctx context.Context, email string) (*threatintel.UserRiskProfile, error) {
	profile := &threatintel.UserRiskProfile{
		ThreatsByType: make(map[string]int),
		RiskFactors:   []threatintel.RiskFactor{},
		TopDomains:    []string{},
	}

	var threatsByType, topDomains, riskFactors sql.NullString
	var firstSeen, lastActivity sql.NullString
	var riskLevel string

	row := s.db.QueryRowContext(ctx, `
		SELECT user_email, risk_level, risk_score, total_matches, threats_by_type,
			   unique_countries, anomaly_count, first_seen, last_activity,
			   days_active, top_domains, risk_factors, trend_direction
		FROM user_risk_profiles
		WHERE user_email = ?
	`, email)

	err := row.Scan(&profile.UserEmail, &riskLevel, &profile.RiskScore,
		&profile.TotalMatches, &threatsByType, &profile.UniqueCountries,
		&profile.AnomalyCount, &firstSeen, &lastActivity,
		&profile.DaysActive, &topDomains, &riskFactors, &profile.TrendDirection)

	if err == sql.ErrNoRows {
		// Calculate fresh profile if not exists
		return s.CalculateUserRiskProfile(ctx, email)
	}
	if err != nil {
		return nil, err
	}

	profile.RiskLevel = threatintel.RiskLevel(riskLevel)

	if threatsByType.Valid {
		json.Unmarshal([]byte(threatsByType.String), &profile.ThreatsByType)
	}
	if topDomains.Valid {
		json.Unmarshal([]byte(topDomains.String), &profile.TopDomains)
	}
	if riskFactors.Valid {
		json.Unmarshal([]byte(riskFactors.String), &profile.RiskFactors)
	}
	if firstSeen.Valid {
		profile.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen.String)
	}
	if lastActivity.Valid {
		profile.LastActivity, _ = time.Parse(time.RFC3339, lastActivity.String)
	}

	return profile, nil
}

// GetUserRiskSummary returns summary of all user risk profiles
func (s *Storage) GetUserRiskSummary(ctx context.Context) (*threatintel.UserRiskSummary, error) {
	summary := &threatintel.UserRiskSummary{
		ByRiskLevel:   make(map[string]int),
		HighRiskUsers: []*threatintel.UserRiskProfile{},
	}

	// Get total users and risk distribution
	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(AVG(risk_score), 0)
		FROM user_risk_profiles
	`)
	row.Scan(&summary.TotalUsers, &summary.AverageRiskScore)

	// Get distribution by risk level
	rows, err := s.db.QueryContext(ctx, `
		SELECT risk_level, COUNT(*) 
		FROM user_risk_profiles 
		GROUP BY risk_level
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var level string
		var count int
		if rows.Scan(&level, &count) == nil {
			summary.ByRiskLevel[level] = count
		}
	}

	// Get high risk users (score >= 50)
	highRiskRows, err := s.db.QueryContext(ctx, `
		SELECT user_email, risk_level, risk_score, total_matches, threats_by_type,
			   unique_countries, anomaly_count, first_seen, last_activity,
			   days_active, top_domains, risk_factors, trend_direction
		FROM user_risk_profiles
		WHERE risk_score >= 50
		ORDER BY risk_score DESC
		LIMIT 10
	`)
	if err != nil {
		return summary, nil
	}
	defer highRiskRows.Close()

	for highRiskRows.Next() {
		profile := &threatintel.UserRiskProfile{
			ThreatsByType: make(map[string]int),
			RiskFactors:   []threatintel.RiskFactor{},
			TopDomains:    []string{},
		}
		var threatsByType, topDomains, riskFactors sql.NullString
		var firstSeen, lastActivity sql.NullString
		var riskLevel string

		if highRiskRows.Scan(&profile.UserEmail, &riskLevel, &profile.RiskScore,
			&profile.TotalMatches, &threatsByType, &profile.UniqueCountries,
			&profile.AnomalyCount, &firstSeen, &lastActivity,
			&profile.DaysActive, &topDomains, &riskFactors, &profile.TrendDirection) == nil {

			profile.RiskLevel = threatintel.RiskLevel(riskLevel)
			if threatsByType.Valid {
				json.Unmarshal([]byte(threatsByType.String), &profile.ThreatsByType)
			}
			if topDomains.Valid {
				json.Unmarshal([]byte(topDomains.String), &profile.TopDomains)
			}
			if riskFactors.Valid {
				json.Unmarshal([]byte(riskFactors.String), &profile.RiskFactors)
			}
			if firstSeen.Valid {
				profile.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen.String)
			}
			if lastActivity.Valid {
				profile.LastActivity, _ = time.Parse(time.RFC3339, lastActivity.String)
			}

			summary.HighRiskUsers = append(summary.HighRiskUsers, profile)
		}
	}

	// Count recent escalations (risk increased in last 24h)
	s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_risk_profiles
		WHERE trend_direction = 'up' AND updated_at > datetime('now', '-24 hours')
	`).Scan(&summary.RecentEscalations)

	return summary, nil
}

// RecalculateAllUserRiskProfiles recalculates risk profiles for all users with threat activity
func (s *Storage) RecalculateAllUserRiskProfiles(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT user_email FROM threat_matches WHERE user_email != ''
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var email string
		if rows.Scan(&email) == nil {
			emails = append(emails, email)
		}
	}

	for _, email := range emails {
		s.CalculateUserRiskProfile(ctx, email)
	}

	return nil
}

// ==================== DNS Analysis Functions ====================

// UpdateDNSDomainStats updates statistics for a domain
func (s *Storage) UpdateDNSDomainStats(ctx context.Context, domain string, threatType string, source string) error {
	now := time.Now().Format(time.RFC3339)

	// Check if domain exists
	var existing sql.NullString
	var existingTypes, existingSources sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT domain, threat_types, sources FROM dns_domain_stats WHERE domain = ?
	`, domain).Scan(&existing, &existingTypes, &existingSources)

	if err == sql.ErrNoRows {
		// New domain
		types, _ := json.Marshal([]string{threatType})
		sources, _ := json.Marshal([]string{source})
		categoryHits, _ := json.Marshal(map[string]int{threatType: 1})

		_, err = s.db.ExecContext(ctx, `
			INSERT INTO dns_domain_stats (domain, total_hits, unique_users, threat_types, sources, first_seen, last_seen, category_hits)
			VALUES (?, 1, 1, ?, ?, ?, ?, ?)
		`, domain, string(types), string(sources), now, now, string(categoryHits))
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
			threat_types = ?,
			sources = ?,
			last_seen = ?
		WHERE domain = ?
	`, string(typesJSON), string(sourcesJSON), now, domain)

	return err
}

// helper function
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
		VALUES (?, 1, ?, 1)
		ON CONFLICT(hour) DO UPDATE SET
			total_queries = total_queries + 1,
			blocked_queries = blocked_queries + ?
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
		VALUES (?, 1, ?, 1)
		ON CONFLICT(day) DO UPDATE SET
			total_queries = total_queries + 1,
			blocked_queries = blocked_queries + ?
	`, day, blockedInc, blockedInc)

	return err
}

// UpdateUserDNSStats updates DNS statistics for a user
func (s *Storage) UpdateUserDNSStats(ctx context.Context, email string, domain string, blocked bool) error {
	now := time.Now().Format(time.RFC3339)

	blockedInc := 0
	if blocked {
		blockedInc = 1
	}

	// Get existing top domains
	var existingDomains sql.NullString
	s.db.QueryRowContext(ctx, `SELECT top_domains FROM user_dns_stats WHERE user_email = ?`, email).Scan(&existingDomains)

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

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_dns_stats (user_email, total_queries, blocked_queries, top_domains, updated_at)
		VALUES (?, 1, ?, ?, ?)
		ON CONFLICT(user_email) DO UPDATE SET
			total_queries = total_queries + 1,
			blocked_queries = blocked_queries + ?,
			top_domains = ?,
			updated_at = ?
	`, email, blockedInc, string(domainsJSON), now, blockedInc, string(domainsJSON), now)

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
		WHERE day > date('now', '-30 days')
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
			var firstSeen, lastSeen sql.NullString
			var riskLevel string

			if rows.Scan(&ds.Domain, &ds.TotalHits, &ds.UniqueUsers, &threatTypes, &sources, &firstSeen, &lastSeen, &riskLevel) == nil {
				if threatTypes.Valid {
					json.Unmarshal([]byte(threatTypes.String), &ds.ThreatTypes)
				}
				if sources.Valid {
					json.Unmarshal([]byte(sources.String), &ds.Sources)
				}
				if firstSeen.Valid {
					ds.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen.String)
				}
				if lastSeen.Valid {
					ds.LastSeen, _ = time.Parse(time.RFC3339, lastSeen.String)
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
		WHERE hour >= datetime('now', '-24 hours')
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
		WHERE day >= date('now', '-30 days')
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

	rows, err := s.db.QueryContext(ctx, `
		SELECT user_email, total_queries, blocked_queries, top_domains
		FROM user_dns_stats
		ORDER BY blocked_queries DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		u := &threatintel.UserDNSStats{
			TopDomains: []string{},
		}
		var topDomains sql.NullString

		if rows.Scan(&u.UserEmail, &u.TotalQueries, &u.BlockedQueries, &topDomains) == nil {
			if u.TotalQueries > 0 {
				u.BlockRate = float64(u.BlockedQueries) / float64(u.TotalQueries) * 100
			}
			if topDomains.Valid {
				json.Unmarshal([]byte(topDomains.String), &u.TopDomains)
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
		SELECT COALESCE(SUM(blocked_queries), 0) FROM dns_daily_stats WHERE day >= date('now', '-7 days')
	`).Scan(&recent)
	s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(blocked_queries), 0) FROM dns_daily_stats WHERE day >= date('now', '-14 days') AND day < date('now', '-7 days')
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
