package storage

import (
	"context"
	"database/sql"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// SaveGeoStats updates geographic statistics for a threat match
func (s *Storage) SaveGeoStats(ctx context.Context, countryCode, countryName, threatType, userEmail string) error {
	if countryCode == "" {
		return nil
	}

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
