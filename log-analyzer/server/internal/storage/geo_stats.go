package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// SaveGeoStats updates geographic statistics for a threat match
func (s *Storage) SaveGeoStats(ctx context.Context, countryCode, countryName, threatType, userEmail string) error {
	if countryCode == "" {
		return nil
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_geo_stats (country_code, country_name, threat_type, match_count, unique_users, last_match)
		VALUES ($1, $2, $3, 1, 1, NOW())
		ON CONFLICT (country_code, threat_type) DO UPDATE SET
			match_count = threat_geo_stats.match_count + 1,
			unique_users = (
				SELECT COUNT(DISTINCT user_email) FROM threat_matches
				WHERE threat_type = $4
				AND source_ip IN (SELECT DISTINCT source_ip FROM user_locations WHERE country_code = $5)
			),
			last_match = NOW()
	`, countryCode, countryName, threatType, threatType, countryCode)

	return err
}

// SaveUserLocation tracks user access from a specific location with coordinates
func (s *Storage) SaveUserLocation(ctx context.Context, userEmail, countryCode, countryName, city string, lat, lon float64) error {
	if countryCode == "" || userEmail == "" {
		return nil
	}

	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_locations (user_email, country_code, country_name, city, latitude, longitude, last_seen, request_count)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), 1)
		ON CONFLICT (user_email, country_code) DO UPDATE SET
			city = CASE WHEN $7 != '' THEN $8 ELSE user_locations.city END,
			latitude = CASE WHEN $9 != 0 THEN $10 ELSE user_locations.latitude END,
			longitude = CASE WHEN $11 != 0 THEN $12 ELSE user_locations.longitude END,
			last_seen = NOW(),
			request_count = user_locations.request_count + 1
	`, userUUID, countryCode, countryName, city, lat, lon, city, city, lat, lat, lon, lon)

	return err
}

// GetGeoStats returns geographic threat statistics (cached)
func (s *Storage) GetGeoStats(ctx context.Context, limit int) ([]*threatintel.GeoStats, error) {
	if limit <= 0 {
		limit = 20
	}

	cacheKey := fmt.Sprintf("geo_stats_%d", limit)
	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]*threatintel.GeoStats), nil
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT country_code, country_name, threat_type, match_count, unique_users, last_match
		FROM threat_geo_stats
		ORDER BY match_count DESC
		LIMIT $1
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

	s.cache.Set(cacheKey, result, CacheTTLMedium)
	return result, nil
}

// GetGeoSummary returns aggregated geographic analysis (cached)
func (s *Storage) GetGeoSummary(ctx context.Context) (*threatintel.GeoSummary, error) {
	cacheKey := "geo_summary"
	if cached, found := s.cache.Get(cacheKey); found {
		return cached.(*threatintel.GeoSummary), nil
	}

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

	s.cache.Set(cacheKey, summary, CacheTTLMedium)
	return summary, nil
}

// GetUserLocations returns location history for users
func (s *Storage) GetUserLocations(ctx context.Context, userEmail string, limit int) ([]*threatintel.UserLocation, error) {
	if limit <= 0 {
		limit = 10
	}

	scanLocs := func(query string, args ...interface{}) ([]*threatintel.UserLocation, error) {
		rows, err := s.pool.Query(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var result []*threatintel.UserLocation
		for rows.Next() {
			loc := &threatintel.UserLocation{}
			if e := rows.Scan(&loc.UserEmail, &loc.CountryCode, &loc.CountryName, &loc.City, &loc.LastSeen, &loc.RequestCount); e != nil {
				continue
			}
			result = append(result, loc)
		}
		return result, rows.Err()
	}

	if userEmail != "" {
		userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
		if err != nil {
			return nil, fmt.Errorf("resolve user_email: %w", err)
		}
		return scanLocs(`
			SELECT user_email::text, country_code, country_name, COALESCE(city,''), last_seen, request_count
			FROM user_locations
			WHERE user_email = $1
			ORDER BY last_seen DESC
			LIMIT $2
		`, userUUID, limit)
	}

	return scanLocs(`
		SELECT user_email::text, country_code, country_name, COALESCE(city,''), last_seen, request_count
		FROM user_locations
		ORDER BY last_seen DESC
		LIMIT $1
	`, limit)
}

// GetConnectionGeoStats returns geographic statistics for ALL connections (not just threats)
func (s *Storage) GetConnectionGeoStats(ctx context.Context, limit int) ([]*threatintel.CountryStats, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			country_code,
			country_name,
			SUM(request_count) as total_connections,
			COUNT(DISTINCT user_email) as unique_users
		FROM user_locations
		WHERE country_code != ''
		GROUP BY country_code, country_name
		ORDER BY total_connections DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*threatintel.CountryStats
	for rows.Next() {
		stat := &threatintel.CountryStats{}
		if err := rows.Scan(&stat.CountryCode, &stat.CountryName, &stat.TotalMatches, &stat.UniqueUsers); err != nil {
			continue
		}
		result = append(result, stat)
	}

	return result, nil
}

// CityGeoStats represents geo stats for a specific city with coordinates
type CityGeoStats struct {
	City        string  `json:"city"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Connections int64   `json:"connections"`
	UniqueUsers int     `json:"unique_users"`
}

// GetCityGeoStats returns geographic statistics grouped by city with coordinates
func (s *Storage) GetCityGeoStats(ctx context.Context, limit int) ([]*CityGeoStats, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			COALESCE(city, country_name) as city,
			country_code,
			country_name,
			COALESCE(latitude, 0) as latitude,
			COALESCE(longitude, 0) as longitude,
			SUM(request_count) as total_connections,
			COUNT(DISTINCT user_email) as unique_users
		FROM user_locations
		WHERE country_code != '' AND latitude IS NOT NULL AND longitude IS NOT NULL
		GROUP BY country_code, city, country_name, latitude, longitude
		ORDER BY total_connections DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*CityGeoStats
	for rows.Next() {
		stat := &CityGeoStats{}
		if err := rows.Scan(&stat.City, &stat.CountryCode, &stat.CountryName, &stat.Latitude, &stat.Longitude, &stat.Connections, &stat.UniqueUsers); err != nil {
			continue
		}
		// Skip entries without valid coordinates
		if stat.Latitude == 0 && stat.Longitude == 0 {
			continue
		}
		result = append(result, stat)
	}

	return result, nil
}

// GetLocationsWithoutCoords returns user locations that need coordinate enrichment
func (s *Storage) GetLocationsWithoutCoords(ctx context.Context, limit int) ([]*threatintel.LocationWithoutCoords, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT user_email::text, country_code, COALESCE(city, '') as city
		FROM user_locations
		WHERE (latitude IS NULL OR latitude = 0) AND (longitude IS NULL OR longitude = 0)
		ORDER BY request_count DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*threatintel.LocationWithoutCoords
	for rows.Next() {
		loc := &threatintel.LocationWithoutCoords{}
		if err := rows.Scan(&loc.UserEmail, &loc.CountryCode, &loc.City); err != nil {
			continue
		}
		result = append(result, loc)
	}

	return result, nil
}

// UpdateLocationCoords updates coordinates for a specific user location
func (s *Storage) UpdateLocationCoords(ctx context.Context, userEmail, countryCode, city string, lat, lon float64) error {
	userUUID, err := s.ResolveUserEmailToUUID(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE user_locations
		SET city = CASE WHEN $1 != '' THEN $2 ELSE city END,
			latitude = $3,
			longitude = $4
		WHERE user_email = $5 AND country_code = $6
	`, city, city, lat, lon, userUUID, countryCode)
	return err
}
