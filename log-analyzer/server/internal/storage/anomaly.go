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

	return scanAnomalies(rows)
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

	detectors := []func(context.Context, time.Time) ([]*threatintel.Anomaly, error){
		s.detectActivitySpikes,
		s.detectNightActivity,
		s.detectNewUserHighVolume,
		s.detectThreatBursts,
		s.detectMultipleCountries,
	}

	for _, detect := range detectors {
		if found, err := detect(ctx, now); err == nil {
			anomalies = append(anomalies, found...)
		}
	}

	// Save all new anomalies
	for _, a := range anomalies {
		s.SaveAnomaly(ctx, a)
	}

	return anomalies, nil
}

// ResolveAnomaly marks an anomaly as resolved
func (s *Storage) ResolveAnomaly(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE anomalies SET resolved = 1 WHERE id = ?`, id)
	return err
}

// detectActivitySpikes detects users with abnormally high activity
func (s *Storage) detectActivitySpikes(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

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
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          fmt.Sprintf("spike_%s_%d", email, now.Unix()),
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

// detectNightActivity detects unusual nighttime activity
func (s *Storage) detectNightActivity(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

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
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          fmt.Sprintf("night_%s_%d", email, now.Unix()),
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

// detectNewUserHighVolume detects new users with high activity
func (s *Storage) detectNewUserHighVolume(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

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
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          fmt.Sprintf("newuser_%s_%d", email, now.Unix()),
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

// detectThreatBursts detects bursts of threat activity
func (s *Storage) detectThreatBursts(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

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
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          fmt.Sprintf("burst_%s_%d", email, now.Unix()),
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

// detectMultipleCountries detects users accessing from multiple countries
func (s *Storage) detectMultipleCountries(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

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
			anomalies = append(anomalies, &threatintel.Anomaly{
				ID:          fmt.Sprintf("geo_%s_%d", email, now.Unix()),
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

// scanAnomalies is a helper to scan anomaly rows
func scanAnomalies(rows *sql.Rows) ([]*threatintel.Anomaly, error) {
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
