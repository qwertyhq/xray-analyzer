package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// severityToInt converts a text severity to the smallint used in schema v2.
func severityToInt(s threatintel.AnomalySeverity) int16 {
	switch s {
	case threatintel.SeverityLow:
		return 1
	case threatintel.SeverityMedium:
		return 2
	case threatintel.SeverityHigh:
		return 3
	case threatintel.SeverityCritical:
		return 4
	default:
		return 2 // medium default
	}
}

// intToSeverity converts the smallint severity back to the text form.
func intToSeverity(n int16) threatintel.AnomalySeverity {
	switch n {
	case 1:
		return threatintel.SeverityLow
	case 2:
		return threatintel.SeverityMedium
	case 3:
		return threatintel.SeverityHigh
	case 4:
		return threatintel.SeverityCritical
	default:
		return threatintel.SeverityMedium
	}
}

// SaveAnomaly saves a detected anomaly to the database.
// anomaly.UserEmail may be empty (nullable) or a valid UUID string.
// anomaly.Severity (string) is converted to smallint for storage.
// The ON CONFLICT key includes (id, ts) because anomalies is partitioned by ts.
func (s *Storage) SaveAnomaly(ctx context.Context, anomaly *threatintel.Anomaly) error {
	detailsJSON := "{}"
	if anomaly.Details != nil {
		if data, err := json.Marshal(anomaly.Details); err == nil {
			detailsJSON = string(data)
		}
	}

	resolved := 0
	if anomaly.Resolved {
		resolved = 1
	}

	now := time.Now().UTC()
	if !anomaly.DetectedAt.IsZero() {
		now = anomaly.DetectedAt.UTC()
	}

	// user_email is nullable uuid
	var userEmailVal interface{}
	if anomaly.UserEmail != "" {
		if u, err := uuid.Parse(anomaly.UserEmail); err == nil {
			userEmailVal = u
		}
		// If not a valid UUID, leave as nil (don't fail — some anomalies use
		// plain strings as user identifiers; they are stored with NULL user_email).
	}

	severityInt := severityToInt(anomaly.Severity)

	// anomalies is PARTITIONED BY RANGE (ts), so ON CONFLICT must include ts.
	// Use INSERT ... ON CONFLICT (id, ts) DO UPDATE.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO anomalies (id, type, severity, user_email, description, details, detected_at, resolved, ts)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id, ts) DO UPDATE SET
			type        = EXCLUDED.type,
			severity    = EXCLUDED.severity,
			user_email  = EXCLUDED.user_email,
			description = EXCLUDED.description,
			details     = EXCLUDED.details,
			detected_at = EXCLUDED.detected_at,
			resolved    = EXCLUDED.resolved
	`, anomaly.ID, string(anomaly.Type), severityInt, userEmailVal, anomaly.Description, detailsJSON, now, resolved, now)

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
	query += " ORDER BY detected_at DESC LIMIT $1"

	rows, err := s.pool.Query(ctx, query, limit)
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

	// Count by severity (now smallint in DB)
	rows, err := s.pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM anomalies WHERE resolved = 0 GROUP BY severity
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var severityInt int16
			var count int
			if rows.Scan(&severityInt, &count) == nil {
				sev := string(intToSeverity(severityInt))
				summary.BySeverity[sev] = count
				summary.TotalAnomalies += count
			}
		}
	}

	// Count by type
	rows2, err := s.pool.Query(ctx, `
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

	// Affected users (count distinct non-null user_email)
	s.pool.QueryRow(ctx, `
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
		s.detectPortScan,
		s.detectAbusePortFlood,
		s.detectBurstScanAnyTarget,
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
	_, err := s.pool.Exec(ctx, `UPDATE anomalies SET resolved = 1 WHERE id = $1`, id)
	return err
}

// detectActivitySpikes detects users with abnormally high activity
func (s *Storage) detectActivitySpikes(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	var anomalies []*threatintel.Anomaly

	rows, err := s.pool.Query(ctx, `
		WITH hourly AS (
			SELECT user_email, COUNT(*) as count
			FROM threat_matches
			WHERE matched_at > NOW() - INTERVAL '1 hour'
			GROUP BY user_email
			HAVING COUNT(*) >= 10
		),
		daily_avg AS (
			SELECT user_email, COUNT(*) * 1.0 / 24 as avg_hourly
			FROM threat_matches
			WHERE matched_at > NOW() - INTERVAL '7 days'
			GROUP BY user_email
		)
		SELECT h.user_email::text, h.count, COALESCE(d.avg_hourly, 1) as avg
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

	rows, err := s.pool.Query(ctx, `
		SELECT user_email::text, COUNT(*) as count
		FROM threat_matches
		WHERE matched_at > NOW() - INTERVAL '6 hours'
		AND EXTRACT(HOUR FROM matched_at AT TIME ZONE 'UTC') BETWEEN 1 AND 5
		GROUP BY user_email
		HAVING COUNT(*) >= 5
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

	rows, err := s.pool.Query(ctx, `
		SELECT user_email::text, COUNT(*) as count, MIN(matched_at) as first_seen
		FROM threat_matches
		GROUP BY user_email
		HAVING MIN(matched_at) > NOW() - INTERVAL '24 hours'
		AND COUNT(*) >= 20
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

	rows, err := s.pool.Query(ctx, `
		SELECT user_email::text, COUNT(DISTINCT threat_type) as types, COUNT(*) as total
		FROM threat_matches
		WHERE matched_at > NOW() - INTERVAL '1 hour'
		GROUP BY user_email
		HAVING COUNT(DISTINCT threat_type) >= 3 AND COUNT(*) >= 10
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

	rows, err := s.pool.Query(ctx, `
		SELECT user_email::text, COUNT(DISTINCT country_code) as countries,
			   STRING_AGG(DISTINCT country_code, ',') as country_list
		FROM user_locations
		WHERE last_seen > NOW() - INTERVAL '24 hours'
		GROUP BY user_email
		HAVING COUNT(DISTINCT country_code) >= 3
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

// detectPortScan flags masscan-style sweeps: many unique IPv4 destinations
// inside a single /16 from one user, on any port, within a short window.
func (s *Storage) detectPortScan(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	const (
		minUniqueIPs  = 20
		windowMinutes = 5
	)

	cutoff := now.Add(-time.Duration(windowMinutes) * time.Minute).UTC()

	rows, err := s.pool.Query(ctx, `
		WITH parsed AS (
			SELECT user_email,
			       SUBSTRING(destination, 1, POSITION(':' IN destination) - 1) AS ip,
			       SUBSTRING(destination, POSITION(':' IN destination) + 1)    AS port
			FROM user_destinations
			WHERE last_seen > $1
			  AND destination ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$'
		)
		SELECT user_email,
		       split_part(ip, '.', 1) || '.' || split_part(ip, '.', 2) AS slash16,
		       port,
		       COUNT(DISTINCT ip) AS uniq_ips
		FROM parsed
		WHERE port NOT IN ('80', '443', '53', '8080')
		GROUP BY user_email, slash16, port
		HAVING COUNT(DISTINCT ip) >= $2
		ORDER BY uniq_ips DESC
		LIMIT 50
	`, cutoff, minUniqueIPs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*threatintel.Anomaly
	for rows.Next() {
		var (
			email, subnet, port string
			uniq                int
		)
		if err := rows.Scan(&email, &subnet, &port, &uniq); err != nil {
			continue
		}
		out = append(out, &threatintel.Anomaly{
			ID:        fmt.Sprintf("portscan_%s_%s_%s_%d", email, subnet, port, now.Unix()),
			Type:      threatintel.AnomalyPortScan,
			Severity:  threatintel.SeverityHigh,
			UserEmail: email,
			Description: fmt.Sprintf("Port scan: %d IPs in %s.0.0/16 on port %s in last %d min",
				uniq, subnet, port, windowMinutes),
			Details: map[string]any{
				"unique_ips":     uniq,
				"target_subnet":  subnet + ".0.0/16",
				"port":           port,
				"window_minutes": windowMinutes,
			},
			DetectedAt: now,
		})
	}
	return out, nil
}

// abusePortList is the set of destination ports where a flood of distinct
// destinations is almost always malicious from a VPN user.
var abusePortList = []string{
	"22", "23", "25", "135", "139", "445", "465", "587",
	"1433", "3306", "3389", "5432", "5900", "6379", "11211", "27017",
}

// detectAbusePortFlood flags brute-force / spam patterns.
func (s *Storage) detectAbusePortFlood(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	const (
		minUniqueDests = 15
		windowMinutes  = 10
	)

	cutoff := now.Add(-time.Duration(windowMinutes) * time.Minute).UTC()

	pgRows, err := s.pool.Query(ctx, `
		SELECT user_email,
		       SUBSTRING(destination, POSITION(':' IN destination) + 1) AS port,
		       COUNT(DISTINCT destination) AS uniq_dst
		FROM user_destinations
		WHERE last_seen > $1
		  AND SUBSTRING(destination, POSITION(':' IN destination) + 1) = ANY($2)
		GROUP BY user_email, port
		HAVING COUNT(DISTINCT destination) >= $3
		ORDER BY uniq_dst DESC
		LIMIT 50
	`, cutoff, abusePortList, minUniqueDests)
	if err != nil {
		return nil, err
	}
	defer pgRows.Close()

	var out []*threatintel.Anomaly
	for pgRows.Next() {
		var (
			email, port string
			uniq        int
		)
		if err := pgRows.Scan(&email, &port, &uniq); err != nil {
			continue
		}
		out = append(out, &threatintel.Anomaly{
			ID:        fmt.Sprintf("abuseport_%s_%s_%d", email, port, now.Unix()),
			Type:      threatintel.AnomalyAbusePortFlood,
			Severity:  threatintel.SeverityHigh,
			UserEmail: email,
			Description: fmt.Sprintf("Abuse-port flood: %d destinations on port %s in last %d min",
				uniq, port, windowMinutes),
			Details: map[string]any{
				"unique_destinations": uniq,
				"port":                port,
				"window_minutes":      windowMinutes,
			},
			DetectedAt: now,
		})
	}
	return out, nil
}

// GetAttackAnomalies returns anomalies whose type belongs to the supplied
// allow-list within `since`. Unlike GetAnomalies this is narrowed to active
// attack-type detections.
func (s *Storage) GetAttackAnomalies(ctx context.Context, types []string, since time.Duration, limit int, includeResolved bool) ([]*threatintel.Anomaly, error) {
	if len(types) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if since <= 0 {
		since = 24 * time.Hour
	}

	threshold := time.Now().Add(-since).UTC()

	resolvedClause := "AND resolved = 0"
	if includeResolved {
		resolvedClause = ""
	}

	query := fmt.Sprintf(`
		SELECT id, type, severity, user_email, description, details, detected_at, resolved
		FROM anomalies
		WHERE type = ANY($1)
		  AND detected_at >= $2
		  %s
		ORDER BY detected_at DESC
		LIMIT $3
	`, resolvedClause)

	pgRows, err := s.pool.Query(ctx, query, types, threshold, limit)
	if err != nil {
		return nil, err
	}
	defer pgRows.Close()

	return scanAnomalies(pgRows)
}

// benignHighVolumePorts are ports where a single user legitimately touches
// many distinct IPs in normal operation.
var benignHighVolumePorts = []string{
	"80", "443", "53", "8080", "8443",
	"123",
	"554",
	"5222", "5223",
	"6881", "6882", "6883", "6884", "6885", "6886", "6887", "6888", "6889",
	"51413",
}

// detectBurstScanAnyTarget flags "target-agnostic" scans.
func (s *Storage) detectBurstScanAnyTarget(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	const (
		minUniqueIPs = 15
		windowMin    = 1
	)

	cutoff := now.Add(-time.Duration(windowMin) * time.Minute).UTC()

	pgRows, err := s.pool.Query(ctx, `
		WITH parsed AS (
			SELECT user_email,
			       SUBSTRING(destination, 1, POSITION(':' IN destination) - 1) AS ip,
			       SUBSTRING(destination, POSITION(':' IN destination) + 1)    AS port
			FROM user_destinations
			WHERE first_seen > $1
			  AND destination ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$'
		)
		SELECT user_email, port, COUNT(DISTINCT ip) AS uniq_ips
		FROM parsed
		WHERE NOT (port = ANY($2))
		GROUP BY user_email, port
		HAVING COUNT(DISTINCT ip) >= $3
		ORDER BY uniq_ips DESC
		LIMIT 50
	`, cutoff, benignHighVolumePorts, minUniqueIPs)
	if err != nil {
		return nil, err
	}
	defer pgRows.Close()

	var out []*threatintel.Anomaly
	for pgRows.Next() {
		var (
			email, port string
			uniq        int
		)
		if err := pgRows.Scan(&email, &port, &uniq); err != nil {
			continue
		}
		out = append(out, &threatintel.Anomaly{
			ID:        fmt.Sprintf("burstscan_%s_%s_%d", email, port, now.Unix()),
			Type:      threatintel.AnomalyBurstScan,
			Severity:  threatintel.SeverityHigh,
			UserEmail: email,
			Description: fmt.Sprintf("Burst scan: %d unique IPv4 destinations on port %s in last %d min",
				uniq, port, windowMin),
			Details: map[string]any{
				"unique_ips":     uniq,
				"port":           port,
				"window_minutes": windowMin,
			},
			DetectedAt: now,
		})
	}
	return out, nil
}

// scanAnomalies is a helper to scan anomaly rows from pgx rows.
func scanAnomalies(rows pgx.Rows) ([]*threatintel.Anomaly, error) {
	var result []*threatintel.Anomaly
	for rows.Next() {
		a := &threatintel.Anomaly{}
		var userEmailVal interface{}
		var detailsJSON string
		var resolved int
		var severityInt int16

		if err := rows.Scan(&a.ID, &a.Type, &severityInt, &userEmailVal, &a.Description, &detailsJSON, &a.DetectedAt, &resolved); err != nil {
			continue
		}

		a.Severity = intToSeverity(severityInt)

		// user_email is uuid (nullable) — convert back to string
		if userEmailVal != nil {
			switch v := userEmailVal.(type) {
			case [16]byte:
				a.UserEmail = uuid.UUID(v).String()
			case uuid.UUID:
				a.UserEmail = v.String()
			default:
				// Try string conversion
				if s, ok := v.(string); ok {
					a.UserEmail = s
				}
			}
		}

		a.Resolved = resolved == 1

		if detailsJSON != "" && detailsJSON != "{}" {
			json.Unmarshal([]byte(detailsJSON), &a.Details)
		}

		result = append(result, a)
	}

	return result, rows.Err()
}
