//go:build sqlite_legacy

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

// detectPortScan flags masscan-style sweeps: many unique IPv4 destinations
// inside a single /16 from one user, on any port, within a short window.
//
// Why "same /16" instead of a port whitelist: a targeted scan always hits a
// single network range (the thing the scanner is enumerating). Normal
// browsing — even the worst WhatsApp/CDN chatter — scatters across many
// providers' /16s. Concentration in one /16 is what distinguishes the two,
// and it works regardless of whether the target port is :443 or :8317.
//
// We drop known-infra ports to cut residual noise: :80/:443/:53/:8080 are
// the web/DNS that still account for most multi-IP sessions.
//
// Threshold: ≥20 unique IPs in the same /16 in the last 5 minutes.
func (s *Storage) detectPortScan(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	const (
		minUniqueIPs  = 20
		windowMinutes = 5
	)

	rows, err := s.db.QueryContext(ctx, `
		WITH parsed AS (
			SELECT user_email,
			       SUBSTR(destination, 1, INSTR(destination, ':') - 1) AS ip,
			       SUBSTR(destination, INSTR(destination, ':') + 1) AS port
			FROM user_destinations
			WHERE last_seen > datetime('now', ?)
			  AND destination GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:[0-9]*'
		)
		SELECT user_email,
		       SUBSTR(ip, 1, INSTR(ip, '.') + INSTR(SUBSTR(ip, INSTR(ip, '.') + 1), '.') - 1) AS slash16,
		       port,
		       COUNT(DISTINCT ip) AS uniq_ips
		FROM parsed
		WHERE port NOT IN ('80', '443', '53', '8080')
		GROUP BY user_email, slash16, port
		HAVING uniq_ips >= ?
		ORDER BY uniq_ips DESC
		LIMIT 50
	`, fmt.Sprintf("-%d minutes", windowMinutes), minUniqueIPs)
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
// destinations is almost always malicious from a VPN user: ssh/telnet/smtp
// (credential stuffing, spam), SMB/RDP/VNC (brute force), database ports
// (exposed-DB scanning), memcache/redis/mongo (open-instance looting).
var abusePortList = []string{
	"22", "23", "25", "135", "139", "445", "465", "587",
	"1433", "3306", "3389", "5432", "5900", "6379", "11211", "27017",
}

// detectAbusePortFlood flags brute-force / spam patterns: many distinct
// destinations on one abuse port within 10 min. Unlike port_scan this one
// does NOT require /16 concentration — a campaign against random SMTP
// servers or an SSH dictionary sweep naturally hits scattered networks.
//
// Threshold: ≥15 unique destinations (IP or domain) on one port.
func (s *Storage) detectAbusePortFlood(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	const (
		minUniqueDests = 15
		windowMinutes  = 10
	)

	placeholders := make([]string, len(abusePortList))
	args := make([]interface{}, 0, len(abusePortList)+2)
	args = append(args, fmt.Sprintf("-%d minutes", windowMinutes))
	for i, p := range abusePortList {
		placeholders[i] = "?"
		args = append(args, p)
	}
	args = append(args, minUniqueDests)

	query := fmt.Sprintf(`
		SELECT user_email,
		       SUBSTR(destination, INSTR(destination, ':') + 1) AS port,
		       COUNT(DISTINCT destination) AS uniq_dst
		FROM user_destinations
		WHERE last_seen > datetime('now', ?)
		  AND SUBSTR(destination, INSTR(destination, ':') + 1) IN (%s)
		GROUP BY user_email, port
		HAVING uniq_dst >= ?
		ORDER BY uniq_dst DESC
		LIMIT 50
	`, strings.Join(placeholders, ","))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*threatintel.Anomaly
	for rows.Next() {
		var (
			email, port string
			uniq        int
		)
		if err := rows.Scan(&email, &port, &uniq); err != nil {
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
// allow-list (e.g. port_scan + abuse_port_flood) within `since`. Unlike
// GetAnomalies this is narrowed to active attack-type detections so the UI
// can render a dedicated "Attacks" screen without the activity_spike /
// night_activity noise that dominates the generic anomalies list.
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

	placeholders := make([]string, len(types))
	args := make([]interface{}, 0, len(types)+2)
	for i, t := range types {
		placeholders[i] = "?"
		args = append(args, t)
	}
	// modernc.org/sqlite binds time.Time → DATETIME correctly but string →
	// string comparison on a DATETIME column does not match rows written from
	// time.Time. Pass the threshold as time.Time so the driver handles it.
	args = append(args, time.Now().Add(-since).UTC())

	resolvedClause := "AND resolved = 0"
	if includeResolved {
		resolvedClause = ""
	}

	query := fmt.Sprintf(`
		SELECT id, type, severity, user_email, description, details, detected_at, resolved
		FROM anomalies
		WHERE type IN (%s)
		  AND detected_at >= ?
		  %s
		ORDER BY detected_at DESC
		LIMIT ?
	`, strings.Join(placeholders, ","), resolvedClause)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAnomalies(rows)
}

// benignHighVolumePorts are ports where a single user legitimately touches
// many distinct IPs in normal operation. Exclude them from burst-scan so
// NTP clients, BitTorrent peers, XMPP messengers and RTSP cameras don't
// get flagged as mamka-hackers.
var benignHighVolumePorts = []string{
	"80", "443", "53", "8080", "8443", // web/DNS
	"123",         // NTP
	"554",         // RTSP (cameras)
	"5222", "5223", // XMPP (Telegram, WhatsApp signalling)
	"6881", "6882", "6883", "6884", "6885", "6886", "6887", "6888", "6889", // BitTorrent
	"51413",       // deluge/qBittorrent default
}

// detectBurstScanAnyTarget flags "target-agnostic" scans: a user hits many
// distinct IPv4 destinations on one non-web, non-benign port inside a single
// minute. Unlike detectPortScan (which needs a /16 concentration) this catches
// SSH/RDP/RTSP/exposed-service sweeps against scattered networks — the thing
// mamka-hackers actually do.
//
// Threshold: ≥15 unique IPs on one port in 60 seconds.
func (s *Storage) detectBurstScanAnyTarget(ctx context.Context, now time.Time) ([]*threatintel.Anomaly, error) {
	const (
		minUniqueIPs = 15
		windowMin    = 1
	)

	placeholders := make([]string, len(benignHighVolumePorts))
	args := make([]interface{}, 0, len(benignHighVolumePorts)+1)
	args = append(args, fmt.Sprintf("-%d minutes", windowMin))
	for i, p := range benignHighVolumePorts {
		placeholders[i] = "?"
		args = append(args, p)
	}

	// first_seen is the signal — it marks the *first time* we saw this
	// (user, destination) pair, which is exactly what a scanner generates
	// in bulk (each probe is a brand-new dest). Repeat traffic doesn't
	// qualify here; port_scan/abuse_port_flood cover steady-state flood.
	query := fmt.Sprintf(`
		WITH parsed AS (
			SELECT user_email,
			       SUBSTR(destination, 1, INSTR(destination, ':') - 1) AS ip,
			       SUBSTR(destination, INSTR(destination, ':') + 1) AS port
			FROM user_destinations
			WHERE first_seen > datetime('now', ?)
			  AND destination GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:[0-9]*'
		)
		SELECT user_email, port, COUNT(DISTINCT ip) AS uniq_ips
		FROM parsed
		WHERE port NOT IN (%s)
		GROUP BY user_email, port
		HAVING uniq_ips >= %d
		ORDER BY uniq_ips DESC
		LIMIT 50
	`, strings.Join(placeholders, ","), minUniqueIPs)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*threatintel.Anomaly
	for rows.Next() {
		var (
			email, port string
			uniq        int
		)
		if err := rows.Scan(&email, &port, &uniq); err != nil {
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
