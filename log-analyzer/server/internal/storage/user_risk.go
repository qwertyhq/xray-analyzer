package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// ==================== User Risk Profile Functions ====================

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
		WHERE user_email = $1
	`, email)

	var firstSeen, lastActivity *time.Time
	if err := row.Scan(&profile.TotalMatches, &firstSeen, &lastActivity, &profile.DaysActive); err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if firstSeen != nil {
		profile.FirstSeen = *firstSeen
	}
	if lastActivity != nil {
		profile.LastActivity = *lastActivity
	}

	// Get threats by type
	rows, err := s.db.QueryContext(ctx, `
		SELECT threat_type, COUNT(*) as cnt
		FROM threat_matches
		WHERE user_email = $1
		GROUP BY threat_type
	`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var threatType string
		var count int
		if err := rows.Scan(&threatType, &count); err != nil {
			return nil, fmt.Errorf("scan threat type: %w", err)
		}
		profile.ThreatsByType[threatType] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate threat types: %w", err)
	}

	// Get unique countries
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT country_code)
		FROM user_locations
		WHERE user_email = $1
	`, email)
	if err := row.Scan(&profile.UniqueCountries); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("scan unique countries: %w", err)
	}

	// Get anomaly count
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM anomalies
		WHERE user_email = $1 AND resolved = 0
	`, email)
	if err := row.Scan(&profile.AnomalyCount); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("scan anomaly count: %w", err)
	}

	// Get top domains
	domainRows, err := s.db.QueryContext(ctx, `
		SELECT destination, COUNT(*) as cnt
		FROM threat_matches
		WHERE user_email = $1
		GROUP BY destination
		ORDER BY cnt DESC
		LIMIT 5
	`, email)
	if err != nil {
		return nil, fmt.Errorf("query top domains: %w", err)
	}
	defer domainRows.Close()
	for domainRows.Next() {
		var domain string
		var cnt int
		if err := domainRows.Scan(&domain, &cnt); err != nil {
			return nil, fmt.Errorf("scan top domain: %w", err)
		}
		profile.TopDomains = append(profile.TopDomains, domain)
	}
	if err := domainRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top domains: %w", err)
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
	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threat_matches
		WHERE user_email = $1 AND matched_at > NOW() - INTERVAL '7 days'
	`, email)
	if err := row.Scan(&recent); err != nil {
		return "stable" // Default on error
	}

	// Count matches in previous 7 days
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threat_matches
		WHERE user_email = $1
		AND matched_at > NOW() - INTERVAL '14 days'
		AND matched_at <= NOW() - INTERVAL '7 days'
	`, email)
	if err := row.Scan(&previous); err != nil {
		return "stable" // Default on error
	}

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
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
		ON CONFLICT (user_email) DO UPDATE SET
			risk_level = EXCLUDED.risk_level,
			risk_score = EXCLUDED.risk_score,
			total_matches = EXCLUDED.total_matches,
			threats_by_type = EXCLUDED.threats_by_type,
			unique_countries = EXCLUDED.unique_countries,
			anomaly_count = EXCLUDED.anomaly_count,
			last_activity = EXCLUDED.last_activity,
			days_active = EXCLUDED.days_active,
			top_domains = EXCLUDED.top_domains,
			risk_factors = EXCLUDED.risk_factors,
			trend_direction = EXCLUDED.trend_direction,
			updated_at = NOW()
	`, profile.UserEmail, string(profile.RiskLevel), profile.RiskScore,
		profile.TotalMatches, string(threatsByType), profile.UniqueCountries,
		profile.AnomalyCount, profile.FirstSeen, profile.LastActivity,
		profile.DaysActive, string(topDomains), string(riskFactors), profile.TrendDirection)

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
	var firstSeen, lastActivity *time.Time
	var riskLevel string

	row := s.db.QueryRowContext(ctx, `
		SELECT user_email, risk_level, risk_score, total_matches, threats_by_type,
			   unique_countries, anomaly_count, first_seen, last_activity,
			   days_active, top_domains, risk_factors, trend_direction
		FROM user_risk_profiles
		WHERE user_email = $1
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
		if err := json.Unmarshal([]byte(threatsByType.String), &profile.ThreatsByType); err != nil {
			return nil, fmt.Errorf("unmarshal threats_by_type: %w", err)
		}
	}
	if topDomains.Valid {
		if err := json.Unmarshal([]byte(topDomains.String), &profile.TopDomains); err != nil {
			return nil, fmt.Errorf("unmarshal top_domains: %w", err)
		}
	}
	if riskFactors.Valid {
		if err := json.Unmarshal([]byte(riskFactors.String), &profile.RiskFactors); err != nil {
			return nil, fmt.Errorf("unmarshal risk_factors: %w", err)
		}
	}
	if firstSeen != nil {
		profile.FirstSeen = *firstSeen
	}
	if lastActivity != nil {
		profile.LastActivity = *lastActivity
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
	if err := row.Scan(&summary.TotalUsers, &summary.AverageRiskScore); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("scan user risk summary: %w", err)
	}

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
		if err := rows.Scan(&level, &count); err != nil {
			return nil, fmt.Errorf("scan risk level: %w", err)
		}
		summary.ByRiskLevel[level] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate risk levels: %w", err)
	}

	// Get high risk users (score >= 50)
	highRiskRows, err := s.db.QueryContext(ctx, `
		SELECT p.user_email, COALESCE(r.username, p.user_email) as display_name,
			   p.risk_level, p.risk_score, p.total_matches, p.threats_by_type,
			   p.unique_countries, p.anomaly_count, p.first_seen, p.last_activity,
			   p.days_active, p.top_domains, p.risk_factors, p.trend_direction
		FROM user_risk_profiles p
		LEFT JOIN remna_users r ON (
			p.user_email = r.username
			OR CAST(r.id AS TEXT) = p.user_email
		)
		WHERE p.risk_score >= 50
		ORDER BY p.risk_score DESC
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
		var firstSeen, lastActivity *time.Time
		var riskLevel string

		if err := highRiskRows.Scan(&profile.UserEmail, &profile.Username, &riskLevel, &profile.RiskScore,
			&profile.TotalMatches, &threatsByType, &profile.UniqueCountries,
			&profile.AnomalyCount, &firstSeen, &lastActivity,
			&profile.DaysActive, &topDomains, &riskFactors, &profile.TrendDirection); err != nil {
			continue // Skip malformed rows
		}

		profile.RiskLevel = threatintel.RiskLevel(riskLevel)
		if threatsByType.Valid {
			json.Unmarshal([]byte(threatsByType.String), &profile.ThreatsByType) // Non-critical, use defaults on error
		}
		if topDomains.Valid {
			json.Unmarshal([]byte(topDomains.String), &profile.TopDomains)
		}
		if riskFactors.Valid {
			json.Unmarshal([]byte(riskFactors.String), &profile.RiskFactors)
		}
		if firstSeen != nil {
			profile.FirstSeen = *firstSeen
		}
		if lastActivity != nil {
			profile.LastActivity = *lastActivity
		}

		summary.HighRiskUsers = append(summary.HighRiskUsers, profile)
	}
	if err := highRiskRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate high risk users: %w", err)
	}

	// Count recent escalations (risk increased in last 24h)
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_risk_profiles
		WHERE trend_direction = 'up' AND updated_at > NOW() - INTERVAL '24 hours'
	`)
	if err := row.Scan(&summary.RecentEscalations); err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("scan recent escalations: %w", err)
	}

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
		if err := rows.Scan(&email); err != nil {
			return fmt.Errorf("scan email: %w", err)
		}
		emails = append(emails, email)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate emails: %w", err)
	}

	for _, email := range emails {
		if _, err := s.CalculateUserRiskProfile(ctx, email); err != nil {
			return fmt.Errorf("calculate risk profile for %s: %w", email, err)
		}
	}

	return nil
}
