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
