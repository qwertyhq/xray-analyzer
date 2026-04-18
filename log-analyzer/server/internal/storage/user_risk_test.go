package storage

import (
	"context"
	"testing"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

func seedThreatMatch(t *testing.T, s *Storage, email, threatType string, at time.Time) {
	t.Helper()
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO threat_matches (user_email, node_id, source_ip, destination, threat_type, source, confidence, matched_at)
		VALUES ($1, 'node1', '1.2.3.4', 'bad.com', $2, 'test', 80, $3)
	`, email, threatType, at)
	if err != nil {
		t.Fatalf("seedThreatMatch: %v", err)
	}
}

func TestUserRisk_SaveAndGet(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC()
	profile := &threatintel.UserRiskProfile{
		UserEmail:       "risk-user@test.com",
		RiskLevel:       threatintel.RiskLevelMedium,
		RiskScore:       35,
		TotalMatches:    10,
		ThreatsByType:   map[string]int{"malware": 5, "tor": 5},
		UniqueCountries: 2,
		AnomalyCount:    1,
		FirstSeen:       now.Add(-24 * time.Hour),
		LastActivity:    now,
		DaysActive:      3,
		TopDomains:      []string{"bad.com", "evil.net"},
		RiskFactors: []threatintel.RiskFactor{
			{Type: "total_matches", Description: "10 total threat matches", Weight: 20, DetectedAt: "2026-01-01"},
		},
		TrendDirection: "stable",
	}

	if err := s.SaveUserRiskProfile(ctx, profile); err != nil {
		t.Fatalf("SaveUserRiskProfile: %v", err)
	}

	got, err := s.GetUserRiskProfile(ctx, "risk-user@test.com")
	if err != nil {
		t.Fatalf("GetUserRiskProfile: %v", err)
	}

	if got.RiskScore != 35 {
		t.Errorf("RiskScore = %d, want 35", got.RiskScore)
	}
	if got.RiskLevel != threatintel.RiskLevelMedium {
		t.Errorf("RiskLevel = %q, want medium", got.RiskLevel)
	}
	if got.ThreatsByType["malware"] != 5 {
		t.Errorf("ThreatsByType[malware] = %d, want 5", got.ThreatsByType["malware"])
	}
	if len(got.TopDomains) != 2 {
		t.Errorf("TopDomains len = %d, want 2", len(got.TopDomains))
	}
	if len(got.RiskFactors) != 1 {
		t.Errorf("RiskFactors len = %d, want 1", len(got.RiskFactors))
	}
}

func TestUserRisk_GetProfileCalculatesFreshIfMissing(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "fresh-calc@test.com"
	now := time.Now().UTC()

	// Insert some threat matches so score > 0
	seedThreatMatch(t, s, email, "malware", now)
	seedThreatMatch(t, s, email, "malware", now)

	profile, err := s.GetUserRiskProfile(ctx, email)
	if err != nil {
		t.Fatalf("GetUserRiskProfile: %v", err)
	}
	if profile.UserEmail != email {
		t.Errorf("UserEmail = %q, want %q", profile.UserEmail, email)
	}
	if profile.TotalMatches < 2 {
		t.Errorf("TotalMatches = %d, want >= 2", profile.TotalMatches)
	}
	if profile.RiskScore <= 0 {
		t.Error("RiskScore should be > 0 after matches")
	}
}

func TestUserRisk_CalculateRiskProfile(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "calc-risk@test.com"
	now := time.Now().UTC()

	// Seed enough matches to get a non-zero risk score
	for i := 0; i < 5; i++ {
		seedThreatMatch(t, s, email, "tor", now)
	}

	profile, err := s.CalculateUserRiskProfile(ctx, email)
	if err != nil {
		t.Fatalf("CalculateUserRiskProfile: %v", err)
	}
	if profile.TotalMatches < 5 {
		t.Errorf("TotalMatches = %d, want >= 5", profile.TotalMatches)
	}
	if profile.ThreatsByType["tor"] < 5 {
		t.Errorf("ThreatsByType[tor] = %d, want >= 5", profile.ThreatsByType["tor"])
	}
	// Tor usage adds 10 pts + matches add more
	if profile.RiskScore <= 0 {
		t.Error("RiskScore should be > 0")
	}
	if profile.TrendDirection == "" {
		t.Error("TrendDirection should not be empty")
	}
}

func TestUserRisk_GetUserRiskSummary(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC()
	profiles := []struct {
		email string
		score int
		level threatintel.RiskLevel
	}{
		{"summary-low@test.com", 10, threatintel.RiskLevelLow},
		{"summary-high@test.com", 60, threatintel.RiskLevelHigh},
	}

	for _, p := range profiles {
		if err := s.SaveUserRiskProfile(ctx, &threatintel.UserRiskProfile{
			UserEmail:      p.email,
			RiskLevel:      p.level,
			RiskScore:      p.score,
			ThreatsByType:  map[string]int{},
			RiskFactors:    []threatintel.RiskFactor{},
			TopDomains:     []string{},
			TrendDirection: "stable",
			FirstSeen:      now,
			LastActivity:   now,
		}); err != nil {
			t.Fatalf("SaveUserRiskProfile %s: %v", p.email, err)
		}
	}

	summary, err := s.GetUserRiskSummary(ctx)
	if err != nil {
		t.Fatalf("GetUserRiskSummary: %v", err)
	}
	if summary.TotalUsers < 2 {
		t.Errorf("TotalUsers = %d, want >= 2", summary.TotalUsers)
	}
	if summary.AverageRiskScore <= 0 {
		t.Error("AverageRiskScore should be > 0")
	}
	if len(summary.ByRiskLevel) == 0 {
		t.Error("ByRiskLevel should not be empty")
	}
	// The high-risk user (score=60) should appear in HighRiskUsers
	found := false
	for _, u := range summary.HighRiskUsers {
		if u.UserEmail == "summary-high@test.com" {
			found = true
		}
	}
	if !found {
		t.Error("high-risk user not found in HighRiskUsers")
	}
}

func TestUserRisk_RecalculateAll(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	emails := []string{"recalc-a@test.com", "recalc-b@test.com"}
	now := time.Now().UTC()
	for _, email := range emails {
		seedThreatMatch(t, s, email, "malware", now)
	}

	if err := s.RecalculateAllUserRiskProfiles(ctx); err != nil {
		t.Fatalf("RecalculateAllUserRiskProfiles: %v", err)
	}

	for _, email := range emails {
		p, err := s.GetUserRiskProfile(ctx, email)
		if err != nil {
			t.Errorf("GetUserRiskProfile %s: %v", email, err)
			continue
		}
		if p.TotalMatches < 1 {
			t.Errorf("%s: TotalMatches = %d, want >= 1", email, p.TotalMatches)
		}
	}
}
