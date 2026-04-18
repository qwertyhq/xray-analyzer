package storage

import (
	"context"
	"testing"
)

func TestUpdateDNSHourlyStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Record a blocked and an unblocked query
	if err := s.UpdateDNSHourlyStats(ctx, true); err != nil {
		t.Fatalf("UpdateDNSHourlyStats(blocked=true): %v", err)
	}
	if err := s.UpdateDNSHourlyStats(ctx, false); err != nil {
		t.Fatalf("UpdateDNSHourlyStats(blocked=false): %v", err)
	}

	// Verify via GetDNSQueryStats
	stats, err := s.GetDNSQueryStats(ctx)
	if err != nil {
		t.Fatalf("GetDNSQueryStats: %v", err)
	}
	if len(stats.HourlyStats) == 0 {
		t.Fatal("expected at least one hourly stat entry")
	}
	h := stats.HourlyStats[0]
	if h.TotalQueries < 2 {
		t.Errorf("expected TotalQueries >= 2, got %d", h.TotalQueries)
	}
	if h.BlockedQueries < 1 {
		t.Errorf("expected BlockedQueries >= 1, got %d", h.BlockedQueries)
	}
}

func TestUpdateDNSDailyStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.UpdateDNSDailyStats(ctx, true); err != nil {
		t.Fatalf("UpdateDNSDailyStats(blocked=true): %v", err)
	}
	if err := s.UpdateDNSDailyStats(ctx, false); err != nil {
		t.Fatalf("UpdateDNSDailyStats(blocked=false): %v", err)
	}

	stats, err := s.GetDNSQueryStats(ctx)
	if err != nil {
		t.Fatalf("GetDNSQueryStats: %v", err)
	}
	if len(stats.DailyStats) == 0 {
		t.Fatal("expected at least one daily stat entry")
	}
	d := stats.DailyStats[0]
	if d.TotalQueries < 2 {
		t.Errorf("expected TotalQueries >= 2, got %d", d.TotalQueries)
	}
	if d.BlockedQueries < 1 {
		t.Errorf("expected BlockedQueries >= 1, got %d", d.BlockedQueries)
	}
}

func TestUpdateDNSDomainStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	domain := "evil.example.com"

	// First insert
	if err := s.UpdateDNSDomainStats(ctx, domain, "malware", "abuse.ch"); err != nil {
		t.Fatalf("first UpdateDNSDomainStats: %v", err)
	}
	// Second update (same domain, same type+source — no new entries in arrays)
	if err := s.UpdateDNSDomainStats(ctx, domain, "malware", "abuse.ch"); err != nil {
		t.Fatalf("second UpdateDNSDomainStats: %v", err)
	}
	// Third update with a new threat type
	if err := s.UpdateDNSDomainStats(ctx, domain, "phishing", "urlhaus"); err != nil {
		t.Fatalf("third UpdateDNSDomainStats: %v", err)
	}

	stats, err := s.GetDNSQueryStats(ctx)
	if err != nil {
		t.Fatalf("GetDNSQueryStats: %v", err)
	}
	if len(stats.TopDomains) == 0 {
		t.Fatal("expected at least one domain in TopDomains")
	}
	found := stats.TopDomains[0]
	if found.Domain != domain {
		t.Errorf("expected domain %q, got %q", domain, found.Domain)
	}
	if found.TotalHits < 3 {
		t.Errorf("expected TotalHits >= 3, got %d", found.TotalHits)
	}
	if len(found.ThreatTypes) < 2 {
		t.Errorf("expected at least 2 threat types, got %v", found.ThreatTypes)
	}
}

func TestUpdateUserDNSStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "alice@example.com"
	domain := "blocked.example.com"

	if err := s.UpdateUserDNSStats(ctx, email, domain, true); err != nil {
		t.Fatalf("UpdateUserDNSStats(blocked): %v", err)
	}
	if err := s.UpdateUserDNSStats(ctx, email, domain, false); err != nil {
		t.Fatalf("UpdateUserDNSStats(unblocked): %v", err)
	}

	users, err := s.GetTopUsersByDNS(ctx, 10)
	if err != nil {
		t.Fatalf("GetTopUsersByDNS: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("expected at least one user")
	}
	u := users[0]
	if u.UserEmail != email {
		t.Errorf("expected email %q, got %q", email, u.UserEmail)
	}
	if u.TotalQueries < 2 {
		t.Errorf("expected TotalQueries >= 2, got %d", u.TotalQueries)
	}
	if u.BlockedQueries < 1 {
		t.Errorf("expected BlockedQueries >= 1, got %d", u.BlockedQueries)
	}
}

func TestRecordDNSQuery(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	err := s.RecordDNSQuery(ctx, "bob@example.com", "ad.tracker.com", "ads", "adguard", true)
	if err != nil {
		t.Fatalf("RecordDNSQuery: %v", err)
	}
	// Unblocked query (no domain stats update)
	err = s.RecordDNSQuery(ctx, "bob@example.com", "google.com", "", "", false)
	if err != nil {
		t.Fatalf("RecordDNSQuery(unblocked): %v", err)
	}
}

func TestGetDNSAnalysisSummary(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Seed some data
	s.UpdateDNSDomainStats(ctx, "bad.com", "malware", "abuse.ch")
	s.UpdateDNSHourlyStats(ctx, true)
	s.UpdateDNSDailyStats(ctx, true)

	summary, err := s.GetDNSAnalysisSummary(ctx)
	if err != nil {
		t.Fatalf("GetDNSAnalysisSummary: %v", err)
	}
	if summary == nil {
		t.Fatal("summary is nil")
	}
	if summary.QueryStats == nil {
		t.Fatal("QueryStats is nil")
	}
	// TrendDirection must be one of the known values
	td := summary.TrendDirection
	if td != "up" && td != "down" && td != "stable" {
		t.Errorf("unexpected TrendDirection %q", td)
	}
}

func TestGetTopUsersByDNS_Empty(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	users, err := s.GetTopUsersByDNS(ctx, 10)
	if err != nil {
		t.Fatalf("GetTopUsersByDNS on empty DB: %v", err)
	}
	if users == nil {
		// nil slice is fine for empty result
		users = nil
	}
	_ = users
}
