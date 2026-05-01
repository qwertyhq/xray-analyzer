package storage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// seedThreatTypeStats inserts a row into threat_type_stats
func seedThreatTypeStats(t *testing.T, s *Storage, threatType string, count int64) {
	t.Helper()
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO threat_type_stats (threat_type, match_count, last_match)
		VALUES ($1, $2, $3)
		ON CONFLICT (threat_type) DO UPDATE SET
			match_count = threat_type_stats.match_count + $4,
			last_match = $5
	`, threatType, count, time.Now(), count, time.Now())
	if err != nil {
		t.Fatalf("seedThreatTypeStats: %v", err)
	}
}

// seedUserThreatStats inserts a row into user_threat_stats.
// email is resolved via ResolveUserEmailToUUID for consistency with the storage layer.
func seedUserThreatStats(t *testing.T, s *Storage, email, threatType string, count int64) {
	t.Helper()
	ctx := context.Background()
	userUUID, err := s.ResolveUserEmailToUUID(ctx, email)
	if err != nil {
		t.Fatalf("seedUserThreatStats ResolveUserEmailToUUID: %v", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_threat_stats (user_email, threat_type, match_count, last_match)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_email, threat_type) DO UPDATE SET
			match_count = user_threat_stats.match_count + $5,
			last_match = $6
	`, userUUID, threatType, count, time.Now(), count, time.Now())
	if err != nil {
		t.Fatalf("seedUserThreatStats: %v", err)
	}
}

// seedThreatHourlyStats inserts a row into threat_hourly_stats
func seedThreatHourlyStats(t *testing.T, s *Storage, hour, threatType string, count, unique int64) {
	t.Helper()
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO threat_hourly_stats (hour, threat_type, match_count, unique_users)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (hour, threat_type) DO UPDATE SET
			match_count = threat_hourly_stats.match_count + $5,
			unique_users = GREATEST(threat_hourly_stats.unique_users, $6)
	`, hour, threatType, count, unique, count, unique)
	if err != nil {
		t.Fatalf("seedThreatHourlyStats: %v", err)
	}
}

// seedThreatDailyStats inserts a row into threat_daily_stats
func seedThreatDailyStats(t *testing.T, s *Storage, day, threatType string, count, unique int64) {
	t.Helper()
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO threat_daily_stats (day, threat_type, match_count, unique_users)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (day, threat_type) DO UPDATE SET
			match_count = threat_daily_stats.match_count + $5,
			unique_users = GREATEST(threat_daily_stats.unique_users, $6)
	`, day, threatType, count, unique, count, unique)
	if err != nil {
		t.Fatalf("seedThreatDailyStats: %v", err)
	}
}

func TestGetThreatStats_Basic(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Seed threat_stats_agg singleton (schema.sql inserts id=1 with 0; UPDATE it)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO threat_stats_agg (id, total_matches) VALUES (1, 42)
		ON CONFLICT (id) DO UPDATE SET total_matches = EXCLUDED.total_matches
	`)
	if err != nil {
		t.Fatalf("seed threat_stats_agg: %v", err)
	}

	seedThreatTypeStats(t, s, "malware", 20)
	seedThreatTypeStats(t, s, "phishing", 15)

	stats, err := s.GetThreatStats(ctx)
	if err != nil {
		t.Fatalf("GetThreatStats: %v", err)
	}
	if stats.TotalMatches != 42 {
		t.Errorf("expected TotalMatches=42, got %d", stats.TotalMatches)
	}
	if stats.IndicatorsByType["malware"] != 20 {
		t.Errorf("expected malware=20, got %d", stats.IndicatorsByType["malware"])
	}
	if stats.IndicatorsByType["phishing"] != 15 {
		t.Errorf("expected phishing=15, got %d", stats.IndicatorsByType["phishing"])
	}
}

func TestGetTopUsersByCategory(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	aliceEmail := testUUID("alice")
	bobEmail := testUUID("bob")
	carolEmail := testUUID("carol")

	seedUserThreatStats(t, s, aliceEmail, "porn", 50)
	seedUserThreatStats(t, s, bobEmail, "porn", 30)
	seedUserThreatStats(t, s, carolEmail, "gambling", 10)

	// Add some domain entries for alice
	aliceUUID, _ := uuid.Parse(aliceEmail)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_threat_domains (user_email, threat_type, domain, hit_count)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING
	`, aliceUUID, "porn", "adult.example.com", 5)
	if err != nil {
		t.Fatalf("seed user_threat_domains: %v", err)
	}

	results, err := s.GetTopUsersByCategory(ctx, "porn", 10)
	if err != nil {
		t.Fatalf("GetTopUsersByCategory: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 users for porn, got %d", len(results))
	}
	if results[0].UserEmail != aliceEmail {
		t.Errorf("expected alice first, got %s", results[0].UserEmail)
	}
	if results[0].MatchCount != 50 {
		t.Errorf("expected MatchCount=50, got %d", results[0].MatchCount)
	}
	// alice should have the domain populated
	if len(results[0].Domains) == 0 {
		t.Error("expected domains populated for alice")
	}
}

func TestGetTopUsersByAllCategories(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	seedUserThreatStats(t, s, testUUID("all-cat-user"), "gambling", 5)

	result, err := s.GetTopUsersByAllCategories(ctx, 5)
	if err != nil {
		t.Fatalf("GetTopUsersByAllCategories: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	// Expect all 6 category keys to be present
	for _, cat := range []string{"porn", "gambling", "social", "fakenews", "torrent", "tor"} {
		if _, ok := result[cat]; !ok {
			t.Errorf("missing category %q in result", cat)
		}
	}
	if len(result["gambling"]) != 1 {
		t.Errorf("expected 1 user for gambling, got %d", len(result["gambling"]))
	}
}

func TestGetRecentUsersByCategory_FromAgg(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	recentEmail := testUUID("recent-tor-user")
	seedUserThreatStats(t, s, recentEmail, "tor", 7)

	results, err := s.GetRecentUsersByCategory(ctx, "tor", 5)
	if err != nil {
		t.Fatalf("GetRecentUsersByCategory: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].UserEmail != recentEmail {
		t.Errorf("expected %s, got %s", recentEmail, results[0].UserEmail)
	}
}

func TestGetUsersByCategory_Pagination(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Insert 5 users for "social"
	for i := 0; i < 5; i++ {
		email := testUUID("social-user-" + string(rune('a'+i)))
		seedUserThreatStats(t, s, email, "social", int64(10-i))
	}

	// Page 1, size 3
	results, total, err := s.GetUsersByCategory(ctx, "social", 1, 3)
	if err != nil {
		t.Fatalf("GetUsersByCategory page 1: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 results on page 1, got %d", len(results))
	}

	// Page 2, size 3
	results2, total2, err := s.GetUsersByCategory(ctx, "social", 2, 3)
	if err != nil {
		t.Fatalf("GetUsersByCategory page 2: %v", err)
	}
	if total2 != 5 {
		t.Errorf("expected total=5 on page 2, got %d", total2)
	}
	if len(results2) != 2 {
		t.Errorf("expected 2 results on page 2, got %d", len(results2))
	}
}

func TestGetHourlyThreatStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now()
	currentHour := now.Format("2006-01-02T15")
	prevHour := now.Add(-1 * time.Hour).Format("2006-01-02T15")

	seedThreatHourlyStats(t, s, currentHour, "malware", 10, 3)
	seedThreatHourlyStats(t, s, prevHour, "phishing", 5, 2)
	// This one should be excluded (> 24 hours ago)
	oldHour := now.Add(-48 * time.Hour).Format("2006-01-02T15")
	seedThreatHourlyStats(t, s, oldHour, "malware", 999, 1)

	results, err := s.GetHourlyThreatStats(ctx, 24)
	if err != nil {
		t.Fatalf("GetHourlyThreatStats: %v", err)
	}
	// Should have 2 entries (not the old one)
	if len(results) < 2 {
		t.Errorf("expected >= 2 hourly entries, got %d", len(results))
	}
	// Verify old hour is not included
	for _, h := range results {
		if h.Hour == oldHour {
			t.Errorf("old hour %q should not be included in 24h window", oldHour)
		}
	}
}

func TestGetDailyThreatStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	today := time.Now().Format("2006-01-02")
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	old := time.Now().AddDate(0, 0, -60).Format("2006-01-02")

	seedThreatDailyStats(t, s, today, "malware", 100, 10)
	seedThreatDailyStats(t, s, yesterday, "phishing", 50, 5)
	seedThreatDailyStats(t, s, old, "malware", 9999, 1) // should be excluded

	results, err := s.GetDailyThreatStats(ctx, 30)
	if err != nil {
		t.Fatalf("GetDailyThreatStats: %v", err)
	}
	if len(results) < 2 {
		t.Errorf("expected >= 2 daily entries, got %d", len(results))
	}
	for _, d := range results {
		if d.Day == old {
			t.Errorf("old day %q should not be in 30-day window", old)
		}
	}
}

func TestGetTimeAnalytics(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Seed hourly and daily data
	currentHour := time.Now().Format("2006-01-02T15")
	seedThreatHourlyStats(t, s, currentHour, "malware", 42, 5)

	today := time.Now().Format("2006-01-02")
	seedThreatDailyStats(t, s, today, "malware", 100, 10)

	analytics, err := s.GetTimeAnalytics(ctx)
	if err != nil {
		t.Fatalf("GetTimeAnalytics: %v", err)
	}
	if analytics == nil {
		t.Fatal("analytics is nil")
	}
	if analytics.HourlyStats == nil {
		t.Error("HourlyStats is nil")
	}
	if analytics.DailyStats == nil {
		t.Error("DailyStats is nil")
	}
}

func TestGetRecentUsersByAllCategories(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	torEmail := testUUID("torrent-user-recent")
	seedUserThreatStats(t, s, torEmail, "torrent", 3)

	result, err := s.GetRecentUsersByAllCategories(ctx, 5)
	if err != nil {
		t.Fatalf("GetRecentUsersByAllCategories: %v", err)
	}
	if len(result["torrent"]) == 0 {
		t.Error("expected at least one user for torrent")
	}
}
