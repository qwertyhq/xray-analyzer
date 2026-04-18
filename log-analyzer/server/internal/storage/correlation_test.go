package storage

import (
	"context"
	"testing"
	"time"
)

func TestRecordIPUserMapping_UpsertAndRead(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// First insert
	if err := s.RecordIPUserMapping(ctx, "1.2.3.4", "alice@example.com", "node1"); err != nil {
		t.Fatalf("first RecordIPUserMapping: %v", err)
	}
	// Second call — should upsert (request_count++)
	if err := s.RecordIPUserMapping(ctx, "1.2.3.4", "alice@example.com", "node1"); err != nil {
		t.Fatalf("second RecordIPUserMapping: %v", err)
	}

	users, err := s.GetUsersForIP(ctx, "1.2.3.4")
	if err != nil {
		t.Fatalf("GetUsersForIP: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	u := users[0]
	if u.UserEmail != "alice@example.com" {
		t.Errorf("expected alice, got %s", u.UserEmail)
	}
	if u.RequestCount < 2 {
		t.Errorf("expected request_count >= 2, got %d", u.RequestCount)
	}
}

func TestRecordHWIDUserMapping_UpsertAndRead(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.RecordHWIDUserMapping(ctx, "hwid-abc", "bob@example.com", "android"); err != nil {
		t.Fatalf("first RecordHWIDUserMapping: %v", err)
	}
	if err := s.RecordHWIDUserMapping(ctx, "hwid-abc", "bob@example.com", "android"); err != nil {
		t.Fatalf("second RecordHWIDUserMapping: %v", err)
	}

	users, err := s.GetUsersForHWID(ctx, "hwid-abc")
	if err != nil {
		t.Fatalf("GetUsersForHWID: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	u := users[0]
	if u.UserEmail != "bob@example.com" {
		t.Errorf("expected bob, got %s", u.UserEmail)
	}
	if u.RequestCount < 2 {
		t.Errorf("expected request_count >= 2, got %d", u.RequestCount)
	}
	if u.Platform != "android" {
		t.Errorf("expected platform android, got %s", u.Platform)
	}
}

func TestRecordUserFingerprint_UpsertAndRead(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.RecordUserFingerprint(ctx, "carol@example.com", "10.0.0.1", "fp-hwid", "Mozilla/5.0", "node2"); err != nil {
		t.Fatalf("first RecordUserFingerprint: %v", err)
	}
	if err := s.RecordUserFingerprint(ctx, "carol@example.com", "10.0.0.1", "fp-hwid", "Mozilla/5.0", "node2"); err != nil {
		t.Fatalf("second RecordUserFingerprint: %v", err)
	}

	fps, err := s.GetUserFingerprints(ctx, "carol@example.com")
	if err != nil {
		t.Fatalf("GetUserFingerprints: %v", err)
	}
	if len(fps) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(fps))
	}
	fp := fps[0]
	if fp.SessionCount < 2 {
		t.Errorf("expected session_count >= 2, got %d", fp.SessionCount)
	}
	if fp.HWID != "fp-hwid" {
		t.Errorf("expected hwid fp-hwid, got %s", fp.HWID)
	}
}

func TestGetSharedIPUsers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Two users on the same IP
	s.RecordIPUserMapping(ctx, "5.5.5.5", "alice@example.com", "n1")
	s.RecordIPUserMapping(ctx, "5.5.5.5", "bob@example.com", "n1")

	shared, err := s.GetSharedIPUsers(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetSharedIPUsers: %v", err)
	}
	if len(shared) == 0 {
		t.Fatal("expected at least one shared user")
	}
	found := false
	for _, u := range shared {
		if u.UserEmail == "bob@example.com" {
			found = true
			if u.Reason != "shared_ip" {
				t.Errorf("expected reason shared_ip, got %s", u.Reason)
			}
		}
	}
	if !found {
		t.Error("bob not found in shared IP users")
	}
}

func TestGetSharedHWIDUsers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	s.RecordHWIDUserMapping(ctx, "shared-hwid", "alice@example.com", "ios")
	s.RecordHWIDUserMapping(ctx, "shared-hwid", "dave@example.com", "ios")

	shared, err := s.GetSharedHWIDUsers(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetSharedHWIDUsers: %v", err)
	}
	if len(shared) == 0 {
		t.Fatal("expected at least one shared user")
	}
	if shared[0].Reason != "shared_hwid" {
		t.Errorf("expected reason shared_hwid, got %s", shared[0].Reason)
	}
}

func TestGetTopSharedIPs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// IP shared by two users
	s.RecordIPUserMapping(ctx, "9.9.9.9", "u1@example.com", "n1")
	s.RecordIPUserMapping(ctx, "9.9.9.9", "u2@example.com", "n1")
	// Unshared IP
	s.RecordIPUserMapping(ctx, "8.8.8.8", "u1@example.com", "n1")

	results, err := s.GetTopSharedIPs(ctx, 10)
	if err != nil {
		t.Fatalf("GetTopSharedIPs: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one shared IP")
	}
	// Only 9.9.9.9 should be in results (user_count > 1)
	for _, r := range results {
		if r.UserCount < 2 {
			t.Errorf("IP %s has user_count %d, expected >= 2", r.IPAddress, r.UserCount)
		}
	}
	if results[0].IPAddress != "9.9.9.9" {
		t.Errorf("expected 9.9.9.9 first, got %s", results[0].IPAddress)
	}
}

func TestGetTopSharedHWIDs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// HWID shared by three users
	s.RecordHWIDUserMapping(ctx, "multi-hwid", "ua@example.com", "android")
	s.RecordHWIDUserMapping(ctx, "multi-hwid", "ub@example.com", "android")
	s.RecordHWIDUserMapping(ctx, "multi-hwid", "uc@example.com", "android")
	// Unshared
	s.RecordHWIDUserMapping(ctx, "solo-hwid", "ua@example.com", "ios")

	results, err := s.GetTopSharedHWIDs(ctx, 10)
	if err != nil {
		t.Fatalf("GetTopSharedHWIDs: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one shared HWID")
	}
	if results[0].HWID != "multi-hwid" {
		t.Errorf("expected multi-hwid first, got %s", results[0].HWID)
	}
	if results[0].UserCount < 3 {
		t.Errorf("expected user_count >= 3, got %d", results[0].UserCount)
	}
}

func TestGetCorrelationStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Seed shared IP
	s.RecordIPUserMapping(ctx, "7.7.7.7", "x@example.com", "n")
	s.RecordIPUserMapping(ctx, "7.7.7.7", "y@example.com", "n")

	// Seed shared HWID
	s.RecordHWIDUserMapping(ctx, "h1", "x@example.com", "win")
	s.RecordHWIDUserMapping(ctx, "h1", "y@example.com", "win")

	// Seed fingerprint
	s.RecordUserFingerprint(ctx, "x@example.com", "7.7.7.7", "h1", "", "n")

	stats, err := s.GetCorrelationStats(ctx)
	if err != nil {
		t.Fatalf("GetCorrelationStats: %v", err)
	}
	if stats.SharedIPs < 1 {
		t.Errorf("expected SharedIPs >= 1, got %d", stats.SharedIPs)
	}
	if stats.SharedHWIDs < 1 {
		t.Errorf("expected SharedHWIDs >= 1, got %d", stats.SharedHWIDs)
	}
	if stats.TotalFingerprints < 1 {
		t.Errorf("expected TotalFingerprints >= 1, got %d", stats.TotalFingerprints)
	}
}

func TestUpsertAndGetUserAIProfile(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	profile := &UserAIProfile{
		UserEmail:          "ai@example.com",
		UniqueIPs:          3,
		UniqueHWIDs:        2,
		UniqueFingerprints: 5,
		TotalRequests:      100,
		TotalSessions:      20,
		RiskScore:          42,
		RiskFactors:        []string{"shared_ip", "high_traffic"},
		ThreatCategories:   map[string]int{"malware": 3},
		ClusterIDs:         []string{"c1"},
		TypicalHours:       []int{10, 14, 20},
		FirstSeen:          now,
		LastSeen:           now,
	}

	if err := s.UpsertUserAIProfile(ctx, profile); err != nil {
		t.Fatalf("UpsertUserAIProfile: %v", err)
	}

	got, err := s.GetUserAIProfile(ctx, "ai@example.com")
	if err != nil {
		t.Fatalf("GetUserAIProfile: %v", err)
	}
	if got == nil {
		t.Fatal("expected profile, got nil")
	}
	if got.RiskScore != 42 {
		t.Errorf("expected RiskScore=42, got %d", got.RiskScore)
	}
	if got.UniqueIPs != 3 {
		t.Errorf("expected UniqueIPs=3, got %d", got.UniqueIPs)
	}
	if len(got.RiskFactors) != 2 {
		t.Errorf("expected 2 risk factors, got %v", got.RiskFactors)
	}
	if got.ThreatCategories["malware"] != 3 {
		t.Errorf("expected threat_categories.malware=3, got %d", got.ThreatCategories["malware"])
	}

	// Upsert again with updated values — first_seen should stay pinned
	profile.RiskScore = 99
	profile.UniqueIPs = 10
	if err := s.UpsertUserAIProfile(ctx, profile); err != nil {
		t.Fatalf("second UpsertUserAIProfile: %v", err)
	}
	got2, err := s.GetUserAIProfile(ctx, "ai@example.com")
	if err != nil {
		t.Fatalf("second GetUserAIProfile: %v", err)
	}
	if got2.RiskScore != 99 {
		t.Errorf("expected RiskScore=99 after update, got %d", got2.RiskScore)
	}
	if got2.UniqueIPs != 10 {
		t.Errorf("expected UniqueIPs=10 after update, got %d", got2.UniqueIPs)
	}
}

func TestGetUserAIProfile_NotFound(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	got, err := s.GetUserAIProfile(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("GetUserAIProfile on missing: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing profile, got %+v", got)
	}
}

func TestGetAllUserAIProfiles(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now()
	// Insert two profiles
	p1 := &UserAIProfile{UserEmail: "high@example.com", RiskScore: 80, FirstSeen: now, LastSeen: now}
	p2 := &UserAIProfile{UserEmail: "low@example.com", RiskScore: 10, FirstSeen: now, LastSeen: now}
	s.UpsertUserAIProfile(ctx, p1)
	s.UpsertUserAIProfile(ctx, p2)

	// Only profiles with risk_score >= 50
	results, err := s.GetAllUserAIProfiles(ctx, 10, 50)
	if err != nil {
		t.Fatalf("GetAllUserAIProfiles: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 profile with risk >= 50, got %d", len(results))
	}
	if results[0].UserEmail != "high@example.com" {
		t.Errorf("expected high@example.com, got %s", results[0].UserEmail)
	}
}
