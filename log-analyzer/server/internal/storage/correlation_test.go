package storage

import (
	"context"
	"testing"
	"time"
)

func TestRecordIPUserMapping_UpsertAndRead(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	aliceUUID := testUUID("corr-alice")

	// First insert
	if err := s.RecordIPUserMapping(ctx, "1.2.3.4", aliceUUID, "node1"); err != nil {
		t.Fatalf("first RecordIPUserMapping: %v", err)
	}
	// Second call — should upsert (request_count++)
	if err := s.RecordIPUserMapping(ctx, "1.2.3.4", aliceUUID, "node1"); err != nil {
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
	if u.UserEmail != aliceUUID {
		t.Errorf("expected %s, got %s", aliceUUID, u.UserEmail)
	}
	if u.RequestCount < 2 {
		t.Errorf("expected request_count >= 2, got %d", u.RequestCount)
	}
}

func TestRecordHWIDUserMapping_UpsertAndRead(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	bobUUID := testUUID("corr-bob")

	if err := s.RecordHWIDUserMapping(ctx, "hwid-abc", bobUUID, "android"); err != nil {
		t.Fatalf("first RecordHWIDUserMapping: %v", err)
	}
	if err := s.RecordHWIDUserMapping(ctx, "hwid-abc", bobUUID, "android"); err != nil {
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
	if u.UserEmail != bobUUID {
		t.Errorf("expected %s, got %s", bobUUID, u.UserEmail)
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

	carolUUID := testUUID("corr-carol")

	if err := s.RecordUserFingerprint(ctx, carolUUID, "10.0.0.1", "fp-hwid", "Mozilla/5.0", "node2"); err != nil {
		t.Fatalf("first RecordUserFingerprint: %v", err)
	}
	if err := s.RecordUserFingerprint(ctx, carolUUID, "10.0.0.1", "fp-hwid", "Mozilla/5.0", "node2"); err != nil {
		t.Fatalf("second RecordUserFingerprint: %v", err)
	}

	fps, err := s.GetUserFingerprints(ctx, carolUUID)
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

	aliceUUID := testUUID("shared-ip-alice")
	bobUUID := testUUID("shared-ip-bob")

	// Two users on the same IP
	s.RecordIPUserMapping(ctx, "5.5.5.5", aliceUUID, "n1")
	s.RecordIPUserMapping(ctx, "5.5.5.5", bobUUID, "n1")

	shared, err := s.GetSharedIPUsers(ctx, aliceUUID)
	if err != nil {
		t.Fatalf("GetSharedIPUsers: %v", err)
	}
	if len(shared) == 0 {
		t.Fatal("expected at least one shared user")
	}
	found := false
	for _, u := range shared {
		if u.UserEmail == bobUUID {
			found = true
			if u.Reason != "shared_ip" {
				t.Errorf("expected reason shared_ip, got %s", u.Reason)
			}
		}
	}
	if !found {
		t.Errorf("bob (%s) not found in shared IP users: %+v", bobUUID, shared)
	}
}

func TestGetSharedHWIDUsers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	aliceUUID := testUUID("shared-hwid-alice")
	daveUUID := testUUID("shared-hwid-dave")

	s.RecordHWIDUserMapping(ctx, "shared-hwid", aliceUUID, "ios")
	s.RecordHWIDUserMapping(ctx, "shared-hwid", daveUUID, "ios")

	shared, err := s.GetSharedHWIDUsers(ctx, aliceUUID)
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
	s.RecordIPUserMapping(ctx, "9.9.9.9", testUUID("top-ip-u1"), "n1")
	s.RecordIPUserMapping(ctx, "9.9.9.9", testUUID("top-ip-u2"), "n1")
	// Unshared IP
	s.RecordIPUserMapping(ctx, "8.8.8.8", testUUID("top-ip-u1"), "n1")

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
	s.RecordHWIDUserMapping(ctx, "multi-hwid", testUUID("top-hwid-ua"), "android")
	s.RecordHWIDUserMapping(ctx, "multi-hwid", testUUID("top-hwid-ub"), "android")
	s.RecordHWIDUserMapping(ctx, "multi-hwid", testUUID("top-hwid-uc"), "android")
	// Unshared
	s.RecordHWIDUserMapping(ctx, "solo-hwid", testUUID("top-hwid-ua"), "ios")

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

	xUUID := testUUID("corr-stats-x")
	yUUID := testUUID("corr-stats-y")

	// Seed shared IP
	s.RecordIPUserMapping(ctx, "7.7.7.7", xUUID, "n")
	s.RecordIPUserMapping(ctx, "7.7.7.7", yUUID, "n")

	// Seed shared HWID
	s.RecordHWIDUserMapping(ctx, "h1", xUUID, "win")
	s.RecordHWIDUserMapping(ctx, "h1", yUUID, "win")

	// Seed fingerprint
	s.RecordUserFingerprint(ctx, xUUID, "7.7.7.7", "h1", "", "n")

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

	aiEmail := testUUID("ai-profile-user")
	now := time.Now().Truncate(time.Second)
	profile := &UserAIProfile{
		UserEmail:          aiEmail,
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

	got, err := s.GetUserAIProfile(ctx, aiEmail)
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
	got2, err := s.GetUserAIProfile(ctx, aiEmail)
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

	got, err := s.GetUserAIProfile(ctx, testUUID("ai-nobody"))
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

	highEmail := testUUID("ai-high-risk")
	lowEmail := testUUID("ai-low-risk")
	now := time.Now()
	// Insert two profiles
	p1 := &UserAIProfile{UserEmail: highEmail, RiskScore: 80, FirstSeen: now, LastSeen: now}
	p2 := &UserAIProfile{UserEmail: lowEmail, RiskScore: 10, FirstSeen: now, LastSeen: now}
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
	if results[0].UserEmail != highEmail {
		t.Errorf("expected %s, got %s", highEmail, results[0].UserEmail)
	}
}
