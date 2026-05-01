package storage

import (
	"context"
	"testing"
	"time"

	"github.com/xray-log-analyzer/server/internal/remnawave"
)

func TestUsers_UpdateAndGetAllUsers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := testUUID("user-stats-1")
	if err := s.UpdateUserStats(ctx, "node-1", email, 100, 5, "evil.com", 10, "1.2.3.4"); err != nil {
		t.Fatalf("UpdateUserStats: %v", err)
	}
	// Second call triggers ON CONFLICT DO UPDATE
	if err := s.UpdateUserStats(ctx, "node-1", email, 50, 0, "", 3, "1.2.3.5"); err != nil {
		t.Fatalf("UpdateUserStats (2nd): %v", err)
	}

	users, err := s.GetAllUsers(ctx, 100)
	if err != nil {
		t.Fatalf("GetAllUsers: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("expected at least one user")
	}

	var found bool
	for _, u := range users {
		if u.UserEmail == email {
			found = true
			if u.TotalRequests < 150 {
				t.Errorf("TotalRequests = %d, want >= 150 (accumulated)", u.TotalRequests)
			}
			if u.BlacklistHits < 5 {
				t.Errorf("BlacklistHits = %d, want >= 5", u.BlacklistHits)
			}
		}
	}
	if !found {
		t.Error("inserted user not found in GetAllUsers")
	}
}

func TestUsers_GetGlobalStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// node_stats is populated by UpdateNodeStats; user_stats by UpdateUserStats
	if err := s.UpdateNodeStats(ctx, "node-gs", 200, 0, 1); err != nil {
		t.Fatalf("UpdateNodeStats: %v", err)
	}
	if err := s.UpdateUserStats(ctx, "node-gs", testUUID("gs-user"), 200, 0, "", 5, ""); err != nil {
		t.Fatalf("UpdateUserStats: %v", err)
	}

	stats, err := s.GetGlobalStats(ctx)
	if err != nil {
		t.Fatalf("GetGlobalStats: %v", err)
	}
	if stats.TotalRequests <= 0 {
		t.Errorf("TotalRequests = %d, want > 0", stats.TotalRequests)
	}
	if stats.TotalUniqueUsers <= 0 {
		t.Errorf("TotalUniqueUsers = %d, want > 0", stats.TotalUniqueUsers)
	}
	if stats.TotalNodes <= 0 {
		t.Errorf("TotalNodes = %d, want > 0", stats.TotalNodes)
	}
}

func TestUsers_RecordAndGetIPHistory(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := testUUID("ip-history-user")
	if err := s.RecordUserIP(ctx, email, "10.10.10.1", "node-ip", "DE", "Germany", "Berlin"); err != nil {
		t.Fatalf("RecordUserIP: %v", err)
	}
	// Second call increments request_count
	if err := s.RecordUserIP(ctx, email, "10.10.10.1", "node-ip", "DE", "Germany", "Berlin"); err != nil {
		t.Fatalf("RecordUserIP (2nd): %v", err)
	}

	history, err := s.GetUserIPHistory(ctx, email)
	if err != nil {
		t.Fatalf("GetUserIPHistory: %v", err)
	}
	if len(history) == 0 {
		t.Fatal("expected IP history, got none")
	}
	if history[0].IPAddress != "10.10.10.1" {
		t.Errorf("IPAddress = %q, want 10.10.10.1", history[0].IPAddress)
	}
	if history[0].RequestCount < 2 {
		t.Errorf("RequestCount = %d, want >= 2", history[0].RequestCount)
	}
}

func TestUsers_GetUserDetails_WithRemnaUser(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Use a valid UUID for the Remnawave user
	detailUUID := testUUID("detail-user")

	// Insert a Remnawave user
	remnaUser := &remnawave.RemnaUserData{
		UUID:                 detailUUID,
		ID:                   999,
		Username:             "detailuser",
		Status:               "ACTIVE",
		TrafficLimitBytes:    5_000_000_000,
		UsedTrafficBytes:     1_000_000_000,
		TrafficLimitStrategy: "MONTH",
		CreatedAt:            now,
		UpdatedAt:            now,
		SyncedAt:             now,
	}
	if err := s.UpsertRemnaUser(ctx, remnaUser); err != nil {
		t.Fatalf("UpsertRemnaUser: %v", err)
	}

	// Insert user stats under the Remnawave user UUID (as it would be stored in schema v2)
	if err := s.UpdateUserStats(ctx, "node-detail", detailUUID, 300, 2, "bad.com", 15, "5.6.7.8"); err != nil {
		t.Fatalf("UpdateUserStats: %v", err)
	}

	details, err := s.GetUserDetails(ctx, "detailuser")
	if err != nil {
		t.Fatalf("GetUserDetails: %v", err)
	}
	if details == nil {
		t.Fatal("expected details, got nil")
	}
	if details.RemnaUUID != detailUUID {
		t.Errorf("RemnaUUID = %q, want %q", details.RemnaUUID, detailUUID)
	}
	if details.RemnaStatus != "ACTIVE" {
		t.Errorf("RemnaStatus = %q, want ACTIVE", details.RemnaStatus)
	}
}

func TestUsers_BuildFullSearchIDs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	u := &remnawave.RemnaUserData{
		UUID:                 testUUID("fsid-user"),
		ID:                   555,
		Username:             "fsiduser",
		Status:               "ACTIVE",
		TrafficLimitStrategy: "MONTH",
		CreatedAt:            now,
		UpdatedAt:            now,
		SyncedAt:             now,
	}
	if err := s.UpsertRemnaUser(ctx, u); err != nil {
		t.Fatalf("UpsertRemnaUser: %v", err)
	}

	ids := s.BuildFullSearchIDs(ctx, "fsiduser")
	if len(ids) == 0 {
		t.Fatal("expected non-empty search IDs")
	}

	// Should contain "fsiduser" at minimum
	hasUsername := false
	for _, id := range ids {
		if id == "fsiduser" {
			hasUsername = true
		}
	}
	if !hasUsername {
		t.Errorf("search IDs missing username; got: %v", ids)
	}
}

func TestUsers_GetTopBlacklistUsers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := testUUID("bl2-user")
	if err := s.UpdateUserStats(ctx, "node-bl2", email, 50, 30, "spam.com", 5, ""); err != nil {
		t.Fatalf("UpdateUserStats: %v", err)
	}

	users, err := s.GetTopBlacklistUsers(ctx, 10)
	if err != nil {
		t.Fatalf("GetTopBlacklistUsers: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("expected at least one result")
	}
	if users[0].BlacklistHits <= 0 {
		t.Errorf("BlacklistHits = %d, want > 0", users[0].BlacklistHits)
	}
}

func TestUsers_GetSubscriptionAbusers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := testUUID("abuser-user")
	// Record multiple IPs for one user — qualifies as potential abuser
	ips := []string{"10.1.1.1", "10.1.1.2", "10.1.1.3"}
	for _, ip := range ips {
		if err := s.RecordUserIP(ctx, email, ip, "node-abuse", "US", "United States", "NYC"); err != nil {
			t.Fatalf("RecordUserIP %s: %v", ip, err)
		}
	}

	since := time.Now().UTC().Add(-time.Hour)
	abusers, err := s.GetSubscriptionAbusers(ctx, since, 2)
	if err != nil {
		t.Fatalf("GetSubscriptionAbusers: %v", err)
	}

	found := false
	for _, a := range abusers {
		if a.UserEmail == email {
			found = true
			if a.UniqueIPs < 3 {
				t.Errorf("UniqueIPs = %d, want >= 3", a.UniqueIPs)
			}
		}
	}
	if !found {
		t.Error("abuser not found in GetSubscriptionAbusers results")
	}
}
