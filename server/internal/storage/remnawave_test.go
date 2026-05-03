package storage

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/xray-log-analyzer/server/internal/remnawave"
)

func TestRemnawave_UpsertAndGetUser(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	user := &remnawave.RemnaUserData{
		UUID:                 testUUID("test-user-1"),
		ID:                   42,
		ShortUUID:            "short1",
		Username:             "testuser",
		Email:                strPtr("testuser@example.com"),
		Status:               "ACTIVE",
		TrafficLimitBytes:    10_000_000_000,
		UsedTrafficBytes:     1_000_000,
		LifetimeTrafficBytes: 5_000_000,
		TrafficLimitStrategy: "MONTH",
		CreatedAt:            now,
		UpdatedAt:            now,
		SyncedAt:             now,
	}

	if err := s.UpsertRemnaUser(ctx, user); err != nil {
		t.Fatalf("UpsertRemnaUser: %v", err)
	}

	// Upsert again with updated traffic to test conflict resolution
	user.UsedTrafficBytes = 2_000_000
	if err := s.UpsertRemnaUser(ctx, user); err != nil {
		t.Fatalf("UpsertRemnaUser (update): %v", err)
	}

	got, err := s.GetRemnaUserByEmail(ctx, "testuser@example.com")
	if err != nil {
		t.Fatalf("GetRemnaUserByEmail: %v", err)
	}
	if got == nil {
		t.Fatal("expected user, got nil")
	}
	if got.Username != "testuser" {
		t.Errorf("Username = %q, want %q", got.Username, "testuser")
	}
	if got.UsedTrafficBytes != 2_000_000 {
		t.Errorf("UsedTrafficBytes = %d, want 2000000", got.UsedTrafficBytes)
	}
}

func TestRemnawave_UpsertNode(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	node := &remnawave.RemnaNodeData{
		UUID:           "node-uuid-1",
		Name:           "test-node",
		Address:        "10.0.0.1",
		Port:           443,
		IsConnected:    true,
		IsDisabled:     false,
		IsTrafficTrack: true,
		TrafficTotal:   100_000_000,
		TrafficUsed:    50_000_000,
		UsersOnline:    7,
		CountryCode:    "NL",
		SyncedAt:       now,
	}

	if err := s.UpsertRemnaNode(ctx, node); err != nil {
		t.Fatalf("UpsertRemnaNode: %v", err)
	}

	nodes, err := s.GetRemnaNodes(ctx)
	if err != nil {
		t.Fatalf("GetRemnaNodes: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("expected at least one node")
	}

	found := false
	for _, n := range nodes {
		if n.UUID == "node-uuid-1" {
			found = true
			if n.UsersOnline != 7 {
				t.Errorf("UsersOnline = %d, want 7", n.UsersOnline)
			}
			if n.CountryCode != "NL" {
				t.Errorf("CountryCode = %q, want NL", n.CountryCode)
			}
		}
	}
	if !found {
		t.Error("inserted node not found in GetRemnaNodes")
	}
}

func TestRemnawave_GetRemnaStats(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	for i, status := range []string{"ACTIVE", "ACTIVE", "DISABLED", "EXPIRED"} {
		u := &remnawave.RemnaUserData{
			UUID:                 testUUID("stats-user-" + itoa(i)),
			ID:                   int64(100 + i),
			Username:             "statsuser" + itoa(i),
			Status:               status,
			TrafficLimitBytes:    1_000_000_000,
			UsedTrafficBytes:     int64(i) * 100_000,
			TrafficLimitStrategy: "MONTH",
			CreatedAt:            now,
			UpdatedAt:            now,
			SyncedAt:             now,
		}
		if err := s.UpsertRemnaUser(ctx, u); err != nil {
			t.Fatalf("UpsertRemnaUser[%d]: %v", i, err)
		}
	}

	stats, err := s.GetRemnaStats(ctx)
	if err != nil {
		t.Fatalf("GetRemnaStats: %v", err)
	}
	if stats.TotalUsers < 4 {
		t.Errorf("TotalUsers = %d, want >= 4", stats.TotalUsers)
	}
	if stats.ActiveUsers < 2 {
		t.Errorf("ActiveUsers = %d, want >= 2", stats.ActiveUsers)
	}
	if stats.DisabledUsers < 1 {
		t.Errorf("DisabledUsers = %d, want >= 1", stats.DisabledUsers)
	}
}

func TestRemnawave_GetRemnaUsers_Search(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	users := []*remnawave.RemnaUserData{
		{UUID: testUUID("srch-alice"), ID: 201, Username: "alice", Status: "ACTIVE", TrafficLimitStrategy: "MONTH", CreatedAt: now, UpdatedAt: now, SyncedAt: now},
		{UUID: testUUID("srch-bob"), ID: 202, Username: "bob", Status: "ACTIVE", TrafficLimitStrategy: "MONTH", CreatedAt: now, UpdatedAt: now, SyncedAt: now},
		{UUID: testUUID("srch-charlie"), ID: 203, Username: "charlie", Status: "DISABLED", TrafficLimitStrategy: "MONTH", CreatedAt: now, UpdatedAt: now, SyncedAt: now},
	}
	for _, u := range users {
		if err := s.UpsertRemnaUser(ctx, u); err != nil {
			t.Fatalf("UpsertRemnaUser: %v", err)
		}
	}

	// Search by username prefix
	results, err := s.GetRemnaUsers(ctx, 100, "", "ali")
	if err != nil {
		t.Fatalf("GetRemnaUsers search: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least one result for search 'ali'")
	}
	if results[0].Username != "alice" {
		t.Errorf("first result username = %q, want alice", results[0].Username)
	}

	// Filter by status
	active, err := s.GetRemnaUsers(ctx, 100, "ACTIVE", "")
	if err != nil {
		t.Fatalf("GetRemnaUsers status filter: %v", err)
	}
	for _, u := range active {
		if u.Status != "ACTIVE" {
			t.Errorf("expected ACTIVE, got %q", u.Status)
		}
	}
}

func TestRemnawave_HwidDevice(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	// Insert a user first (FK)
	hwidUserUUID := testUUID("hwid-user")
	u := &remnawave.RemnaUserData{
		UUID:                 hwidUserUUID,
		ID:                   301,
		Username:             "hwiduser",
		Status:               "ACTIVE",
		TrafficLimitStrategy: "MONTH",
		CreatedAt:            now,
		UpdatedAt:            now,
		SyncedAt:             now,
	}
	if err := s.UpsertRemnaUser(ctx, u); err != nil {
		t.Fatalf("UpsertRemnaUser: %v", err)
	}

	device := &remnawave.RemnaHwidData{
		Hwid:        "device-hwid-abc",
		UserUUID:    hwidUserUUID,
		Username:    "hwiduser",
		FirstSeenAt: now,
		SyncedAt:    now,
	}
	if err := s.UpsertRemnaHwidDevice(ctx, device); err != nil {
		t.Fatalf("UpsertRemnaHwidDevice: %v", err)
	}

	devices, err := s.GetRemnaUserHwids(ctx, hwidUserUUID)
	if err != nil {
		t.Fatalf("GetRemnaUserHwids: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].Hwid != "device-hwid-abc" {
		t.Errorf("Hwid = %q, want device-hwid-abc", devices[0].Hwid)
	}
}

// helpers

func strPtr(s string) *string { return &s }

func itoa(i int) string {
	return strconv.Itoa(i)
}
