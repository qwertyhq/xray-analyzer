package storage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/models"
)

func TestBlacklist_RecordAndAnalytics(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	userUUID := testUUID("bl-user")
	now := time.Now().UTC()
	match := &models.BlacklistMatch{
		NodeID:      "node-bl-1",
		UserEmail:   userUUID,
		SourceIP:    "10.0.0.1",
		Destination: "evil.com",
		MatchedRule: "malware",
		Timestamp:   now,
	}

	if err := s.RecordBlacklistMatch(ctx, match); err != nil {
		t.Fatalf("RecordBlacklistMatch: %v", err)
	}

	since := now.Add(-time.Hour)
	analytics, err := s.GetBlacklistAnalytics(ctx, since)
	if err != nil {
		t.Fatalf("GetBlacklistAnalytics: %v", err)
	}

	if analytics.TotalHits < 1 {
		t.Errorf("TotalHits = %d, want >= 1", analytics.TotalHits)
	}
	if analytics.UniqueUsers < 1 {
		t.Errorf("UniqueUsers = %d, want >= 1", analytics.UniqueUsers)
	}
	if analytics.UniqueDomains < 1 {
		t.Errorf("UniqueDomains = %d, want >= 1", analytics.UniqueDomains)
	}
	if len(analytics.TopDomains) == 0 {
		t.Error("TopDomains is empty")
	}
	if len(analytics.RecentMatches) == 0 {
		t.Error("RecentMatches is empty")
	}
	// Timestamp should round-trip correctly
	if analytics.RecentMatches[0].Timestamp.IsZero() {
		t.Error("RecentMatches[0].Timestamp is zero")
	}
}

func TestBlacklist_AnalyticsSinceExcludesOldRecords(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	userUUID := testUUID("old-user")
	old := time.Now().UTC().Add(-48 * time.Hour)
	match := &models.BlacklistMatch{
		NodeID:      "node-bl-old",
		UserEmail:   userUUID,
		SourceIP:    "10.0.0.2",
		Destination: "old-evil.com",
		MatchedRule: "spam",
		Timestamp:   old,
	}
	if err := s.RecordBlacklistMatch(ctx, match); err != nil {
		t.Fatalf("RecordBlacklistMatch: %v", err)
	}

	// Query only last 1 hour — should see 0 hits
	since := time.Now().UTC().Add(-time.Hour)
	analytics, err := s.GetBlacklistAnalytics(ctx, since)
	if err != nil {
		t.Fatalf("GetBlacklistAnalytics: %v", err)
	}
	if analytics.TotalHits != 0 {
		t.Errorf("TotalHits = %d, want 0 (old record should be excluded)", analytics.TotalHits)
	}
}

func TestBlacklist_GetUserBlacklistDetails(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	userUUID := testUUID("detail-user")
	now := time.Now().UTC()

	for i := 0; i < 3; i++ {
		if err := s.RecordBlacklistMatch(ctx, &models.BlacklistMatch{
			NodeID:      "node-detail",
			UserEmail:   userUUID,
			SourceIP:    "1.2.3.4",
			Destination: "site.com",
			MatchedRule: "rule",
			Timestamp:   now,
		}); err != nil {
			t.Fatalf("RecordBlacklistMatch #%d: %v", i, err)
		}
	}

	details, err := s.GetUserBlacklistDetails(ctx, userUUID, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetUserBlacklistDetails: %v", err)
	}
	if len(details) != 3 {
		t.Errorf("got %d details, want 3", len(details))
	}

	// Unknown user (non-UUID) should return nil without error.
	unknown, err := s.GetUserBlacklistDetails(ctx, "not-a-uuid", now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetUserBlacklistDetails (unknown): %v", err)
	}
	if len(unknown) != 0 {
		t.Errorf("unknown user: got %d details, want 0", len(unknown))
	}
}

func TestBlacklist_GetUserBlacklistMatches_Pagination(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	userUUID := testUUID("page-bl")
	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		if err := s.RecordBlacklistMatch(ctx, &models.BlacklistMatch{
			NodeID:      "node-page",
			UserEmail:   userUUID,
			SourceIP:    "5.5.5.5",
			Destination: "paged.com",
			MatchedRule: "r",
			Timestamp:   now,
		}); err != nil {
			t.Fatalf("RecordBlacklistMatch #%d: %v", i, err)
		}
	}

	resp, err := s.GetUserBlacklistMatches(ctx, userUUID, now.Add(-time.Hour), 1, 2)
	if err != nil {
		t.Fatalf("GetUserBlacklistMatches page 1: %v", err)
	}
	if resp.Total != 5 {
		t.Errorf("Total = %d, want 5", resp.Total)
	}
	if len(resp.Matches) != 2 {
		t.Errorf("page 1 len = %d, want 2", len(resp.Matches))
	}
	if resp.TotalPages != 3 {
		t.Errorf("TotalPages = %d, want 3", resp.TotalPages)
	}

	resp2, err := s.GetUserBlacklistMatches(ctx, userUUID, now.Add(-time.Hour), 3, 2)
	if err != nil {
		t.Fatalf("GetUserBlacklistMatches page 3: %v", err)
	}
	if len(resp2.Matches) != 1 {
		t.Errorf("page 3 len = %d, want 1", len(resp2.Matches))
	}
}

func TestRecordBlacklistMatch_NonUUIDEmail(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	const syntheticEmail = "5117"
	knownUUID := uuid.MustParse("11111111-1111-4111-8111-111111111113")

	// Pre-seed remna_users so ResolveUserEmailToUUID finds it by username.
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO remna_users (uuid, username, status)
		VALUES ($1, $2, 'ACTIVE')
	`, knownUUID, syntheticEmail); err != nil {
		t.Fatalf("seed remna_users: %v", err)
	}

	now := time.Now().UTC()
	if err := s.RecordBlacklistMatch(ctx, &models.BlacklistMatch{
		NodeID:      "node-synthetic-bl",
		UserEmail:   syntheticEmail,
		SourceIP:    "203.0.113.5",
		Destination: "example.com:443",
		MatchedRule: "test-rule",
		Timestamp:   now,
	}); err != nil {
		t.Fatalf("non-UUID email should succeed via remna_users lookup: %v", err)
	}

	var got uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT user_email FROM blacklist_matches WHERE destination = $1`, "example.com:443",
	).Scan(&got)
	if err != nil {
		t.Fatalf("query inserted row: %v", err)
	}
	if got != knownUUID {
		t.Errorf("user_email = %s, want %s (remna_users uuid for %q)", got, knownUUID, syntheticEmail)
	}
}
