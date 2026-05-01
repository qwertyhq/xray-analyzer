package storage

import (
	"context"
	"testing"
	"time"

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
