package storage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/threatintel"
)

func newThreatMatch(user, threatType string) *threatintel.ThreatMatch {
	return &threatintel.ThreatMatch{
		UserEmail:   user,
		NodeID:      "node1",
		SourceIP:    "1.2.3.4",
		Destination: "evil.example.com:443",
		ThreatType:  threatintel.ThreatType(threatType),
		Source:      threatintel.ThreatSource("test"),
		Confidence:  90,
		Description: "test match",
		MatchedAt:   time.Now(),
	}
}

func TestSaveThreatMatch_BasicWrite(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	userUUID := testUUID("alice")
	match := newThreatMatch(userUUID, "malware")
	if err := s.SaveThreatMatch(ctx, match); err != nil {
		t.Fatalf("SaveThreatMatch: %v", err)
	}

	// Verify we can read it back
	matches, err := s.GetThreatMatches(ctx, 10)
	if err != nil {
		t.Fatalf("GetThreatMatches: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	m := matches[0]
	if m.UserEmail != userUUID {
		t.Errorf("expected %s, got %s", userUUID, m.UserEmail)
	}
	if string(m.ThreatType) != "malware" {
		t.Errorf("expected malware, got %s", m.ThreatType)
	}
	if m.Confidence != 90 {
		t.Errorf("expected confidence 90, got %d", m.Confidence)
	}
}

func TestSaveThreatMatch_UpdatesAggregates(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	bobUUID := testUUID("bob")
	// Save two matches for same user+type
	s.SaveThreatMatch(ctx, newThreatMatch(bobUUID, "phishing"))
	s.SaveThreatMatch(ctx, newThreatMatch(bobUUID, "phishing"))

	// Check user_threat_stats accumulated
	var count int64
	bobUID, _ := uuid.Parse(bobUUID)
	err := s.pool.QueryRow(ctx, `
		SELECT match_count FROM user_threat_stats
		WHERE user_email = $1 AND threat_type = $2
	`, bobUID, "phishing").Scan(&count)
	if err != nil {
		t.Fatalf("query user_threat_stats: %v", err)
	}
	if count != 2 {
		t.Errorf("expected match_count=2, got %d", count)
	}

	// Check threat_type_stats accumulated
	var typeCount int64
	err = s.pool.QueryRow(ctx, `
		SELECT match_count FROM threat_type_stats WHERE threat_type = $1
	`, "phishing").Scan(&typeCount)
	if err != nil {
		t.Fatalf("query threat_type_stats: %v", err)
	}
	if typeCount != 2 {
		t.Errorf("expected type match_count=2, got %d", typeCount)
	}
}

func TestSaveThreatMatch_HourlyDailyTracking(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	u1 := testUUID("u1-tor")
	u2 := testUUID("u2-tor")
	// Two different users — unique_users should be 2
	s.SaveThreatMatch(ctx, newThreatMatch(u1, "tor"))
	s.SaveThreatMatch(ctx, newThreatMatch(u2, "tor"))
	// Same user again — unique count should not change
	s.SaveThreatMatch(ctx, newThreatMatch(u1, "tor"))

	hourKey := time.Now().Format("2006-01-02T15")
	var matchCount, uniqueUsers int64
	err := s.pool.QueryRow(ctx, `
		SELECT match_count, unique_users FROM threat_hourly_stats
		WHERE hour = $1 AND threat_type = $2
	`, hourKey, "tor").Scan(&matchCount, &uniqueUsers)
	if err != nil {
		t.Fatalf("query threat_hourly_stats: %v", err)
	}
	if matchCount != 3 {
		t.Errorf("expected match_count=3, got %d", matchCount)
	}
	if uniqueUsers != 2 {
		t.Errorf("expected unique_users=2, got %d", uniqueUsers)
	}
}

func TestGetThreatMatchesByUser(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	carolUUID := testUUID("carol")
	otherUUID := testUUID("other-threat")
	s.SaveThreatMatch(ctx, newThreatMatch(carolUUID, "gambling"))
	s.SaveThreatMatch(ctx, newThreatMatch(carolUUID, "malware"))
	s.SaveThreatMatch(ctx, newThreatMatch(otherUUID, "malware"))

	matches, err := s.GetThreatMatchesByUser(ctx, carolUUID, 10)
	if err != nil {
		t.Fatalf("GetThreatMatchesByUser: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches for carol, got %d", len(matches))
	}
	for _, m := range matches {
		if m.UserEmail != carolUUID {
			t.Errorf("unexpected user %s", m.UserEmail)
		}
	}
}

func TestGetThreatMatchesByType(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	s.SaveThreatMatch(ctx, newThreatMatch(testUUID("d"), "social"))
	s.SaveThreatMatch(ctx, newThreatMatch(testUUID("e"), "social"))
	s.SaveThreatMatch(ctx, newThreatMatch(testUUID("f"), "malware2"))

	matches, err := s.GetThreatMatchesByType(ctx, "social", 10)
	if err != nil {
		t.Fatalf("GetThreatMatchesByType: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 social matches, got %d", len(matches))
	}
}

func TestGetThreatMatchesByType_FallbackToHistorical(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	gUUID := testUUID("g-fakenews")
	uid, _ := uuid.Parse(gUUID)

	// Directly insert into user_threat_domains without going through SaveThreatMatch
	// so threat_matches is empty for "fakenews"
	_, err := s.pool.Exec(ctx, `
		INSERT INTO user_threat_domains (user_email, threat_type, domain, hit_count, last_seen)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING
	`, uid, "fakenews", "fake.news", 5, time.Now())
	if err != nil {
		t.Fatalf("seed user_threat_domains: %v", err)
	}

	matches, err := s.GetThreatMatchesByType(ctx, "fakenews", 10)
	if err != nil {
		t.Fatalf("GetThreatMatchesByType fallback: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected fallback historical match")
	}
	m := matches[0]
	if string(m.Source) != "historical" {
		t.Errorf("expected source=historical, got %s", m.Source)
	}
	if m.Description == "" {
		t.Error("expected non-empty description")
	}
}

func TestCleanupOldThreatMatches(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	hUUID := testUUID("h-cleanup")
	oldUUID := testUUID("old-cleanup")
	// Insert a "fresh" match
	s.SaveThreatMatch(ctx, newThreatMatch(hUUID, "malware"))

	// Manually backdate one row using correct types
	oldUID, _ := uuid.Parse(oldUUID)
	nodeID, _ := s.LookupNodeID(ctx, "n-cleanup", "exit")
	_, err := s.pool.Exec(ctx, `
		INSERT INTO threat_matches (user_email, node_id, source_ip, destination, threat_type, source, confidence, description, matched_at, ts)
		VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10)
	`, oldUID, int16(nodeID), "1.1.1.1", "old.com", "malware", "test", 50, "old",
		time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatalf("insert old match: %v", err)
	}

	deleted, err := s.CleanupOldThreatMatches(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("CleanupOldThreatMatches: %v", err)
	}
	if deleted < 1 {
		t.Errorf("expected at least 1 deleted, got %d", deleted)
	}

	// Verify old one is gone, fresh one remains
	matches, err := s.GetThreatMatches(ctx, 10)
	if err != nil {
		t.Fatalf("GetThreatMatches after cleanup: %v", err)
	}
	for _, m := range matches {
		if m.UserEmail == oldUUID {
			t.Error("old match should have been deleted")
		}
	}
}

func TestClearThreatIntelData(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Seed some data
	s.SaveThreatMatch(ctx, newThreatMatch(testUUID("z"), "malware"))

	if err := s.ClearThreatIntelData(ctx); err != nil {
		t.Fatalf("ClearThreatIntelData: %v", err)
	}

	// threat_matches should be empty
	matches, err := s.GetThreatMatches(ctx, 10)
	if err != nil {
		t.Fatalf("GetThreatMatches after clear: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches after clear, got %d", len(matches))
	}

	// threat_stats_agg id=1 should be reset to 0
	var total int64
	s.pool.QueryRow(ctx, `SELECT total_matches FROM threat_stats_agg WHERE id = 1`).Scan(&total)
	if total != 0 {
		t.Errorf("expected total_matches=0 after clear, got %d", total)
	}
}

func TestGetThreatMatches_Empty(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	matches, err := s.GetThreatMatches(ctx, 10)
	if err != nil {
		t.Fatalf("GetThreatMatches on empty DB: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on empty DB, got %d", len(matches))
	}
}

func TestSaveThreatMatch_PerUserCategoryTrim(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	trimUUID := testUUID("trim")
	// Insert MaxThreatMatchesPerUserCategory+5 matches for same user+type
	total := MaxThreatMatchesPerUserCategory + 5
	for i := 0; i < total; i++ {
		if err := s.SaveThreatMatch(ctx, newThreatMatch(trimUUID, "social")); err != nil {
			t.Fatalf("SaveThreatMatch #%d: %v", i, err)
		}
	}

	// Count remaining rows for this (user, type) pair
	uid, _ := uuid.Parse(trimUUID)
	var remaining int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM threat_matches
		WHERE user_email = $1 AND threat_type = $2
	`, uid, "social").Scan(&remaining)
	if err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining > MaxThreatMatchesPerUserCategory {
		t.Errorf("expected <= %d remaining, got %d", MaxThreatMatchesPerUserCategory, remaining)
	}
}

// SaveThreatMatch for (userA, typeX) must not touch rows in other partitions.
func TestSaveThreatMatch_TrimScopedToInsertedPartition(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	otherUUID := testUUID("other-partition")
	meUUID := testUUID("me-partition")
	otherUID, _ := uuid.Parse(otherUUID)

	// Get node ID for seeding
	nid, err := s.LookupNodeID(ctx, "n1-trim", "exit")
	if err != nil {
		t.Fatalf("LookupNodeID: %v", err)
	}

	// Seed 105 rows for (other@, social) directly, bypassing SaveThreatMatch
	// so nothing trims them yet.
	over := MaxThreatMatchesPerUserCategory + 5
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < over; i++ {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO threat_matches (user_email, node_id, source_ip, destination,
				threat_type, source, confidence, description, matched_at, ts)
			VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10)
		`, otherUID, int16(nid), "1.1.1.1", "x.example.com:443",
			"social", "test", 50, "seed",
			base.Add(time.Duration(i)*time.Second),
			base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("seed #%d: %v", i, err)
		}
	}

	// Act in an unrelated partition.
	if err := s.SaveThreatMatch(ctx, newThreatMatch(meUUID, "malware")); err != nil {
		t.Fatalf("SaveThreatMatch: %v", err)
	}

	// Other partition must be intact (fails under global trim — old behavior).
	var count int
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM threat_matches
		WHERE user_email = $1 AND threat_type = $2
	`, otherUID, "social").Scan(&count)
	if err != nil {
		t.Fatalf("count other: %v", err)
	}
	if count != over {
		t.Errorf("unrelated partition trimmed: expected %d rows, got %d", over, count)
	}
}

func TestSaveThreatMatch_NonUUIDEmail(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	const syntheticEmail = "5117"
	knownUUID := uuid.MustParse("11111111-1111-4111-8111-111111111114")

	// Pre-seed remna_users so ResolveUserEmailToUUID finds it by username.
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO remna_users (uuid, username, status)
		VALUES ($1, $2, 'ACTIVE')
	`, knownUUID, syntheticEmail); err != nil {
		t.Fatalf("seed remna_users: %v", err)
	}

	match := newThreatMatch(syntheticEmail, "malware")
	if err := s.SaveThreatMatch(ctx, match); err != nil {
		t.Fatalf("non-UUID email should succeed via remna_users lookup: %v", err)
	}

	var got uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT user_email FROM threat_matches WHERE destination = $1`, match.Destination,
	).Scan(&got)
	if err != nil {
		t.Fatalf("query inserted row: %v", err)
	}
	if got != knownUUID {
		t.Errorf("user_email = %s, want %s (remna_users uuid for %q)", got, knownUUID, syntheticEmail)
	}
}
