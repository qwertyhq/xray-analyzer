package storage

import (
	"context"
	"testing"
	"time"
)

func TestHourly_UpdateAndGet(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodeID := "hourly-node-1"

	// Insert two batches for the same hour — should accumulate requests/hits
	// and take GREATEST for unique_users.
	if err := s.UpdateHourlyStats(ctx, nodeID, 100, 10, 5); err != nil {
		t.Fatalf("UpdateHourlyStats #1: %v", err)
	}
	if err := s.UpdateHourlyStats(ctx, nodeID, 50, 5, 8); err != nil {
		t.Fatalf("UpdateHourlyStats #2: %v", err)
	}

	stats, err := s.GetHourlyStats(ctx, 2)
	if err != nil {
		t.Fatalf("GetHourlyStats: %v", err)
	}
	if len(stats) == 0 {
		t.Fatal("expected at least one hourly stats row")
	}

	var found bool
	for _, st := range stats {
		if st.TotalRequests >= 150 {
			found = true
			if st.BlacklistHits < 15 {
				t.Errorf("BlacklistHits = %d, want >= 15", st.BlacklistHits)
			}
			// GREATEST(5, 8) = 8
			if st.UniqueUsers != 8 {
				t.Errorf("UniqueUsers = %d, want 8", st.UniqueUsers)
			}
		}
	}
	if !found {
		t.Errorf("accumulated row (total_requests >= 150) not found in hourly stats")
	}
}

func TestHourly_GetHourlyStats_EmptyReturnsEmptySlice(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	stats, err := s.GetHourlyStats(ctx, 24)
	if err != nil {
		t.Fatalf("GetHourlyStats: %v", err)
	}
	// Should return empty slice, not nil/error
	if stats == nil {
		t.Fatal("expected non-nil slice, got nil")
	}
	if len(stats) != 0 {
		t.Fatalf("expected 0 rows in fresh DB, got %d", len(stats))
	}
}

func TestHourly_GetHourlyStatsRange(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodeID := "range-node"
	if err := s.UpdateHourlyStats(ctx, nodeID, 200, 20, 10); err != nil {
		t.Fatalf("UpdateHourlyStats: %v", err)
	}

	from := time.Now().UTC().Add(-2 * time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	stats, err := s.GetHourlyStatsRange(ctx, from, to)
	if err != nil {
		t.Fatalf("GetHourlyStatsRange: %v", err)
	}
	if len(stats) == 0 {
		t.Fatal("expected stats in range, got none")
	}
}

func TestHourly_GetHourlyStatsRange_ZeroDefaults(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Both zero — should default to last 7d; just ensure no error
	_, err := s.GetHourlyStatsRange(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("GetHourlyStatsRange with zero times: %v", err)
	}
}

func TestHourly_GetHourlyStats_Cache(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodeID := "cache-node"
	if err := s.UpdateHourlyStats(ctx, nodeID, 77, 7, 3); err != nil {
		t.Fatalf("UpdateHourlyStats: %v", err)
	}

	// First call populates cache
	first, err := s.GetHourlyStats(ctx, 2)
	if err != nil {
		t.Fatalf("GetHourlyStats (first): %v", err)
	}

	// Second call should return from cache (same result)
	second, err := s.GetHourlyStats(ctx, 2)
	if err != nil {
		t.Fatalf("GetHourlyStats (second): %v", err)
	}

	if len(first) != len(second) {
		t.Errorf("cache returned different length: first=%d second=%d", len(first), len(second))
	}
}

func TestHourly_CleanupOldData(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Create fresh stats — will be within retention, so not cleaned up
	if err := s.UpdateHourlyStats(ctx, "cleanup-node", 10, 1, 1); err != nil {
		t.Fatalf("UpdateHourlyStats: %v", err)
	}

	// Run cleanup with 30-day retention — should not error
	if err := s.CleanupOldData(ctx, 30); err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}

	// Stats inserted moments ago should still be present
	stats, err := s.GetHourlyStats(ctx, 2)
	if err != nil {
		t.Fatalf("GetHourlyStats after cleanup: %v", err)
	}
	if len(stats) == 0 {
		t.Error("recent hourly stats were incorrectly removed by CleanupOldData")
	}
}
