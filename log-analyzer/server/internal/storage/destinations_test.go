package storage

import (
	"context"
	"testing"
	"time"
)

func TestDestinations_RecordAndRead(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "dest-user@example.com"
	nodeID := "node-dest-1"
	dst := "example.com"
	since := time.Now().UTC().Add(-1 * time.Hour)

	// Insert a destination record
	if err := s.RecordUserDestination(ctx, email, nodeID, dst); err != nil {
		t.Fatalf("RecordUserDestination: %v", err)
	}

	// Fetch it back
	resp, err := s.GetUserDestinations(ctx, email, since, 1, 20)
	if err != nil {
		t.Fatalf("GetUserDestinations: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("total = %d, want 1", resp.Total)
	}
	if len(resp.Destinations) != 1 {
		t.Fatalf("len(Destinations) = %d, want 1", len(resp.Destinations))
	}
	got := resp.Destinations[0]
	if got.NodeID != nodeID {
		t.Errorf("NodeID = %q, want %q", got.NodeID, nodeID)
	}
	if got.Destination != dst {
		t.Errorf("Destination = %q, want %q", got.Destination, dst)
	}
	if got.RequestCount != 1 {
		t.Errorf("RequestCount = %d, want 1", got.RequestCount)
	}
}

func TestDestinations_IncrementCount(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "incr-user@example.com"
	nodeID := "node-incr"
	dst := "counter.io"
	since := time.Now().UTC().Add(-1 * time.Hour)

	for i := 0; i < 3; i++ {
		if err := s.RecordUserDestination(ctx, email, nodeID, dst); err != nil {
			t.Fatalf("RecordUserDestination #%d: %v", i, err)
		}
	}

	resp, err := s.GetUserDestinations(ctx, email, since, 1, 20)
	if err != nil {
		t.Fatalf("GetUserDestinations: %v", err)
	}
	if resp.Destinations[0].RequestCount != 3 {
		t.Errorf("RequestCount = %d, want 3", resp.Destinations[0].RequestCount)
	}
}

func TestDestinations_SinceFilter(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "since-user@example.com"
	nodeID := "node-since"

	// Record now — should be visible
	if err := s.RecordUserDestination(ctx, email, nodeID, "recent.com"); err != nil {
		t.Fatal(err)
	}

	// Query with future 'since' — should return nothing
	futureTime := time.Now().UTC().Add(1 * time.Hour)
	resp, err := s.GetUserDestinations(ctx, email, futureTime, 1, 20)
	if err != nil {
		t.Fatalf("GetUserDestinations: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("expected 0 results with future since, got %d", resp.Total)
	}
}

func TestDestinations_Cleanup(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	email := "cleanup-user@example.com"

	// Insert a record, then immediately clean up with retentionDays=0 (removes everything)
	if err := s.RecordUserDestination(ctx, email, "n1", "old.com"); err != nil {
		t.Fatal(err)
	}

	// retention=0 means cutoff = now, so everything older than now is deleted
	// To reliably delete the row, use a negative retention (future cutoff)
	// Actually retentionDays=0 → cutoff=today; row's last_seen is just now so < cutoff may miss by ms.
	// Use -1 retention to push cutoff 1 day into the future.
	if err := s.CleanupUserDestinations(ctx, -1); err != nil {
		t.Fatalf("CleanupUserDestinations: %v", err)
	}

	var cnt int
	if err := s.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM user_destinations WHERE user_email = $1", email).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Errorf("after cleanup: %d rows, want 0", cnt)
	}
}
