package storage

import (
	"context"
	"testing"
	"time"
)

func TestOnlineSnapshots_RecordAndReadHistory(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Record snapshots across two hours: peak 100 in hour1, peak 250 in hour2.
	now := time.Date(2026, 4, 18, 15, 0, 0, 0, time.UTC)
	samples := []struct {
		ts    time.Time
		total int
	}{
		{now, 50},
		{now.Add(10 * time.Minute), 100}, // hour 15 peak
		{now.Add(1 * time.Hour), 200},
		{now.Add(1*time.Hour + 15*time.Minute), 250}, // hour 16 peak
	}
	for _, sm := range samples {
		if err := s.RecordOnlineSnapshot(ctx, sm.ts, sm.total); err != nil {
			t.Fatalf("RecordOnlineSnapshot: %v", err)
		}
	}

	// GetOnlineHistoryHourly "since" is measured from time.Now() in production,
	// but we can't stub that here. Use a large window and assert the peaks.
	pts, err := s.GetOnlineHistoryHourly(ctx, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GetOnlineHistoryHourly: %v", err)
	}

	// Expect at least our two hours present, peaks correct.
	var h15, h16 int
	for _, p := range pts {
		if p.Hour.Hour() == 15 && p.Hour.Day() == 18 {
			h15 = p.OnlineUsers
		}
		if p.Hour.Hour() == 16 && p.Hour.Day() == 18 {
			h16 = p.OnlineUsers
		}
	}
	if h15 != 100 {
		t.Errorf("hour 15 peak = %d, want 100", h15)
	}
	if h16 != 250 {
		t.Errorf("hour 16 peak = %d, want 250", h16)
	}
}

func TestOnlineSnapshots_CleanupRetention(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	old := time.Now().UTC().Add(-40 * 24 * time.Hour)
	fresh := time.Now().UTC().Add(-1 * time.Hour)

	if err := s.RecordOnlineSnapshot(ctx, old, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordOnlineSnapshot(ctx, fresh, 20); err != nil {
		t.Fatal(err)
	}

	if err := s.CleanupOnlineSnapshots(ctx, 30); err != nil {
		t.Fatalf("CleanupOnlineSnapshots: %v", err)
	}

	var cnt int
	if err := s.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM online_snapshots").Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Errorf("after cleanup: %d rows, want 1", cnt)
	}
}
