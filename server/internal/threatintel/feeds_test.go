package threatintel

import (
	"context"
	"testing"
	"time"
)

func newInd(value string, source ThreatSource, conf int) *ThreatIndicator {
	return &ThreatIndicator{
		Indicator:  value,
		Type:       "domain",
		ThreatType: ThreatTypeMalware,
		Source:     source,
		Confidence: conf,
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		CreatedAt:  time.Now(),
	}
}

func TestUpsertIndicator_CountsReSeenEntries(t *testing.T) {
	// Regression: reload cycles must keep counting indicators even when the
	// map already has them, otherwise feed status flips to "error: 0
	// indicators" after the first successful load.
	f := NewFeedLoader()

	if !f.upsertIndicator(newInd("evil.example.com", SourceBlockListMalware, 90)) {
		t.Fatal("first insert should count")
	}
	if !f.upsertIndicator(newInd("evil.example.com", SourceBlockListMalware, 90)) {
		t.Fatal("same-source re-seen indicator must still count toward feed")
	}
	if !f.upsertIndicator(newInd("evil.example.com", SourceURLhaus, 80)) {
		t.Fatal("different-source merge must count toward feed")
	}
	if f.upsertIndicator(newInd("github.com", SourceBlockListMalware, 90)) {
		t.Fatal("whitelisted indicator must not count")
	}
}

func TestUpsertIndicator_MultiSourceBoostStillApplies(t *testing.T) {
	f := NewFeedLoader()
	f.upsertIndicator(newInd("bad.example", SourceBlockListMalware, 80))
	f.upsertIndicator(newInd("bad.example", SourceURLhaus, 70))

	existing := f.indicators["bad.example"]
	if got, want := len(existing.Sources), 2; got != want {
		t.Fatalf("sources: got %d, want %d", got, want)
	}
	if existing.Confidence != 85 {
		t.Fatalf("confidence after boost: got %d, want 85", existing.Confidence)
	}
}

func TestLoadWithRetry_ZeroCountNoErrorIsNotRetried(t *testing.T) {
	f := NewFeedLoader()
	calls := 0
	loader := func(context.Context) (int, error) {
		calls++
		return 0, nil
	}
	count, err := f.loadWithRetry(context.Background(), SourceBlockListMalware, loader)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if count != 0 {
		t.Fatalf("count: got %d, want 0", count)
	}
	if calls != 1 {
		t.Fatalf("calls: got %d, want 1 (zero count must not retry)", calls)
	}
}

