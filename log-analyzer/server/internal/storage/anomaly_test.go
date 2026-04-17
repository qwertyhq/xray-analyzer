package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := New(dbPath)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestDetectPortScan_HitsSweepOfIPv4OnSinglePort: classic abuse signature
// from the 2026-04-15 incident — 35 distinct 147.251.x.y:8317 destinations
// from one user in a 5-minute window. Detector must flag as AnomalyPortScan.
func TestDetectPortScan_HitsSweepOfIPv4OnSinglePort(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	// Inject 35 distinct IPv4 destinations on port 8317 for user "scanner-1".
	for i := 0; i < 35; i++ {
		dest := fmt.Sprintf("147.251.6.%d:8317", i+1)
		if err := st.RecordUserDestination(ctx, "scanner-1", "germany-1", dest); err != nil {
			t.Fatalf("RecordUserDestination: %v", err)
		}
	}
	// And some normal traffic from another user — must NOT trip the detector.
	for i := 0; i < 5; i++ {
		_ = st.RecordUserDestination(ctx, "normal-user", "germany-1", fmt.Sprintf("youtube-%d.com:443", i))
	}

	anomalies, err := st.detectPortScan(ctx, time.Now())
	if err != nil {
		t.Fatalf("detectPortScan: %v", err)
	}

	var got *threatintel.Anomaly
	for _, a := range anomalies {
		if a.UserEmail == "scanner-1" {
			got = a
			break
		}
	}
	if got == nil {
		t.Fatalf("scanner-1 was not flagged; all anomalies: %+v", anomalies)
	}
	if got.Type != threatintel.AnomalyPortScan {
		t.Errorf("type: got %q, want %q", got.Type, threatintel.AnomalyPortScan)
	}
	if got.Severity != threatintel.SeverityHigh {
		t.Errorf("severity: got %q, want %q", got.Severity, threatintel.SeverityHigh)
	}
	if got.Details["port"] != "8317" {
		t.Errorf("details.port: got %v, want 8317", got.Details["port"])
	}
	if uniq, _ := got.Details["unique_destinations"].(int); uniq < 30 {
		t.Errorf("details.unique_destinations: got %v, want >= 30", got.Details["unique_destinations"])
	}

	// Normal user must not appear.
	for _, a := range anomalies {
		if a.UserEmail == "normal-user" {
			t.Errorf("false positive: normal-user flagged: %+v", a)
		}
	}
}

// TestDetectPortScan_BelowThresholdNotFlagged: under 30 unique IPs on a port
// → no anomaly (avoid noisy alerts on small bursts).
func TestDetectPortScan_BelowThresholdNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		_ = st.RecordUserDestination(ctx, "borderline", "germany-1", fmt.Sprintf("10.0.0.%d:22", i))
	}
	anomalies, err := st.detectPortScan(ctx, time.Now())
	if err != nil {
		t.Fatalf("detectPortScan: %v", err)
	}
	for _, a := range anomalies {
		if a.UserEmail == "borderline" {
			t.Errorf("borderline user flagged below threshold: %+v", a)
		}
	}
}

// TestDetectPortScan_DomainTrafficNotFlagged: 50 distinct domain:443 hits is
// normal browsing, NOT a port scan. The IPv4 GLOB filter must exclude these.
func TestDetectPortScan_DomainTrafficNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		_ = st.RecordUserDestination(ctx, "browser-user", "germany-1", fmt.Sprintf("site-%d.example.com:443", i))
	}
	anomalies, err := st.detectPortScan(ctx, time.Now())
	if err != nil {
		t.Fatalf("detectPortScan: %v", err)
	}
	for _, a := range anomalies {
		if a.UserEmail == "browser-user" {
			t.Errorf("normal domain browsing flagged as port scan: %+v", a)
		}
	}
}
