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

// TestDetectPortScan_Slash16Sweep: the 2026-04-15 abuse signature — 25
// unique 147.251.x.y:8317 destinations from one user. All IPs in one /16,
// non-web port → fires.
func TestDetectPortScan_Slash16Sweep(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		_ = st.RecordUserDestination(ctx, "scanner-1", "germany-1", fmt.Sprintf("147.251.6.%d:8317", i+1))
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
		t.Fatalf("scanner-1 not flagged: %+v", anomalies)
	}
	if got.Details["target_subnet"] != "147.251.0.0/16" {
		t.Errorf("target_subnet: got %v, want 147.251.0.0/16", got.Details["target_subnet"])
	}
	if got.Details["port"] != "8317" {
		t.Errorf("port: got %v, want 8317", got.Details["port"])
	}
}

// TestDetectPortScan_WhatsAppOn443NotFlagged: WhatsApp/Meta CDN happily
// churns through dozens of IPs on :443. We must NOT flag that. :443 is in
// the exclusion list; even without it the IPs would be scattered across
// many /16s, so concentration alone would save us — this test guards both.
func TestDetectPortScan_WhatsAppOn443NotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	// 100 IPs spread across 10 distinct /16s, all on :443 — normal CDN.
	subnets := []string{"31.13.64", "31.13.65", "31.13.66", "157.240.1", "157.240.2",
		"102.132.96", "163.70.128", "173.252.100", "179.60.192", "185.60.216"}
	for _, s := range subnets {
		for i := 0; i < 10; i++ {
			_ = st.RecordUserDestination(ctx, "whatsapp-user", "germany-1", fmt.Sprintf("%s.%d:443", s, i+1))
		}
	}

	anomalies, err := st.detectPortScan(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range anomalies {
		if a.UserEmail == "whatsapp-user" {
			t.Errorf("WhatsApp false positive: %+v", a)
		}
	}
}

// TestDetectPortScan_DomainTrafficNotFlagged: normal domain browsing has
// no IPv4 form, the GLOB filter must drop it.
func TestDetectPortScan_DomainTrafficNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		_ = st.RecordUserDestination(ctx, "browser", "germany-1", fmt.Sprintf("site-%d.example.com:443", i))
	}
	anomalies, _ := st.detectPortScan(ctx, time.Now())
	for _, a := range anomalies {
		if a.UserEmail == "browser" {
			t.Errorf("domain browsing flagged: %+v", a)
		}
	}
}

// TestDetectPortScan_BelowThresholdNotFlagged: just under the 20-IP line.
func TestDetectPortScan_BelowThresholdNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	for i := 0; i < 15; i++ {
		_ = st.RecordUserDestination(ctx, "borderline", "germany-1", fmt.Sprintf("10.0.0.%d:9999", i))
	}
	anomalies, _ := st.detectPortScan(ctx, time.Now())
	for _, a := range anomalies {
		if a.UserEmail == "borderline" {
			t.Errorf("borderline user flagged: %+v", a)
		}
	}
}

// TestDetectAbusePortFlood_SSHSweep: SSH brute against 20 distinct IPs.
// Fires even though the IPs are in different /16s.
func TestDetectAbusePortFlood_SSHSweep(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	// 20 distinct /24s, one IP each, all on :22 — scattered SSH brute.
	for i := 0; i < 20; i++ {
		_ = st.RecordUserDestination(ctx, "ssh-bruteforcer", "germany-1", fmt.Sprintf("10.%d.1.1:22", i+1))
	}

	anomalies, err := st.detectAbusePortFlood(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var got *threatintel.Anomaly
	for _, a := range anomalies {
		if a.UserEmail == "ssh-bruteforcer" {
			got = a
			break
		}
	}
	if got == nil {
		t.Fatalf("SSH brute not flagged: %+v", anomalies)
	}
	if got.Type != threatintel.AnomalyAbusePortFlood {
		t.Errorf("type: got %q, want abuse_port_flood", got.Type)
	}
	if got.Details["port"] != "22" {
		t.Errorf("port: got %v, want 22", got.Details["port"])
	}
}

// TestDetectAbusePortFlood_SMTPSpam: spam campaign against 18 different
// mail servers on :587.
func TestDetectAbusePortFlood_SMTPSpam(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	for i := 0; i < 18; i++ {
		_ = st.RecordUserDestination(ctx, "spammer", "germany-1", fmt.Sprintf("smtp-%d.example.com:587", i))
	}
	anomalies, _ := st.detectAbusePortFlood(ctx, time.Now())
	found := false
	for _, a := range anomalies {
		if a.UserEmail == "spammer" && a.Details["port"] == "587" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SMTP spammer not flagged; anomalies=%+v", anomalies)
	}
}

// TestDetectAbusePortFlood_WebNotFlagged: :443 and :80 are NOT abuse
// ports; heavy web activity must not fire this detector.
func TestDetectAbusePortFlood_WebNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		_ = st.RecordUserDestination(ctx, "browser", "germany-1", fmt.Sprintf("web-%d.com:443", i))
	}
	anomalies, _ := st.detectAbusePortFlood(ctx, time.Now())
	for _, a := range anomalies {
		if a.UserEmail == "browser" {
			t.Errorf("web traffic flagged as abuse flood: %+v", a)
		}
	}
}
