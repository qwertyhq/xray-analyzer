//go:build sqlite_legacy

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

// TestDetectBurstScan_SSHSweepOnScatteredNetworks: the exact real-world
// signature observed on prod — one user (e.g. "15333") generates 25 new
// (user, IPv4, port=22) entries inside a minute, spread across unrelated
// networks so port_scan's /16 concentration check misses it. detectBurstScan
// must fire on that.
func TestDetectBurstScan_SSHSweepOnScatteredNetworks(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	// 25 distinct SSH targets across /24s — no /16 concentration.
	for i := 0; i < 25; i++ {
		_ = st.RecordUserDestination(ctx, "mamka-hacker", "poland-1", fmt.Sprintf("10.%d.1.1:22", i+1))
	}

	got, err := st.detectBurstScanAnyTarget(ctx, time.Now())
	if err != nil {
		t.Fatalf("detectBurstScan: %v", err)
	}
	var hit *threatintel.Anomaly
	for _, a := range got {
		if a.UserEmail == "mamka-hacker" {
			hit = a
			break
		}
	}
	if hit == nil {
		t.Fatalf("SSH sweep not flagged: %+v", got)
	}
	if hit.Type != threatintel.AnomalyBurstScan {
		t.Errorf("type: got %q, want burst_scan", hit.Type)
	}
	if hit.Details["port"] != "22" {
		t.Errorf("port: got %v, want 22", hit.Details["port"])
	}
}

// TestDetectBurstScan_BenignPortsIgnored: legitimate heavy-IP traffic on
// NTP / RTSP / BitTorrent / XMPP / web ports must NOT trip the detector.
func TestDetectBurstScan_BenignPortsIgnored(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	cases := []struct {
		user, port string
	}{
		{"ntp-client", "123"},
		{"rtsp-cam", "554"},
		{"xmpp-msg", "5222"},
		{"bittorrent", "6881"},
		{"web-user", "443"},
	}
	for _, c := range cases {
		for i := 0; i < 30; i++ {
			_ = st.RecordUserDestination(ctx, c.user, "poland-1", fmt.Sprintf("10.0.%d.%d:%s", i%256, i/256+1, c.port))
		}
	}

	got, _ := st.detectBurstScanAnyTarget(ctx, time.Now())
	for _, a := range got {
		for _, c := range cases {
			if a.UserEmail == c.user {
				t.Errorf("%s on :%s flagged as burst scan (false positive): %+v", c.user, c.port, a)
			}
		}
	}
}

// TestDetectBurstScan_BelowThresholdNotFlagged: 10 unique IPs on :22 stays
// under the 15-IP bar.
func TestDetectBurstScan_BelowThresholdNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_ = st.RecordUserDestination(ctx, "low-vol", "poland-1", fmt.Sprintf("10.%d.1.1:22", i+1))
	}
	got, _ := st.detectBurstScanAnyTarget(ctx, time.Now())
	for _, a := range got {
		if a.UserEmail == "low-vol" {
			t.Errorf("user under threshold flagged: %+v", a)
		}
	}
}

// TestGetAttackAnomalies_FiltersByType: GetAttackAnomalies is the backing
// store for the new Attacks tab. It must return ONLY records of the
// requested attack types — no activity_spike / night_activity noise.
func TestGetAttackAnomalies_FiltersByType(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insert := func(id, atype string) {
		if err := st.SaveAnomaly(ctx, &threatintel.Anomaly{
			ID: id, Type: threatintel.AnomalyType(atype), Severity: threatintel.SeverityHigh,
			UserEmail: "u", Description: id, DetectedAt: now,
		}); err != nil {
			t.Fatalf("SaveAnomaly: %v", err)
		}
	}
	insert("ps-1", "port_scan")
	insert("af-1", "abuse_port_flood")
	insert("sp-1", "activity_spike") // must be filtered out
	insert("na-1", "night_activity") // must be filtered out

	got, err := st.GetAttackAnomalies(ctx, []string{"port_scan", "abuse_port_flood"}, time.Hour, 50, false)
	if err != nil {
		t.Fatalf("GetAttackAnomalies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 attack-type rows, got %d", len(got))
	}
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.ID] = true
		if a.Type != threatintel.AnomalyPortScan && a.Type != threatintel.AnomalyAbusePortFlood {
			t.Errorf("non-attack type leaked through: %s", a.Type)
		}
	}
	if !seen["ps-1"] || !seen["af-1"] {
		t.Errorf("missing expected ids: seen=%v", seen)
	}
}

// TestGetAttackAnomalies_SkipsResolved: resolved rows must be hidden by
// default (UI only cares about live attacks).
func TestGetAttackAnomalies_SkipsResolved(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_ = st.SaveAnomaly(ctx, &threatintel.Anomaly{ID: "active", Type: threatintel.AnomalyPortScan, Severity: threatintel.SeverityHigh, UserEmail: "u", Description: "a", DetectedAt: now})
	_ = st.SaveAnomaly(ctx, &threatintel.Anomaly{ID: "done", Type: threatintel.AnomalyPortScan, Severity: threatintel.SeverityHigh, UserEmail: "u", Description: "d", DetectedAt: now, Resolved: true})

	got, _ := st.GetAttackAnomalies(ctx, []string{"port_scan"}, time.Hour, 50, false)
	if len(got) != 1 || got[0].ID != "active" {
		t.Errorf("expected only 'active', got %+v", got)
	}

	gotAll, _ := st.GetAttackAnomalies(ctx, []string{"port_scan"}, time.Hour, 50, true)
	if len(gotAll) != 2 {
		t.Errorf("includeResolved=true should return both, got %d", len(gotAll))
	}
}
