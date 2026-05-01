package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// TestDetectPortScan_Slash16Sweep: the 2026-04-15 abuse signature — 25
// unique 147.251.x.y:8317 destinations from one user. All IPs in one /16,
// non-web port → fires.
func TestDetectPortScan_Slash16Sweep(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	// RecordUserDestination converts non-UUID strings to deterministic SHA-1 UUID.
	// The detect* query returns that same UUID so we compare with testUUID(name).
	scannerEmail := testUUID("scanner-1")
	for i := 0; i < 25; i++ {
		_ = st.RecordUserDestination(ctx, scannerEmail, "germany-1", fmt.Sprintf("147.251.6.%d:8317", i+1))
	}

	anomalies, err := st.detectPortScan(ctx, time.Now())
	if err != nil {
		t.Fatalf("detectPortScan: %v", err)
	}
	var got *threatintel.Anomaly
	for _, a := range anomalies {
		if a.UserEmail == scannerEmail {
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

	whatsappEmail := testUUID("whatsapp-user")
	// 100 IPs spread across 10 distinct /16s, all on :443 — normal CDN.
	subnets := []string{"31.13.64", "31.13.65", "31.13.66", "157.240.1", "157.240.2",
		"102.132.96", "163.70.128", "173.252.100", "179.60.192", "185.60.216"}
	for _, s := range subnets {
		for i := 0; i < 10; i++ {
			_ = st.RecordUserDestination(ctx, whatsappEmail, "germany-1", fmt.Sprintf("%s.%d:443", s, i+1))
		}
	}

	anomalies, err := st.detectPortScan(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range anomalies {
		if a.UserEmail == whatsappEmail {
			t.Errorf("WhatsApp false positive: %+v", a)
		}
	}
}

// TestDetectPortScan_DomainTrafficNotFlagged: normal domain browsing has
// no IPv4 form, the regex filter must drop it.
func TestDetectPortScan_DomainTrafficNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	browserEmail := testUUID("browser")
	for i := 0; i < 50; i++ {
		_ = st.RecordUserDestination(ctx, browserEmail, "germany-1", fmt.Sprintf("site-%d.example.com:443", i))
	}
	anomalies, _ := st.detectPortScan(ctx, time.Now())
	for _, a := range anomalies {
		if a.UserEmail == browserEmail {
			t.Errorf("domain browsing flagged: %+v", a)
		}
	}
}

// TestDetectPortScan_BelowThresholdNotFlagged: just under the 20-IP line.
func TestDetectPortScan_BelowThresholdNotFlagged(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	borderlineEmail := testUUID("borderline")
	for i := 0; i < 15; i++ {
		_ = st.RecordUserDestination(ctx, borderlineEmail, "germany-1", fmt.Sprintf("10.0.0.%d:9999", i))
	}
	anomalies, _ := st.detectPortScan(ctx, time.Now())
	for _, a := range anomalies {
		if a.UserEmail == borderlineEmail {
			t.Errorf("borderline user flagged: %+v", a)
		}
	}
}

// TestDetectAbusePortFlood_SSHSweep: SSH brute against 20 distinct IPs.
// Fires even though the IPs are in different /16s.
func TestDetectAbusePortFlood_SSHSweep(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()

	sshEmail := testUUID("ssh-bruteforcer")
	// 20 distinct /24s, one IP each, all on :22 — scattered SSH brute.
	for i := 0; i < 20; i++ {
		_ = st.RecordUserDestination(ctx, sshEmail, "germany-1", fmt.Sprintf("10.%d.1.1:22", i+1))
	}

	anomalies, err := st.detectAbusePortFlood(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var got *threatintel.Anomaly
	for _, a := range anomalies {
		if a.UserEmail == sshEmail {
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

	spammerEmail := testUUID("spammer")
	for i := 0; i < 18; i++ {
		_ = st.RecordUserDestination(ctx, spammerEmail, "germany-1", fmt.Sprintf("smtp-%d.example.com:587", i))
	}
	anomalies, _ := st.detectAbusePortFlood(ctx, time.Now())
	found := false
	for _, a := range anomalies {
		if a.UserEmail == spammerEmail && a.Details["port"] == "587" {
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
	webEmail := testUUID("browser-web")
	for i := 0; i < 50; i++ {
		_ = st.RecordUserDestination(ctx, webEmail, "germany-1", fmt.Sprintf("web-%d.com:443", i))
	}
	anomalies, _ := st.detectAbusePortFlood(ctx, time.Now())
	for _, a := range anomalies {
		if a.UserEmail == webEmail {
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

	hackerEmail := testUUID("mamka-hacker")
	// 25 distinct SSH targets across /24s — no /16 concentration.
	for i := 0; i < 25; i++ {
		_ = st.RecordUserDestination(ctx, hackerEmail, "poland-1", fmt.Sprintf("10.%d.1.1:22", i+1))
	}

	got, err := st.detectBurstScanAnyTarget(ctx, time.Now())
	if err != nil {
		t.Fatalf("detectBurstScan: %v", err)
	}
	var hit *threatintel.Anomaly
	for _, a := range got {
		if a.UserEmail == hackerEmail {
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
		{"web-user-benign", "443"},
	}
	emailFor := func(name string) string { return testUUID(name) }
	for _, c := range cases {
		for i := 0; i < 30; i++ {
			_ = st.RecordUserDestination(ctx, emailFor(c.user), "poland-1", fmt.Sprintf("10.0.%d.%d:%s", i%256, i/256+1, c.port))
		}
	}

	got, _ := st.detectBurstScanAnyTarget(ctx, time.Now())
	for _, a := range got {
		for _, c := range cases {
			if a.UserEmail == emailFor(c.user) {
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
	lowVolEmail := testUUID("low-vol")
	for i := 0; i < 10; i++ {
		_ = st.RecordUserDestination(ctx, lowVolEmail, "poland-1", fmt.Sprintf("10.%d.1.1:22", i+1))
	}
	got, _ := st.detectBurstScanAnyTarget(ctx, time.Now())
	for _, a := range got {
		if a.UserEmail == lowVolEmail {
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

	uEmail := testUUID("attack-filter-u")
	insert := func(id, atype string) {
		if err := st.SaveAnomaly(ctx, &threatintel.Anomaly{
			ID: id, Type: threatintel.AnomalyType(atype), Severity: threatintel.SeverityHigh,
			UserEmail: uEmail, Description: id, DetectedAt: now,
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

	uEmail := testUUID("attack-resolved-u")
	_ = st.SaveAnomaly(ctx, &threatintel.Anomaly{ID: "active", Type: threatintel.AnomalyPortScan, Severity: threatintel.SeverityHigh, UserEmail: uEmail, Description: "a", DetectedAt: now})
	_ = st.SaveAnomaly(ctx, &threatintel.Anomaly{ID: "done", Type: threatintel.AnomalyPortScan, Severity: threatintel.SeverityHigh, UserEmail: uEmail, Description: "d", DetectedAt: now, Resolved: true})

	got, _ := st.GetAttackAnomalies(ctx, []string{"port_scan"}, time.Hour, 50, false)
	if len(got) != 1 || got[0].ID != "active" {
		t.Errorf("expected only 'active', got %+v", got)
	}

	gotAll, _ := st.GetAttackAnomalies(ctx, []string{"port_scan"}, time.Hour, 50, true)
	if len(gotAll) != 2 {
		t.Errorf("includeResolved=true should return both, got %d", len(gotAll))
	}
}

// TestSaveAndGetAnomaly_RoundTrip: SaveAnomaly then GetAnomalies returns
// the persisted record with correct fields.
func TestSaveAndGetAnomaly_RoundTrip(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// UserEmail must be a valid UUID to round-trip through the uuid column.
	userEmail := testUUID("round-trip-user")
	a := &threatintel.Anomaly{
		ID:          "test-round-trip-1",
		Type:        threatintel.AnomalyPortScan,
		Severity:    threatintel.SeverityHigh,
		UserEmail:   userEmail,
		Description: "round trip test",
		Details:     map[string]any{"port": "8317", "unique_ips": float64(25)},
		DetectedAt:  now,
		Resolved:    false,
	}

	if err := st.SaveAnomaly(ctx, a); err != nil {
		t.Fatalf("SaveAnomaly: %v", err)
	}

	list, err := st.GetAnomalies(ctx, 10, false)
	if err != nil {
		t.Fatalf("GetAnomalies: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(list))
	}
	got := list[0]
	if got.ID != a.ID {
		t.Errorf("ID: got %q want %q", got.ID, a.ID)
	}
	if got.UserEmail != a.UserEmail {
		t.Errorf("UserEmail: got %q want %q", got.UserEmail, a.UserEmail)
	}
	if got.Resolved {
		t.Errorf("expected Resolved=false")
	}
}

// TestResolveAnomaly: ResolveAnomaly sets resolved=1 so GetAnomalies hides it.
func TestResolveAnomaly(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC()

	uEmail := testUUID("resolve-u")
	_ = st.SaveAnomaly(ctx, &threatintel.Anomaly{
		ID: "resolve-me", Type: threatintel.AnomalyAbusePortFlood,
		Severity: threatintel.SeverityHigh, UserEmail: uEmail,
		Description: "will be resolved", DetectedAt: now,
	})

	if err := st.ResolveAnomaly(ctx, "resolve-me"); err != nil {
		t.Fatalf("ResolveAnomaly: %v", err)
	}

	// GetAnomalies with includeResolved=false must hide it
	list, _ := st.GetAnomalies(ctx, 10, false)
	for _, a := range list {
		if a.ID == "resolve-me" {
			t.Error("resolved anomaly still appears in unresolved list")
		}
	}

	// GetAnomalies with includeResolved=true must show it
	all, _ := st.GetAnomalies(ctx, 10, true)
	found := false
	for _, a := range all {
		if a.ID == "resolve-me" {
			found = true
			if !a.Resolved {
				t.Error("anomaly.Resolved should be true")
			}
		}
	}
	if !found {
		t.Error("resolved anomaly not visible with includeResolved=true")
	}
}

// TestGetAnomalySummary_CountsByType: summary aggregates unresolved counts.
func TestGetAnomalySummary_CountsByType(t *testing.T) {
	st := newTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC()

	u1Email := testUUID("summary-u1")
	u2Email := testUUID("summary-u2")

	for i := 0; i < 3; i++ {
		_ = st.SaveAnomaly(ctx, &threatintel.Anomaly{
			ID: fmt.Sprintf("ps-%d", i), Type: threatintel.AnomalyPortScan,
			Severity: threatintel.SeverityHigh, UserEmail: u1Email,
			Description: "x", DetectedAt: now,
		})
	}
	_ = st.SaveAnomaly(ctx, &threatintel.Anomaly{
		ID: "af-1", Type: threatintel.AnomalyAbusePortFlood,
		Severity: threatintel.SeverityHigh, UserEmail: u2Email,
		Description: "x", DetectedAt: now,
	})

	sum, err := st.GetAnomalySummary(ctx)
	if err != nil {
		t.Fatalf("GetAnomalySummary: %v", err)
	}
	if sum.TotalAnomalies != 4 {
		t.Errorf("TotalAnomalies: got %d want 4", sum.TotalAnomalies)
	}
	if sum.ByType[string(threatintel.AnomalyPortScan)] != 3 {
		t.Errorf("ByType[port_scan]: got %d want 3", sum.ByType[string(threatintel.AnomalyPortScan)])
	}
	if sum.AffectedUsers != 2 {
		t.Errorf("AffectedUsers: got %d want 2", sum.AffectedUsers)
	}
}
