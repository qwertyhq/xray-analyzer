package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/storage"

	_ "modernc.org/sqlite"
)

// newTestAnalyzer wires an Analyzer against a fresh on-disk SQLite DB and
// an empty blacklist file. Returns the analyzer and the storage so tests
// can run direct SQL assertions.
func newTestAnalyzer(t *testing.T, bridgePattern string) (*Analyzer, *storage.Storage) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	blPath := filepath.Join(dir, "blacklist.txt")
	if err := os.WriteFile(blPath, []byte{}, 0644); err != nil {
		t.Fatalf("write blacklist: %v", err)
	}
	bl := blacklist.New(blPath, time.Hour)
	if err := bl.Start(context.Background()); err != nil {
		t.Fatalf("blacklist.Start: %v", err)
	}

	a := New(bl, store, make(chan *models.Alert, 16), 1000, time.Hour)
	if err := a.SetBridgeInboundPattern(bridgePattern); err != nil {
		t.Fatalf("SetBridgeInboundPattern: %v", err)
	}
	return a, store
}

// TestProcessBatch_BridgedSourceIPSuppressed verifies the Layer-1 fix: an
// entry whose Inbound matches the bridge pattern (e.g. BRIDGE_DE_IN) must
// NOT have its source IP recorded into user_ip_history — that "IP" is the
// upstream bridge node, not a real client.
//
// A regular entry from the same batch (REALITY_IN) MUST still be recorded
// to prove the filter is selective, not a blanket disable.
func TestProcessBatch_BridgedSourceIPSuppressed(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	ctx := context.Background()

	batch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{
				Timestamp:   time.Now(),
				SourceIP:    "5.188.141.197", // RU-White bridge node IP
				UserEmail:   "5117",
				Destination: "youtube.com:443",
				Inbound:     "BRIDGE_DE_IN",
			},
			{
				Timestamp:   time.Now(),
				SourceIP:    "203.0.113.5", // direct client
				UserEmail:   "9999",
				Destination: "google.com:443",
				Inbound:     "REALITY_IN",
			},
		},
		Count: 2,
	}

	if _, _, err := a.ProcessBatch(ctx, batch); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	db := store.DB()
	count := func(query string, args ...interface{}) int {
		var n int
		if err := db.QueryRow(query, args...).Scan(&n); err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		return n
	}

	// Bridged user must NOT appear in user_ip_history.
	if got := count(`SELECT COUNT(*) FROM user_ip_history WHERE user_email=? AND ip_address=?`, "5117", "5.188.141.197"); got != 0 {
		t.Errorf("user_ip_history leaked bridge IP for bridged user: got %d rows, want 0", got)
	}
	// Direct user MUST appear.
	if got := count(`SELECT COUNT(*) FROM user_ip_history WHERE user_email=? AND ip_address=?`, "9999", "203.0.113.5"); got != 1 {
		t.Errorf("user_ip_history missing direct client IP: got %d rows, want 1", got)
	}

	// Destinations are recorded for both — destination is correct on either side.
	if got := count(`SELECT COUNT(*) FROM user_destinations WHERE user_email=?`, "5117"); got != 1 {
		t.Errorf("user_destinations missing for bridged user: got %d, want 1", got)
	}
	if got := count(`SELECT COUNT(*) FROM user_destinations WHERE user_email=?`, "9999"); got != 1 {
		t.Errorf("user_destinations missing for direct user: got %d, want 1", got)
	}
}

// TestProcessBatch_BridgePatternVariants ensures the default-style regex
// matches both BRIDGE_DE_IN and the suffixed BRIDGE_DE_IN_2 form, but
// does NOT accidentally match unrelated inbounds containing "BRIDGE_OUT_*"
// (those are outbound-tagged tunnel writes on the bridge node itself).
func TestProcessBatch_BridgePatternVariants(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	ctx := context.Background()

	batch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{Timestamp: time.Now(), SourceIP: "10.0.0.1", UserEmail: "u-de-in", Destination: "x.com:443", Inbound: "BRIDGE_DE_IN"},
			{Timestamp: time.Now(), SourceIP: "10.0.0.2", UserEmail: "u-de-in-2", Destination: "x.com:443", Inbound: "BRIDGE_DE_IN_2"},
			{Timestamp: time.Now(), SourceIP: "10.0.0.3", UserEmail: "u-out", Destination: "x.com:443", Inbound: "BRIDGE_OUT_DE"},
			{Timestamp: time.Now(), SourceIP: "10.0.0.4", UserEmail: "u-direct", Destination: "x.com:443", Inbound: "REALITY_IN"},
		},
		Count: 4,
	}
	if _, _, err := a.ProcessBatch(ctx, batch); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	db := store.DB()
	hasIP := func(user string) bool {
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM user_ip_history WHERE user_email=?`, user).Scan(&n)
		return n > 0
	}

	cases := []struct {
		user       string
		expectHas  bool
		shouldNote string
	}{
		{"u-de-in", false, "BRIDGE_DE_IN must be filtered"},
		{"u-de-in-2", false, "BRIDGE_DE_IN_2 must be filtered"},
		{"u-out", true, "BRIDGE_OUT_DE is not an inbound — must NOT be filtered"},
		{"u-direct", true, "REALITY_IN must NOT be filtered"},
	}
	for _, tc := range cases {
		if got := hasIP(tc.user); got != tc.expectHas {
			t.Errorf("user %s: hasIP=%v, want %v (%s)", tc.user, got, tc.expectHas, tc.shouldNote)
		}
	}
}

// TestProcessBatch_CorrelatesBridgedFlowToRealClientIP exercises Layer 3:
// 1) bridge node (ru-white) ingests a real client IP for user "5117" — this
//    populates user_ip_history via the normal ProcessBatch path.
// 2) exit node (germany-1) processes a bridged-flow entry for the same user
//    with destination youtube.com:443. The analyzer must look up the real
//    client IP from step 1 and write a row into bridged_flows.
func TestProcessBatch_CorrelatesBridgedFlowToRealClientIP(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	a.SetBridgeCorrelation([]string{"ru-white"}, 30*time.Second)
	ctx := context.Background()

	now := time.Now()

	// Step 1 — bridge node sees the real client IP for user 5117 (REALITY_IN
	// is a regular user-facing inbound, not bridged, so the source IP IS
	// recorded into user_ip_history).
	bridgeBatch := &models.LogBatch{
		NodeID: "ru-white",
		Entries: []models.LogEntry{
			{
				Timestamp:   now,
				SourceIP:    "91.78.168.130", // real client
				UserEmail:   "5117",
				Destination: "5.188.141.197:9999", // tunnel destination
				Inbound:     "REALITY_IN",
			},
		},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, bridgeBatch); err != nil {
		t.Fatalf("bridge ProcessBatch: %v", err)
	}

	// Step 2 — exit node processes the bridged outbound for the same user.
	exitBatch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{
				Timestamp:   now.Add(50 * time.Millisecond),
				SourceIP:    "5.188.141.197", // bridge node IP, must be filtered
				UserEmail:   "5117",
				Destination: "youtube.com:443",
				Inbound:     "BRIDGE_DE_IN",
			},
		},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatalf("exit ProcessBatch: %v", err)
	}

	flows, err := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{UserEmail: "5117"})
	if err != nil {
		t.Fatalf("GetBridgedFlows: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 bridged_flow row, got %d", len(flows))
	}
	got := flows[0]
	if got.RealClientIP != "91.78.168.130" {
		t.Errorf("real_client_ip: got %q, want 91.78.168.130", got.RealClientIP)
	}
	if got.BridgeNodeID != "ru-white" {
		t.Errorf("bridge_node_id: got %q, want ru-white", got.BridgeNodeID)
	}
	if got.ExitNodeID != "germany-1" {
		t.Errorf("exit_node_id: got %q, want germany-1", got.ExitNodeID)
	}
	if got.Destination != "youtube.com:443" {
		t.Errorf("destination: got %q, want youtube.com:443", got.Destination)
	}
}

// TestProcessBatch_CorrelatesLongLivedBridgeTunnel: the common production
// case. A client opened a bridge tunnel hours ago; Xray logged it once on
// the bridge node and hasn't logged it since (requests inside the tunnel
// don't generate new accept events on the bridge side). A fresh exit-node
// bridged entry must still resolve to the bridge-recorded IP, as long as
// it falls within the configured maxAge lookback.
func TestProcessBatch_CorrelatesLongLivedBridgeTunnel(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	a.SetBridgeCorrelation([]string{"ru-white"}, 24*time.Hour)
	ctx := context.Background()

	// Bridge sees this user ONCE, two hours ago.
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	bridgeBatch := &models.LogBatch{
		NodeID: "ru-white",
		Entries: []models.LogEntry{{
			Timestamp:   twoHoursAgo,
			SourceIP:    "91.78.168.130",
			UserEmail:   "long-lived-5117",
			Destination: "5.188.141.197:9999",
			Inbound:     "REALITY_IN",
		}},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, bridgeBatch); err != nil {
		t.Fatalf("bridge ProcessBatch: %v", err)
	}

	// Fresh exit-node bridged flow right now.
	exitBatch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{{
			Timestamp:   time.Now(),
			SourceIP:    "5.188.141.197",
			UserEmail:   "long-lived-5117",
			Destination: "youtube.com:443",
			Inbound:     "BRIDGE_DE_IN",
		}},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatalf("exit ProcessBatch: %v", err)
	}

	flows, err := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{UserEmail: "long-lived-5117"})
	if err != nil {
		t.Fatalf("GetBridgedFlows: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("long-lived tunnel not correlated: got %d flows, want 1", len(flows))
	}
	if flows[0].RealClientIP != "91.78.168.130" {
		t.Errorf("real_client_ip: got %q, want 91.78.168.130", flows[0].RealClientIP)
	}
}

// TestProcessBatch_StaleBridgeRecordNotUsed verifies the lookback ceiling.
// We simulate an aged user_ip_history row by inserting it directly with an
// old last_seen (ProcessBatch stamps last_seen with now(), so this is the
// only way to exercise the boundary). Record older than maxAge must be
// ignored so we don't attribute flows to a previous session's IP.
func TestProcessBatch_StaleBridgeRecordNotUsed(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	a.SetBridgeCorrelation([]string{"ru-white"}, 1*time.Hour)
	ctx := context.Background()

	// Insert a user_ip_history row with last_seen 3h ago (beyond 1h maxAge).
	threeHoursAgo := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	_, err := store.DB().ExecContext(ctx, `
		INSERT INTO user_ip_history (user_email, ip_address, node_id, first_seen, last_seen, request_count)
		VALUES (?, ?, ?, ?, ?, 1)
	`, "stale-user", "91.78.168.130", "ru-white", threeHoursAgo, threeHoursAgo)
	if err != nil {
		t.Fatalf("seed user_ip_history: %v", err)
	}

	_, _, err = a.ProcessBatch(ctx, &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{{
			Timestamp:   time.Now(),
			SourceIP:    "5.188.141.197",
			UserEmail:   "stale-user",
			Destination: "x.com:443",
			Inbound:     "BRIDGE_DE_IN",
		}},
		Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	flows, err := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{UserEmail: "stale-user"})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 0 {
		t.Errorf("stale bridge record was used: got %d flows, want 0", len(flows))
	}
}

// TestProcessBatch_NoCorrelationWhenBridgeUnknown verifies that an exit-node
// bridged flow without a matching bridge user_ip_history record produces NO
// bridged_flows row (silent skip; future batches may resolve it).
func TestProcessBatch_NoCorrelationWhenBridgeUnknown(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	a.SetBridgeCorrelation([]string{"ru-white"}, 30*time.Second)
	ctx := context.Background()

	exitBatch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{
				Timestamp:   time.Now(),
				SourceIP:    "5.188.141.197",
				UserEmail:   "ghost-user",
				Destination: "anywhere.com:443",
				Inbound:     "BRIDGE_DE_IN",
			},
		},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	flows, err := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{UserEmail: "ghost-user"})
	if err != nil {
		t.Fatalf("GetBridgedFlows: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("expected 0 bridged_flows for unresolvable user, got %d", len(flows))
	}
}

// TestProcessBatch_NoCorrelationWhenDisabled verifies that with empty
// bridgeNodeIDs the correlator stays out of the way (no extra rows, no
// errors) — opt-out for nodes that don't run a bridge.
func TestProcessBatch_NoCorrelationWhenDisabled(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	// Note: SetBridgeCorrelation NOT called → no node IDs configured.
	ctx := context.Background()

	now := time.Now()
	bridgeBatch := &models.LogBatch{
		NodeID:  "ru-white",
		Entries: []models.LogEntry{{Timestamp: now, SourceIP: "91.78.168.130", UserEmail: "u1", Destination: "5.188.141.197:9999", Inbound: "REALITY_IN"}},
		Count:   1,
	}
	exitBatch := &models.LogBatch{
		NodeID:  "germany-1",
		Entries: []models.LogEntry{{Timestamp: now, SourceIP: "5.188.141.197", UserEmail: "u1", Destination: "x.com:443", Inbound: "BRIDGE_DE_IN"}},
		Count:   1,
	}
	if _, _, err := a.ProcessBatch(ctx, bridgeBatch); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatal(err)
	}

	flows, err := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{})
	if err != nil {
		t.Fatalf("GetBridgedFlows: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("correlation disabled, expected 0 rows, got %d", len(flows))
	}
}

// TestProcessBatch_NoFilterWhenPatternEmpty makes sure an empty pattern
// disables the filter entirely (back-compat, opt-out).
func TestProcessBatch_NoFilterWhenPatternEmpty(t *testing.T) {
	a, store := newTestAnalyzer(t, "")
	ctx := context.Background()

	batch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{Timestamp: time.Now(), SourceIP: "5.188.141.197", UserEmail: "5117", Destination: "x.com:443", Inbound: "BRIDGE_DE_IN"},
		},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, batch); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	var n int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM user_ip_history WHERE user_email=?`, "5117").Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Errorf("filter disabled, expected IP recorded for bridged user, got %d rows", n)
	}
}
