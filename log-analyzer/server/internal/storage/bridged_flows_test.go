package storage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testUUID generates a deterministic UUID from a name for tests.
func testUUID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(name)).String()
}

func makeFlow(userEmail, realIP, bridgeNode, exitNode, dst string, ts time.Time) *BridgedFlow {
	return &BridgedFlow{
		UserEmail:    userEmail,
		RealClientIP: realIP,
		BridgeNodeID: bridgeNode,
		ExitNodeID:   exitNode,
		Destination:  dst,
		Timestamp:    ts,
	}
}

func TestBridgedFlows_RecordAndGet(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	userUUID := testUUID("bf-user")
	now := time.Now().UTC()
	f := makeFlow(userUUID, "10.0.0.1", "bridge-1", "exit-1", "example.com", now)

	if err := s.RecordBridgedFlow(ctx, f); err != nil {
		t.Fatalf("RecordBridgedFlow: %v", err)
	}

	flows, err := s.GetBridgedFlows(ctx, BridgedFlowsFilter{UserEmail: userUUID})
	if err != nil {
		t.Fatalf("GetBridgedFlows: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("len = %d, want 1", len(flows))
	}
	got := flows[0]
	if got.UserEmail != userUUID {
		t.Errorf("UserEmail = %q, want %q", got.UserEmail, userUUID)
	}
	if got.RealClientIP != f.RealClientIP {
		t.Errorf("RealClientIP = %q, want %q", got.RealClientIP, f.RealClientIP)
	}
	if got.BridgeNodeID != f.BridgeNodeID {
		t.Errorf("BridgeNodeID = %q, want %q", got.BridgeNodeID, f.BridgeNodeID)
	}
	if got.Destination != f.Destination {
		t.Errorf("Destination = %q, want %q", got.Destination, f.Destination)
	}
	if got.ID == 0 {
		t.Error("ID should be non-zero after insert")
	}
}

func TestBridgedFlows_NilFlow(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	if err := s.RecordBridgedFlow(ctx, nil); err == nil {
		t.Error("expected error for nil flow")
	}
}

func TestBridgedFlows_GetFilter_Destination(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	u := testUUID("filter-dest-user")
	now := time.Now().UTC()
	flows := []*BridgedFlow{
		makeFlow(u, "10.0.0.1", "b1", "e1", "alpha.com", now),
		makeFlow(u, "10.0.0.2", "b1", "e1", "beta.com", now),
		makeFlow(u, "10.0.0.3", "b1", "e1", "gamma.com", now),
	}
	for _, fl := range flows {
		if err := s.RecordBridgedFlow(ctx, fl); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.GetBridgedFlows(ctx, BridgedFlowsFilter{Destination: "beta"})
	if err != nil {
		t.Fatalf("GetBridgedFlows: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result for 'beta', got %d", len(got))
	}
	if got[0].Destination != "beta.com" {
		t.Errorf("Destination = %q, want beta.com", got[0].Destination)
	}
}

func TestBridgedFlows_GetFilter_Since(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	u := testUUID("filter-since-user")
	past := time.Now().UTC().Add(-2 * time.Hour)
	recent := time.Now().UTC().Add(-30 * time.Minute)

	if err := s.RecordBridgedFlow(ctx, makeFlow(u, "1.1.1.1", "b1", "e1", "old.com", past)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBridgedFlow(ctx, makeFlow(u, "2.2.2.2", "b1", "e1", "new.com", recent)); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	got, err := s.GetBridgedFlows(ctx, BridgedFlowsFilter{Since: cutoff})
	if err != nil {
		t.Fatalf("GetBridgedFlows: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result after cutoff, got %d", len(got))
	}
	if got[0].Destination != "new.com" {
		t.Errorf("Destination = %q, want new.com", got[0].Destination)
	}
}

func TestBridgedFlows_LookupBridgeCandidates(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC()
	userUUID := testUUID("cand-user")

	// First ensure node exists in nodes table.
	bridgeNID, err := s.LookupNodeID(ctx, "bridge-node-A", "bridge")
	if err != nil {
		t.Fatalf("LookupNodeID: %v", err)
	}

	// Seed user_ip_history directly using the smallint node id.
	uid, _ := uuid.Parse(userUUID)
	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_ip_history (user_email, ip_address, node_id, first_seen, last_seen)
		VALUES ($1, $2::inet, $3, $4, $5)
	`, uid, "192.168.1.1", int16(bridgeNID), now.Add(-2*time.Second), now)
	if err != nil {
		t.Fatalf("seed user_ip_history: %v", err)
	}

	candidates, err := s.LookupBridgeCandidates(ctx, now, 15*time.Second, []string{"bridge-node-A"})
	if err != nil {
		t.Fatalf("LookupBridgeCandidates: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate")
	}
	if candidates[0].UserEmail != userUUID {
		t.Errorf("UserEmail = %q, want %q", candidates[0].UserEmail, userUUID)
	}
	if candidates[0].IPAddress != "192.168.1.1" {
		t.Errorf("IPAddress = %q, want 192.168.1.1", candidates[0].IPAddress)
	}
}

func TestBridgedFlows_LookupBridgeCandidates_EmptyNodeIDs(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	out, err := s.LookupBridgeCandidates(ctx, time.Now(), 5*time.Second, nil)
	if err != nil {
		t.Fatalf("expected no error for empty nodeIDs, got %v", err)
	}
	if out != nil {
		t.Errorf("expected nil result for empty nodeIDs")
	}
}

func TestBridgedFlows_LookupRealClientIP(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC()
	userUUID := testUUID("real-ip-user")

	// Ensure node in nodes table.
	bridgeNID, err := s.LookupNodeID(ctx, "bridge-B", "bridge")
	if err != nil {
		t.Fatalf("LookupNodeID: %v", err)
	}

	uid, _ := uuid.Parse(userUUID)
	_, err = s.pool.Exec(ctx, `
		INSERT INTO user_ip_history (user_email, ip_address, node_id, first_seen, last_seen)
		VALUES ($1, $2::inet, $3, $4, $5)
	`, uid, "10.10.10.10", int16(bridgeNID), now.Add(-5*time.Minute), now)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	ip, node, ok := s.LookupRealClientIP(ctx, userUUID, now, 1*time.Hour, []string{"bridge-B"})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ip != "10.10.10.10" {
		t.Errorf("ip = %q, want 10.10.10.10", ip)
	}
	if node != "bridge-B" {
		t.Errorf("node = %q, want bridge-B", node)
	}
}

func TestBridgedFlows_LookupRealClientIP_NotFound(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	ghostUUID := testUUID("ghost-user")
	_, _, ok := s.LookupRealClientIP(ctx, ghostUUID, time.Now(), time.Hour, []string{"some-node"})
	if ok {
		t.Error("expected ok=false for unknown user")
	}
}

func TestBridgedFlows_Cleanup(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	u := testUUID("cleanup-user")
	oldTs := time.Now().UTC().Add(-40 * 24 * time.Hour)
	recentTs := time.Now().UTC().Add(-1 * time.Hour)

	if err := s.RecordBridgedFlow(ctx, makeFlow(u, "1.1.1.1", "b", "e", "old.com", oldTs)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBridgedFlow(ctx, makeFlow(u, "2.2.2.2", "b", "e", "new.com", recentTs)); err != nil {
		t.Fatal(err)
	}

	if err := s.CleanupBridgedFlows(ctx, 30); err != nil {
		t.Fatalf("CleanupBridgedFlows: %v", err)
	}

	var cnt int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM bridged_flows").Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Errorf("after cleanup: %d rows, want 1", cnt)
	}
}

func TestRecordBridgedFlow_NonUUIDEmail(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	const syntheticEmail = "5117"
	knownUUID := uuid.MustParse("11111111-1111-4111-8111-111111111111")

	// Pre-seed remna_users so ResolveUserEmailToUUID finds it by username.
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO remna_users (uuid, username, status)
		VALUES ($1, $2, 'ACTIVE')
	`, knownUUID, syntheticEmail); err != nil {
		t.Fatalf("seed remna_users: %v", err)
	}

	// LookupNodeID upserts the node so it exists in the nodes table.
	if _, err := s.LookupNodeID(ctx, "ru-bridge", "bridge"); err != nil {
		t.Fatalf("LookupNodeID bridge: %v", err)
	}
	if _, err := s.LookupNodeID(ctx, "germany-1", "exit"); err != nil {
		t.Fatalf("LookupNodeID exit: %v", err)
	}

	if err := s.RecordBridgedFlow(ctx, &BridgedFlow{
		UserEmail:    syntheticEmail,
		RealClientIP: "203.0.113.5",
		BridgeNodeID: "ru-bridge",
		ExitNodeID:   "germany-1",
		Destination:  "example-bf.com:443",
		Timestamp:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("non-UUID email should succeed via remna_users lookup: %v", err)
	}

	var got uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT user_email FROM bridged_flows WHERE destination = $1`, "example-bf.com:443",
	).Scan(&got)
	if err != nil {
		t.Fatalf("query inserted row: %v", err)
	}
	if got != knownUUID {
		t.Errorf("user_email = %s, want %s (remna_users uuid for %q)", got, knownUUID, syntheticEmail)
	}
}

func TestRecordBridgedFlow_EmailIndexFallback(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	const unknownEmail = "totally-unknown-id-not-in-remna"

	if _, err := s.LookupNodeID(ctx, "ru-bridge", "bridge"); err != nil {
		t.Fatalf("LookupNodeID bridge: %v", err)
	}
	if _, err := s.LookupNodeID(ctx, "germany-1", "exit"); err != nil {
		t.Fatalf("LookupNodeID exit: %v", err)
	}

	if err := s.RecordBridgedFlow(ctx, &BridgedFlow{
		UserEmail:    unknownEmail,
		RealClientIP: "203.0.113.6",
		BridgeNodeID: "ru-bridge",
		ExitNodeID:   "germany-1",
		Destination:  "unknown-fallback.com:443",
		Timestamp:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("unknown email should succeed via SHA-1 fallback: %v", err)
	}

	// email_index must have a row with original_email = unknownEmail.
	var storedEmail string
	err := s.pool.QueryRow(ctx,
		`SELECT original_email FROM email_index WHERE original_email = $1`, unknownEmail,
	).Scan(&storedEmail)
	if err != nil {
		t.Fatalf("email_index row not written: %v", err)
	}
	if storedEmail != unknownEmail {
		t.Errorf("email_index.original_email = %q, want %q", storedEmail, unknownEmail)
	}
}
