package analyzer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/storage"
)

var (
	sharedPGOnce sync.Once
	sharedPGDSN  string
	sharedPGErr  error
)

func sharedPostgres(t *testing.T) string {
	t.Helper()
	sharedPGOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		pg, err := tcpg.Run(ctx, "postgres:17-alpine",
			tcpg.WithDatabase("shared"),
			tcpg.WithUsername("shared"),
			tcpg.WithPassword("shared"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
		)
		if err != nil {
			sharedPGErr = err
			return
		}
		sharedPGDSN, sharedPGErr = pg.ConnectionString(ctx, "sslmode=disable")
	})
	if sharedPGErr != nil {
		t.Fatalf("shared postgres: %v", sharedPGErr)
	}
	return sharedPGDSN
}

func newAnalyzerStorage(t *testing.T) *storage.Storage {
	t.Helper()
	dsn := sharedPostgres(t)
	ctx := context.Background()

	schema := "test_" + randomHex()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	admin.Close()

	scopedDSN := dsn + "&search_path=" + schema
	s, err := storage.New(ctx, scopedDSN)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		cleanupPool, _ := pgxpool.New(ctx, dsn)
		if cleanupPool != nil {
			cleanupPool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			cleanupPool.Close()
		}
	})
	return s
}

func randomHex() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// testEmailUUID converts a test string to a deterministic UUID — same logic as
// storage.emailToUUID so DB writes and query assertions use the same value.
func testEmailUUID(name string) string {
	if u, err := uuid.Parse(name); err == nil {
		return u.String()
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(name)).String()
}

func newTestAnalyzer(t *testing.T, bridgePattern string) (*Analyzer, *storage.Storage) {
	t.Helper()

	store := newAnalyzerStorage(t)

	dir := t.TempDir()
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

// seedBridgeIPRow inserts a user_ip_history row with a controlled last_seen,
// bypassing RecordUserIP's unconditional now() timestamp.
// userEmail may be any string — it is converted to UUID via the same SHA-1 path.
func seedBridgeIPRow(t *testing.T, store *storage.Storage, userEmail, ip, nodeID string, lastSeen time.Time) {
	t.Helper()
	ctx := context.Background()
	// Resolve nodeID to smallint FK.
	nid, err := store.LookupNodeID(ctx, nodeID, "bridge")
	if err != nil {
		t.Fatalf("seed LookupNodeID: %v", err)
	}
	userUUID := testEmailUUID(userEmail)
	_, err = store.Pool().Exec(ctx, `
		INSERT INTO user_ip_history (user_email, ip_address, node_id, first_seen, last_seen, request_count)
		VALUES ($1, $2::inet, $3, $4, $5, 1)
		ON CONFLICT(user_email, ip_address) DO UPDATE SET last_seen = excluded.last_seen
	`, userUUID, ip, int16(nid), lastSeen.UTC(), lastSeen.UTC())
	if err != nil {
		t.Fatalf("seed user_ip_history: %v", err)
	}
}

// TestProcessBatch_BridgedSourceIPSuppressed: Layer 1 — a bridged entry
// must NOT leak the upstream bridge node's IP into user_ip_history. A
// non-bridged entry in the same batch still records normally.
func TestProcessBatch_BridgedSourceIPSuppressed(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	ctx := context.Background()

	user5117 := testEmailUUID("5117")
	user9999 := testEmailUUID("9999")

	batch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{Timestamp: time.Now(), SourceIP: "5.188.141.197", UserEmail: "5117", Destination: "youtube.com:443", Inbound: "BRIDGE_DE_IN"},
			{Timestamp: time.Now(), SourceIP: "203.0.113.5", UserEmail: "9999", Destination: "google.com:443", Inbound: "REALITY_IN"},
		},
		Count: 2,
	}
	if _, _, err := a.ProcessBatch(ctx, batch); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	pool := store.Pool()
	count := func(q string, args ...interface{}) int {
		var n int
		if err := pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		return n
	}

	if got := count(`SELECT COUNT(*) FROM user_ip_history WHERE user_email=$1 AND ip_address=$2::inet`, user5117, "5.188.141.197"); got != 0 {
		t.Errorf("user_ip_history leaked bridge IP: got %d rows, want 0", got)
	}
	if got := count(`SELECT COUNT(*) FROM user_ip_history WHERE user_email=$1 AND ip_address=$2::inet`, user9999, "203.0.113.5"); got != 1 {
		t.Errorf("direct client IP missing: got %d rows, want 1", got)
	}
	// Destinations recorded for both.
	if got := count(`SELECT COUNT(*) FROM user_destinations WHERE user_email=$1`, user5117); got != 1 {
		t.Errorf("bridged destination not recorded: got %d, want 1", got)
	}
}

// TestProcessBatch_BridgePatternVariants: regex matches both BRIDGE_DE_IN
// and BRIDGE_DE_IN_2, but not BRIDGE_OUT_* (which is an outbound tag).
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

	pool := store.Pool()
	hasIP := func(user string) bool {
		userUUID := testEmailUUID(user)
		var n int
		_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_ip_history WHERE user_email=$1`, userUUID).Scan(&n)
		return n > 0
	}
	cases := []struct {
		user      string
		expectHas bool
	}{
		{"u-de-in", false},
		{"u-de-in-2", false},
		{"u-out", true},
		{"u-direct", true},
	}
	for _, tc := range cases {
		if got := hasIP(tc.user); got != tc.expectHas {
			t.Errorf("user %s: hasIP=%v, want %v", tc.user, got, tc.expectHas)
		}
	}
}

// TestProcessBatch_FansOutCandidatesByTime: Layer 3 (time-based, user_email
// collapsed). Two distinct bridge users are active in the correlation
// window on ru-white. An exit-node bridged entry at the same moment must
// produce ONE bridged_flows row PER candidate — so group-by-destination
// later picks the most common one as the most likely culprit.
func TestProcessBatch_FansOutCandidatesByTime(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	a.SetBridgeCorrelation([]string{"ru-white"}, 15*time.Second)
	ctx := context.Background()

	now := time.Now()
	user4875UUID := testEmailUUID("4875")
	user7368UUID := testEmailUUID("7368")
	seedBridgeIPRow(t, store, "4875", "128.71.84.176", "ru-white", now)
	seedBridgeIPRow(t, store, "7368", "91.78.219.232", "ru-white", now)

	exitBatch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{Timestamp: now, SourceIP: "5.188.141.197", UserEmail: "5117", Destination: "youtube.com:443", Inbound: "BRIDGE_DE_IN"},
		},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatal(err)
	}

	flows, err := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{Destination: "youtube.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("expected 2 candidate rows, got %d", len(flows))
	}
	got := map[string]string{}
	for _, f := range flows {
		got[f.UserEmail] = f.RealClientIP
	}
	if got[user4875UUID] != "128.71.84.176" || got[user7368UUID] != "91.78.219.232" {
		t.Errorf("candidate rows wrong: %v", got)
	}
}

// TestProcessBatch_IdleUserNotIncluded: a user whose last_seen on the
// bridge is outside the window must NOT appear as a candidate. The
// window bounds false-positive blame.
func TestProcessBatch_IdleUserNotIncluded(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	a.SetBridgeCorrelation([]string{"ru-white"}, 10*time.Second)
	ctx := context.Background()

	now := time.Now()
	activeUUID := testEmailUUID("active-user")
	// Active: last seen now.
	seedBridgeIPRow(t, store, "active-user", "10.0.0.1", "ru-white", now)
	// Idle: last seen 5 minutes ago — outside ±10s window.
	seedBridgeIPRow(t, store, "idle-user", "10.0.0.2", "ru-white", now.Add(-5*time.Minute))

	exitBatch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{Timestamp: now, SourceIP: "5.188.141.197", UserEmail: "5117", Destination: "target.com:443", Inbound: "BRIDGE_DE_IN"},
		},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatal(err)
	}

	flows, _ := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{Destination: "target.com"})
	if len(flows) != 1 {
		t.Fatalf("expected 1 candidate (only active), got %d", len(flows))
	}
	if flows[0].UserEmail != activeUUID {
		t.Errorf("wrong candidate: got %q, want %q", flows[0].UserEmail, activeUUID)
	}
}

// TestProcessBatch_NoCandidatesNoFlows: when nothing is active on the
// bridge in the window, no row is written (silent skip).
func TestProcessBatch_NoCandidatesNoFlows(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	a.SetBridgeCorrelation([]string{"ru-white"}, 15*time.Second)
	ctx := context.Background()

	exitBatch := &models.LogBatch{
		NodeID: "germany-1",
		Entries: []models.LogEntry{
			{Timestamp: time.Now(), SourceIP: "5.188.141.197", UserEmail: "5117", Destination: "x.com:443", Inbound: "BRIDGE_DE_IN"},
		},
		Count: 1,
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatal(err)
	}
	flows, _ := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{})
	if len(flows) != 0 {
		t.Errorf("expected 0 flows without candidates, got %d", len(flows))
	}
}

// TestProcessBatch_NoCorrelationWhenDisabled: empty bridgeNodeIDs disables
// fan-out entirely.
func TestProcessBatch_NoCorrelationWhenDisabled(t *testing.T) {
	a, store := newTestAnalyzer(t, `^BRIDGE_.*_IN(_\d+)?$`)
	// SetBridgeCorrelation NOT called.
	ctx := context.Background()

	now := time.Now()
	seedBridgeIPRow(t, store, "4875", "128.71.84.176", "ru-white", now)

	exitBatch := &models.LogBatch{
		NodeID:  "germany-1",
		Entries: []models.LogEntry{{Timestamp: now, SourceIP: "5.188.141.197", UserEmail: "5117", Destination: "x.com:443", Inbound: "BRIDGE_DE_IN"}},
		Count:   1,
	}
	if _, _, err := a.ProcessBatch(ctx, exitBatch); err != nil {
		t.Fatal(err)
	}
	flows, _ := store.GetBridgedFlows(ctx, storage.BridgedFlowsFilter{})
	if len(flows) != 0 {
		t.Errorf("correlation disabled, expected 0 rows, got %d", len(flows))
	}
}

// TestProcessBatch_NoFilterWhenPatternEmpty: empty pattern disables the
// filter entirely (back-compat).
func TestProcessBatch_NoFilterWhenPatternEmpty(t *testing.T) {
	a, store := newTestAnalyzer(t, "")
	ctx := context.Background()

	user5117UUID := testEmailUUID("5117")

	batch := &models.LogBatch{
		NodeID:  "germany-1",
		Entries: []models.LogEntry{{Timestamp: time.Now(), SourceIP: "5.188.141.197", UserEmail: "5117", Destination: "x.com:443", Inbound: "BRIDGE_DE_IN"}},
		Count:   1,
	}
	if _, _, err := a.ProcessBatch(ctx, batch); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	var n int
	_ = store.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM user_ip_history WHERE user_email=$1`, user5117UUID).Scan(&n)
	if n != 1 {
		t.Errorf("filter disabled, expected bridge IP recorded, got %d", n)
	}
}
