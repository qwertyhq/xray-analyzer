package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestSchemaAppliesCleanly loads schema.sql into a fresh Postgres and asserts
// every expected table exists. It guards against dialect-specific DDL bugs
// (SQLite AUTOINCREMENT vs Postgres IDENTITY, strftime-indexed generated
// columns, etc.) before we port any query code.
func TestSchemaAppliesCleanly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	pg, err := tcpg.Run(ctx, "postgres:17-alpine",
		tcpg.WithDatabase("test"),
		tcpg.WithUsername("test"),
		tcpg.WithPassword("test"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	defer pg.Terminate(ctx)

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	schema, err := os.ReadFile(filepath.Join("schema.sql"))
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	if _, err := pool.Exec(ctx, string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	wantTables := []string{
		"node_stats", "user_stats", "blacklist_matches", "alerts", "hourly_stats",
		"user_destinations", "threat_matches", "anomalies", "user_ip_history",
		"user_risk_profiles", "remna_users", "remna_hwid_devices", "remna_nodes",
		"bridged_flows", "online_snapshots", "ip_user_map", "hwid_user_map",
		"user_fingerprints",
	}
	for _, tbl := range wantTables {
		var ok bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, tbl).Scan(&ok)
		if err != nil || !ok {
			t.Errorf("table %q not found (err=%v)", tbl, err)
		}
	}
}
