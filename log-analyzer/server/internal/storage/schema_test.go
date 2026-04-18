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
		"ai_chat_messages",
		"ai_chat_sessions",
		"alerts",
		"anomalies",
		"blacklist_matches",
		"bridged_flows",
		"dns_daily_stats",
		"dns_domain_stats",
		"dns_hourly_stats",
		"hourly_stats",
		"hwid_user_map",
		"ip_user_map",
		"node_stats",
		"online_snapshots",
		"remna_hwid_devices",
		"remna_nodes",
		"remna_users",
		"reports",
		"threat_daily_stats",
		"threat_daily_users",
		"threat_geo_stats",
		"threat_hourly_stats",
		"threat_hourly_users",
		"threat_matches",
		"threat_stats_agg",
		"threat_type_stats",
		"user_activity_baseline",
		"user_ai_profile",
		"user_clusters",
		"user_destinations",
		"user_dns_stats",
		"user_fingerprints",
		"user_ip_history",
		"user_locations",
		"user_risk_profiles",
		"user_sessions",
		"user_stats",
		"user_threat_domains",
		"user_threat_stats",
	}
	for _, tbl := range wantTables {
		var ok bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, tbl).Scan(&ok)
		if err != nil || !ok {
			t.Errorf("table %q not found (err=%v)", tbl, err)
		}
	}
}
