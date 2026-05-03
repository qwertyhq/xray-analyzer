package partitions

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	sharedPGOnce sync.Once
	sharedDSN    string
	sharedErr    error
)

func sharedPostgres(t *testing.T) string {
	t.Helper()
	sharedPGOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		pg, err := tcpg.Run(ctx, "postgres:17-alpine",
			tcpg.WithDatabase("partitions"),
			tcpg.WithUsername("partitions"),
			tcpg.WithPassword("partitions"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
		)
		if err != nil {
			sharedErr = err
			return
		}
		sharedDSN, sharedErr = pg.ConnectionString(ctx, "sslmode=disable")
	})
	if sharedErr != nil {
		t.Fatalf("shared postgres: %v", sharedErr)
	}
	return sharedDSN
}

// newTestPool returns a pgxpool with a parent bridged_flows partitioned table
// already created in a fresh schema.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := sharedPostgres(t)
	ctx := context.Background()

	schema := "tp_" + randomSuffix()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	admin.Close()

	pool, err := pgxpool.New(ctx, dsn+"&search_path="+schema)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE bridged_flows (
			id bigint GENERATED ALWAYS AS IDENTITY,
			ts timestamptz NOT NULL,
			payload text
		) PARTITION BY RANGE (ts);
		CREATE TABLE bridged_flows_default PARTITION OF bridged_flows DEFAULT;
	`); err != nil {
		t.Fatalf("create parent: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		cleanup, _ := pgxpool.New(ctx, dsn)
		if cleanup != nil {
			cleanup.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			cleanup.Close()
		}
	})
	return pool
}

func randomSuffix() string {
	const alpha = "abcdefghijklmnop"
	now := time.Now().UnixNano()
	out := make([]byte, 8)
	for i := range out {
		out[i] = alpha[(now>>(i*4))&0xf]
	}
	return string(out)
}
