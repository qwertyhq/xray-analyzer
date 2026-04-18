package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	sharedPGDSN  string
	sharedPGErr  error
)

// sharedPostgres spins up a single Postgres container for the whole test
// binary — each test gets its own schema inside it, which is ~100× faster
// than spawning a container per test.
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

// newTestStorage returns a Storage backed by a dedicated schema inside the
// shared container. Schema is dropped on cleanup.
func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	dsn := sharedPostgres(t)
	ctx := context.Background()

	schema := "test_" + randomSuffix()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	admin.Close()

	scopedDSN := dsn + "&search_path=" + schema
	s, err := New(ctx, scopedDSN)
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

func randomSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func TestStorageNew_Postgres(t *testing.T) {
	s := newTestStorage(t)
	if s == nil {
		t.Fatal("storage is nil")
	}
	// Smoke: a trivial ping-through-pool query works.
	ctx := context.Background()
	var got int
	if err := s.DB().QueryRowContext(ctx, "SELECT 1").Scan(&got); err != nil {
		t.Fatalf("SELECT 1: %v", err)
	}
	if got != 1 {
		t.Fatalf("got %d want 1", got)
	}
}
