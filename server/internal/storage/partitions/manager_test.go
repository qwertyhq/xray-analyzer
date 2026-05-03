package partitions

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewManager(t *testing.T) {
	var pool *pgxpool.Pool
	tables := []Table{{Name: "bridged_flows", RetentionDays: 14}}
	m := NewManager(pool, tables)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestTable_PartitionName(t *testing.T) {
	tbl := Table{Name: "bridged_flows"}
	day := mustDate("2026-05-01")
	if got := tbl.PartitionName(day); got != "bridged_flows_20260501" {
		t.Fatalf("PartitionName = %q want bridged_flows_20260501", got)
	}
}

func mustDate(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestEnsureFuturePartitions_CreatesTodayAndTwoDays(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("EnsureFuturePartitions: %v", err)
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	for i := 0; i <= 2; i++ {
		day := today.AddDate(0, 0, i)
		name := "bridged_flows_" + day.Format("20060102")
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, name).Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", name, err)
		}
		if !exists {
			t.Errorf("partition %s should exist", name)
		}
	}
}

func TestEnsureFuturePartitions_Idempotent(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("second: %v", err)
	}
}

func TestTick_FullCycle(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()

	old := time.Now().UTC().Truncate(24 * time.Hour).AddDate(0, 0, -20)
	next := old.AddDate(0, 0, 1)
	oldName := "bridged_flows_" + old.Format("20060102")
	_, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE %s PARTITION OF bridged_flows
		FOR VALUES FROM ('%s') TO ('%s')
	`, oldName, old.Format(time.RFC3339), next.Format(time.RFC3339)))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := m.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	var exists bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, oldName).Scan(&exists)
	if exists {
		t.Errorf("old partition %s should have been dropped", oldName)
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	todayName := "bridged_flows_" + today.Format("20060102")
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, todayName).Scan(&exists)
	if !exists {
		t.Errorf("today partition %s should exist", todayName)
	}
}

func TestHealthy_PassWhenPartitionsExist(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := m.Healthy(ctx); err != nil {
		t.Errorf("Healthy() = %v want nil", err)
	}
}

func TestHealthy_FailWhenMissing(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()
	// Don't call EnsureFuturePartitions — today's partition is absent.
	if err := m.Healthy(ctx); err == nil {
		t.Errorf("Healthy() should error when partitions missing")
	}
}

func TestHealthy_FailWhenDefaultPartitionNonEmpty(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()

	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	// Insert a row with a far-future timestamp so it lands in bridged_flows_default
	// (no named partition covers 2099).
	if _, err := pool.Exec(ctx,
		`INSERT INTO bridged_flows (ts, payload) VALUES ($1, 'test')`,
		"2099-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("seed default partition: %v", err)
	}

	if err := m.Healthy(ctx); err == nil {
		t.Errorf("Healthy() should fail when default partition is non-empty")
	}
}

func TestDropExpiredPartitions_DropsOldKeepsRecent(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()

	today := time.Now().UTC().Truncate(24 * time.Hour)
	old := today.AddDate(0, 0, -20)
	recent := today.AddDate(0, 0, -5)
	for _, day := range []time.Time{old, recent} {
		name := "bridged_flows_" + day.Format("20060102")
		next := day.AddDate(0, 0, 1)
		_, err := pool.Exec(ctx, fmt.Sprintf(`
			CREATE TABLE %s PARTITION OF bridged_flows
			FOR VALUES FROM ('%s') TO ('%s')
		`, name, day.Format(time.RFC3339), next.Format(time.RFC3339)))
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	if err := m.DropExpiredPartitions(ctx); err != nil {
		t.Fatalf("DropExpiredPartitions: %v", err)
	}

	oldName := "bridged_flows_" + old.Format("20060102")
	recentName := "bridged_flows_" + recent.Format("20060102")
	for _, c := range []struct {
		name      string
		wantExist bool
	}{
		{oldName, false},
		{recentName, true},
	} {
		var exists bool
		_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, c.name).Scan(&exists)
		if exists != c.wantExist {
			t.Errorf("%s exists=%v want %v", c.name, exists, c.wantExist)
		}
	}
}
