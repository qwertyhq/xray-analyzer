package partitions

import (
	"context"
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
