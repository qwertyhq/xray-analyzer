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
