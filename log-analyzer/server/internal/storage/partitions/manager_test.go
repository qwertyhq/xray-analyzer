package partitions

import (
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
