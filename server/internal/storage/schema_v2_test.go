package storage

import (
	"context"
	"testing"
)

func TestSchema_V2_HotTablesPartitioned(t *testing.T) {
	s := newTestStorage(t)
	hot := []string{"alerts", "blacklist_matches", "threat_matches", "anomalies"}
	for _, tbl := range hot {
		var kind string
		err := s.Pool().QueryRow(context.Background(),
			`SELECT relkind::text FROM pg_class WHERE relname = $1`, tbl).Scan(&kind)
		if err != nil {
			t.Fatalf("query %s: %v", tbl, err)
		}
		if kind != "p" {
			t.Errorf("%s relkind = %q want \"p\" (partitioned)", tbl, kind)
		}
	}
}

func TestSchema_V2_NodesLookup(t *testing.T) {
	s := newTestStorage(t)
	var has bool
	err := s.Pool().QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'nodes' AND relkind = 'r')`).Scan(&has)
	if err != nil || !has {
		t.Fatalf("nodes table missing: err=%v has=%v", err, has)
	}
}
