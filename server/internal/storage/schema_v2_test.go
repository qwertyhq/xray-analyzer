package storage

import (
	"context"
	"testing"
)

func TestSchema_V2_HotTablesPartitioned(t *testing.T) {
	s := newTestStorage(t)
	hot := []string{"bridged_flows", "alerts", "blacklist_matches", "threat_matches", "anomalies"}
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

func TestSchema_V2_BridgedFlowsHasUUIDColumn(t *testing.T) {
	s := newTestStorage(t)
	var typ string
	err := s.Pool().QueryRow(context.Background(),
		`SELECT data_type FROM information_schema.columns
		 WHERE table_name = 'bridged_flows' AND column_name = 'user_email'`).Scan(&typ)
	if err != nil {
		t.Fatalf("query column type: %v", err)
	}
	if typ != "uuid" {
		t.Errorf("user_email type = %q want uuid", typ)
	}
}
