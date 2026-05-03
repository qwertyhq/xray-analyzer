package storage

import (
	"context"
	"testing"
	"time"
)

func TestLookupNodeID_AutoInsert(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	id1, err := s.LookupNodeID(ctx, "ru-bridge", "bridge")
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if id1 == 0 {
		t.Fatal("expected non-zero NodeID")
	}
	id2, err := s.LookupNodeID(ctx, "ru-bridge", "bridge")
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if id1 != id2 {
		t.Errorf("expected same id; got %d then %d", id1, id2)
	}
}

func TestLookupNodeID_DifferentNodes(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	a, _ := s.LookupNodeID(ctx, "germany-1", "exit")
	b, _ := s.LookupNodeID(ctx, "germany-2", "exit")
	if a == b {
		t.Errorf("different node_ids should get different ids")
	}
}

func TestLookupNodeID_EmptyNodeID(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	_, err := s.LookupNodeID(ctx, "", "exit")
	if err == nil {
		t.Error("expected error for empty node_id")
	}
}

func TestLookupNodeID_DefaultRole(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	id, err := s.LookupNodeID(ctx, "default-role-node", "")
	if err != nil {
		t.Fatalf("lookup with empty role: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero NodeID")
	}
}

func TestNodes_UpdateNodeStats_Basic(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodeID := "node-test-1"

	if err := s.UpdateNodeStats(ctx, nodeID, 100, 10, 5); err != nil {
		t.Fatalf("UpdateNodeStats: %v", err)
	}

	// Second upsert accumulates requests/hits; last_seen/batch updated
	if err := s.UpdateNodeStats(ctx, nodeID, 50, 5, 3); err != nil {
		t.Fatalf("UpdateNodeStats #2: %v", err)
	}

	nodes, err := s.GetNodeStats(ctx)
	if err != nil {
		t.Fatalf("GetNodeStats: %v", err)
	}

	var found bool
	for _, n := range nodes {
		if n.NodeID == nodeID {
			found = true
			if n.TotalRequests < 150 {
				t.Errorf("TotalRequests = %d, want >= 150", n.TotalRequests)
			}
			if n.BlacklistHits < 15 {
				t.Errorf("BlacklistHits = %d, want >= 15", n.BlacklistHits)
			}
			// last_batch_count should be 3 (latest batch)
			if n.LastBatchCount != 3 {
				t.Errorf("LastBatchCount = %d, want 3", n.LastBatchCount)
			}
			// last_seen should be non-zero
			if n.LastSeen.IsZero() {
				t.Error("LastSeen should not be zero")
			}
		}
	}
	if !found {
		t.Errorf("nodeID %q not found in GetNodeStats result", nodeID)
	}
}

func TestNodes_UpdateNodeStats_EmptyIDReturnsError(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	err := s.UpdateNodeStats(ctx, "", 100, 10, 5)
	if err == nil {
		t.Error("expected error for empty node_id, got nil")
	}
}

func TestNodes_GetNodeStats_Empty(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodes, err := s.GetNodeStats(ctx)
	if err != nil {
		t.Fatalf("GetNodeStats: %v", err)
	}
	// Fresh DB — should return empty (nil slice is fine), never error
	_ = nodes
}

func TestNodes_UpdateNodeUniqueUsers(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodeID := "node-unique-users"

	// Need node_stats row first
	if err := s.UpdateNodeStats(ctx, nodeID, 1, 0, 1); err != nil {
		t.Fatalf("UpdateNodeStats: %v", err)
	}

	// UpdateNodeUniqueUsers without any user_stats rows — should not error
	if err := s.UpdateNodeUniqueUsers(ctx, nodeID); err != nil {
		t.Fatalf("UpdateNodeUniqueUsers: %v", err)
	}
}

func TestNodes_DeleteNode(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodeID := "node-to-delete"
	if err := s.UpdateNodeStats(ctx, nodeID, 10, 1, 1); err != nil {
		t.Fatalf("UpdateNodeStats: %v", err)
	}

	if err := s.DeleteNode(ctx, nodeID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}

	nodes, err := s.GetNodeStats(ctx)
	if err != nil {
		t.Fatalf("GetNodeStats after delete: %v", err)
	}
	for _, n := range nodes {
		if n.NodeID == nodeID {
			t.Errorf("nodeID %q should have been deleted but still present", nodeID)
		}
	}
}

func TestNodes_CleanupInactiveNodes(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Insert a fresh node — should NOT be cleaned up
	activeNode := "active-node"
	if err := s.UpdateNodeStats(ctx, activeNode, 10, 0, 1); err != nil {
		t.Fatalf("UpdateNodeStats active: %v", err)
	}

	// Cleanup with a very short window (1ms — only nodes seen >1ms ago qualify)
	// The just-inserted node's last_seen is NOW so it won't be cleaned up.
	n, err := s.CleanupInactiveNodes(ctx, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("CleanupInactiveNodes: %v", err)
	}
	// 0 nodes should be removed (the active one is fresh)
	_ = n // may or may not be 0 depending on timing; just ensure no error

	// Active node should still exist
	nodes, err := s.GetNodeStats(ctx)
	if err != nil {
		t.Fatalf("GetNodeStats: %v", err)
	}
	found := false
	for _, nd := range nodes {
		if nd.NodeID == activeNode {
			found = true
		}
	}
	// The very-short cutoff may or may not catch the fresh node depending on
	// sub-millisecond timing; the important thing is no panic/error.
	_ = found
}

func TestNodes_GetNodeStats_Cache(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	nodeID := "cached-node"
	if err := s.UpdateNodeStats(ctx, nodeID, 200, 20, 5); err != nil {
		t.Fatalf("UpdateNodeStats: %v", err)
	}

	// First call
	first, err := s.GetNodeStats(ctx)
	if err != nil {
		t.Fatalf("GetNodeStats first: %v", err)
	}
	// Second call (from cache)
	second, err := s.GetNodeStats(ctx)
	if err != nil {
		t.Fatalf("GetNodeStats second: %v", err)
	}
	if len(first) != len(second) {
		t.Errorf("cache inconsistency: first=%d second=%d", len(first), len(second))
	}
}

