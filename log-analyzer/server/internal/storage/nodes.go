package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// UpdateNodeStats updates statistics for a node
func (s *Storage) UpdateNodeStats(ctx context.Context, nodeID string, requests int, blacklistHits int, batchCount int) error {
	if nodeID == "" {
		return fmt.Errorf("empty node_id")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO node_stats (node_id, total_requests, blacklist_hits, last_seen, last_batch_time, last_batch_count)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blacklist_hits = blacklist_hits + excluded.blacklist_hits,
			last_seen = excluded.last_seen,
			last_batch_time = excluded.last_batch_time,
			last_batch_count = excluded.last_batch_count
	`, nodeID, requests, blacklistHits, now, now, batchCount)
	return err
}

// UpdateNodeUniqueUsers updates unique users count for a node
func (s *Storage) UpdateNodeUniqueUsers(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE node_stats 
		SET unique_users = (SELECT COUNT(DISTINCT user_email) FROM user_stats WHERE node_id = ?)
		WHERE node_id = ?
	`, nodeID, nodeID)
	return err
}

// GetNodeStats gets statistics for all nodes (cached)
func (s *Storage) GetNodeStats(ctx context.Context) ([]*models.NodeStats, error) {
	cacheKey := "node_stats"

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]*models.NodeStats), nil
	}

	// 5-minute window instead of 1. Agents occasionally lose their
	// WebSocket for 30-60s (NetBird/Caddy idle drops, DNS hiccups) and
	// during those gaps user_stats.last_seen isn't updated — a 1-minute
	// window would report 0 online users on a still-very-active node.
	// 5 min is a better "who is still active" proxy; real UI latency is
	// dominated by the 10s cache TTL, not this window.
	windowAgo := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)

	// Use LEFT JOIN instead of correlated subquery to avoid N+1 problem
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			n.node_id,
			n.total_requests,
			n.blacklist_hits,
			n.unique_users,
			COALESCE(online.cnt, 0) as online_users,
			COALESCE(n.last_seen, '') as last_seen,
			COALESCE(n.last_batch_time, '') as last_batch_time,
			n.last_batch_count
		FROM node_stats n
		LEFT JOIN (
			SELECT node_id, COUNT(DISTINCT user_email) as cnt
			FROM user_stats
			WHERE last_seen > ?
			GROUP BY node_id
		) online ON online.node_id = n.node_id
		ORDER BY n.total_requests DESC
	`, windowAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.NodeStats
	for rows.Next() {
		n := &models.NodeStats{}
		var lastSeenStr, lastBatchStr string
		err := rows.Scan(&n.NodeID, &n.TotalRequests, &n.BlacklistHits, &n.UniqueUsers, &n.OnlineUsers, &lastSeenStr, &lastBatchStr, &n.LastBatchCount)
		if err != nil {
			return nil, err
		}
		n.LastSeen = parseDateTime(lastSeenStr)
		n.LastBatchTime = parseDateTime(lastBatchStr)
		nodes = append(nodes, n)
	}

	s.cache.Set(cacheKey, nodes, CacheTTLShort)
	return nodes, nil
}

// DeleteNode removes a node and all its related data
func (s *Storage) DeleteNode(ctx context.Context, nodeID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	// Delete from all related tables
	if _, err := tx.ExecContext(ctx, "DELETE FROM user_stats WHERE node_id = ?", nodeID); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete user_stats: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM blacklist_matches WHERE node_id = ?", nodeID); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete blacklist_matches: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM alerts WHERE node_id = ?", nodeID); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete alerts: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM hourly_stats WHERE node_id = ?", nodeID); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete hourly_stats: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM node_stats WHERE node_id = ?", nodeID); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete node_stats: %w", err)
	}

	return tx.Commit()
}

// CleanupInactiveNodes removes nodes that haven't been seen for a while
func (s *Storage) CleanupInactiveNodes(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)

	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id FROM node_stats WHERE last_seen < ?
	`, cutoff)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var nodeIDs []string
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return 0, err
		}
		nodeIDs = append(nodeIDs, nodeID)
	}

	for _, nodeID := range nodeIDs {
		s.DeleteNode(ctx, nodeID)
	}

	return len(nodeIDs), nil
}
