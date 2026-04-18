//go:build sqlite_legacy

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

	// Access-log fallback window: 5 min tolerates WS flaps (30-60s) and
	// is used when the node has no Remnawave mapping or Remnawave isn't
	// synced yet.
	windowAgo := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)

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

	// Enrich with Remnawave's XTLS-level online count. Prefer it over the
	// access-log heuristic: Xray reports real active sessions, the log
	// approach undercounts whenever an agent's WebSocket flaps.
	if len(s.nodeRemnaMap) > 0 {
		remna, err := s.remnaOnlineCounts(ctx)
		if err == nil {
			for _, n := range nodes {
				if name, ok := s.nodeRemnaMap[n.NodeID]; ok {
					if cnt, ok := remna[name]; ok {
						n.OnlineUsers = cnt
					}
				}
			}
		}
	}

	s.cache.Set(cacheKey, nodes, CacheTTLShort)
	return nodes, nil
}

// remnaOnlineCounts returns a map of remnawave-node-name → users_online
// from the synced remna_nodes table. Fast, indexed, read-only.
func (s *Storage) remnaOnlineCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, users_online FROM remna_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var name string
		var cnt int
		if err := rows.Scan(&name, &cnt); err == nil {
			out[name] = cnt
		}
	}
	return out, nil
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
