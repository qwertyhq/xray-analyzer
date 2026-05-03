package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// LookupNodeID resolves a text node_id (e.g. "ru-bridge") to its smallint
// primary key in the nodes table, inserting a new row if it does not yet exist.
// The returned NodeID is always non-zero on success.
//
// Memoized via Storage.nodeIDCache: a hit avoids hitting the database
// entirely. Cache misses do a plain SELECT first; only genuinely new nodes
// take the INSERT path. Avoiding ON CONFLICT keeps the smallint identity
// sequence from burning under high call rates (one batch from agents
// triggers many LookupNodeID calls).
func (s *Storage) LookupNodeID(ctx context.Context, nodeID, role string) (NodeID, error) {
	if nodeID == "" {
		return 0, fmt.Errorf("empty node_id")
	}
	if role == "" {
		role = "exit"
	}

	// Cache lookup.
	s.nodeIDCacheMu.RLock()
	if id, ok := s.nodeIDCache[nodeID]; ok {
		s.nodeIDCacheMu.RUnlock()
		return id, nil
	}
	s.nodeIDCacheMu.RUnlock()

	// Cache miss — SELECT to check whether the row already exists.
	var id int16
	err := s.pool.QueryRow(ctx, `SELECT id FROM nodes WHERE node_id = $1`, nodeID).Scan(&id)
	if err == nil {
		s.cacheNodeID(nodeID, NodeID(id))
		return NodeID(id), nil
	}
	// Unexpected SELECT errors (other than no rows) bubble up as lookup
	// failures. pgx returns ErrNoRows for missing rows.
	if err.Error() != "no rows in result set" {
		// Continue to INSERT — likely just a fresh node. If INSERT
		// itself fails we'll surface that error.
	}

	// Genuinely new node — INSERT once. Don't UPDATE on conflict (avoids
	// burning the identity sequence under repeated calls with the same
	// node_id during a race).
	err = s.pool.QueryRow(ctx, `
		INSERT INTO nodes (node_id, role)
		VALUES ($1, $2)
		ON CONFLICT (node_id) DO NOTHING
		RETURNING id
	`, nodeID, role).Scan(&id)
	if err != nil {
		// Conflict path: the row was inserted by a concurrent caller
		// between our SELECT and INSERT. Re-SELECT to fetch it.
		if err.Error() == "no rows in result set" {
			if serr := s.pool.QueryRow(ctx, `SELECT id FROM nodes WHERE node_id = $1`, nodeID).Scan(&id); serr == nil {
				s.cacheNodeID(nodeID, NodeID(id))
				return NodeID(id), nil
			} else {
				return 0, fmt.Errorf("lookup node %s after conflict: %w", nodeID, serr)
			}
		}
		return 0, fmt.Errorf("lookup node %s: %w", nodeID, err)
	}
	s.cacheNodeID(nodeID, NodeID(id))
	return NodeID(id), nil
}

func (s *Storage) cacheNodeID(nodeID string, id NodeID) {
	s.nodeIDCacheMu.Lock()
	s.nodeIDCache[nodeID] = id
	s.nodeIDCacheMu.Unlock()
}

// UpdateNodeStats updates statistics for a node
func (s *Storage) UpdateNodeStats(ctx context.Context, nodeID string, requests int, blacklistHits int, batchCount int) error {
	if nodeID == "" {
		return fmt.Errorf("empty node_id")
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO node_stats (node_id, total_requests, blacklist_hits, last_seen, last_batch_time, last_batch_count)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (node_id) DO UPDATE SET
			total_requests = node_stats.total_requests + EXCLUDED.total_requests,
			blacklist_hits = node_stats.blacklist_hits + EXCLUDED.blacklist_hits,
			last_seen = EXCLUDED.last_seen,
			last_batch_time = EXCLUDED.last_batch_time,
			last_batch_count = EXCLUDED.last_batch_count
	`, nodeID, requests, blacklistHits, now, now, batchCount)
	return err
}

// UpdateNodeUniqueUsers updates unique users count for a node
func (s *Storage) UpdateNodeUniqueUsers(ctx context.Context, nodeID string) error {
	// user_stats.node_id is smallint FK; resolve text → id first.
	nid, err := s.LookupNodeID(ctx, nodeID, "exit")
	if err != nil {
		return nil // node not registered yet — nothing to update
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE node_stats
		SET unique_users = (SELECT COUNT(DISTINCT user_email) FROM user_stats WHERE node_id = $1)
		WHERE node_id = $2
	`, int16(nid), nodeID)
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
	windowAgo := time.Now().UTC().Add(-5 * time.Minute)

	// user_stats.node_id is a smallint FK into nodes(id), while node_stats.node_id is text.
	// Bridge through the nodes table so the types are compatible.
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			ns.node_id,
			ns.total_requests,
			ns.blacklist_hits,
			ns.unique_users,
			COALESCE(online.cnt, 0) AS online_users,
			ns.last_seen,
			ns.last_batch_time,
			ns.last_batch_count
		FROM node_stats ns
		LEFT JOIN (
			SELECT nd.node_id AS node_text_id, COUNT(DISTINCT us.user_email) AS cnt
			FROM user_stats us
			JOIN nodes nd ON nd.id = us.node_id
			WHERE us.last_seen > $1
			GROUP BY nd.node_id
		) online ON online.node_text_id = ns.node_id
		ORDER BY ns.total_requests DESC
	`, windowAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.NodeStats
	for rows.Next() {
		n := &models.NodeStats{}
		var lastSeen, lastBatch *time.Time
		err := rows.Scan(&n.NodeID, &n.TotalRequests, &n.BlacklistHits, &n.UniqueUsers, &n.OnlineUsers, &lastSeen, &lastBatch, &n.LastBatchCount)
		if err != nil {
			return nil, err
		}
		if lastSeen != nil {
			n.LastSeen = *lastSeen
		}
		if lastBatch != nil {
			n.LastBatchTime = *lastBatch
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
	// Resolve text node_id to the smallint FK used in child tables.
	// If the node doesn't exist in nodes table yet, nothing to cascade.
	var nid int16
	_ = s.pool.QueryRow(ctx, `SELECT id FROM nodes WHERE node_id = $1`, nodeID).Scan(&nid)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	// Tables that reference nodes(id) as smallint FK — use resolved id.
	if nid > 0 {
		if _, err := tx.ExecContext(ctx, "DELETE FROM user_stats WHERE node_id = $1", nid); err != nil {
			tx.Rollback()
			return fmt.Errorf("delete user_stats: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM blacklist_matches WHERE node_id = $1", nid); err != nil {
			tx.Rollback()
			return fmt.Errorf("delete blacklist_matches: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM alerts WHERE node_id = $1", nid); err != nil {
			tx.Rollback()
			return fmt.Errorf("delete alerts: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM hourly_stats WHERE node_id = $1", nid); err != nil {
			tx.Rollback()
			return fmt.Errorf("delete hourly_stats: %w", err)
		}
	}

	// node_stats uses text node_id as PK.
	if _, err := tx.ExecContext(ctx, "DELETE FROM node_stats WHERE node_id = $1", nodeID); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete node_stats: %w", err)
	}

	return tx.Commit()
}

// CleanupInactiveNodes removes nodes that haven't been seen for a while
func (s *Storage) CleanupInactiveNodes(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)

	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id FROM node_stats WHERE last_seen < $1
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
