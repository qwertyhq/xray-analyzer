//go:build sqlite_legacy

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// BridgedFlow is a single correlated record: an exit-node destination
// resolved back to the real client IP seen on the corresponding bridge node.
type BridgedFlow struct {
	ID            int64     `json:"id"`
	UserEmail     string    `json:"user_email"`
	RealClientIP  string    `json:"real_client_ip"`
	BridgeNodeID  string    `json:"bridge_node_id"`
	ExitNodeID    string    `json:"exit_node_id"`
	Destination   string    `json:"destination"`
	Timestamp     time.Time `json:"ts"`
	CreatedAt     time.Time `json:"created_at"`
}

// BridgedFlowsFilter narrows GetBridgedFlows. Zero-values mean "no filter".
type BridgedFlowsFilter struct {
	UserEmail     string
	RealClientIP  string
	Destination   string // matched as LIKE %dst% — caller controls exactness
	Since         time.Time
	Limit         int
}

// RecordBridgedFlow stores a single resolved flow.
func (s *Storage) RecordBridgedFlow(ctx context.Context, f *BridgedFlow) error {
	if f == nil {
		return fmt.Errorf("nil flow")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO bridged_flows
			(user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts)
		VALUES (?, ?, ?, ?, ?, ?)
	`, f.UserEmail, f.RealClientIP, f.BridgeNodeID, f.ExitNodeID, f.Destination, f.Timestamp.UTC().Format(time.RFC3339))
	return err
}

// BridgeCandidate is a user who was active on a bridge node in the
// correlation window surrounding an exit-node bridged entry.
type BridgeCandidate struct {
	UserEmail    string
	IPAddress    string
	BridgeNodeID string
	LastSeen     time.Time
}

// LookupBridgeCandidates returns every (user_email, ip_address) pair seen on
// any of `bridgeNodeIDs` within ±window of `at`. The returned slice is
// ordered by freshness (newest last_seen first).
//
// Why time-based and not user-based: the bridge outbound authenticates to
// the exit node with a single shared UUID, so the exit-node access log
// collapses every real user into one synthetic email. The only remaining
// signal linking an exit-node destination to a real client is the fact
// that the exit entry and the bridge entry are near-simultaneous. With
// NTP-synchronised nodes ±window is sub-second in practice.
func (s *Storage) LookupBridgeCandidates(ctx context.Context, at time.Time, window time.Duration, bridgeNodeIDs []string) ([]BridgeCandidate, error) {
	if len(bridgeNodeIDs) == 0 {
		return nil, nil
	}
	if window <= 0 {
		window = 15 * time.Second
	}

	placeholders := make([]string, len(bridgeNodeIDs))
	args := make([]interface{}, 0, len(bridgeNodeIDs)+2)
	for i, id := range bridgeNodeIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	lo := at.Add(-window).UTC().Format(time.RFC3339)
	hi := at.Add(window).UTC().Format(time.RFC3339)
	args = append(args, lo, hi)

	query := fmt.Sprintf(`
		SELECT user_email, ip_address, node_id, last_seen
		FROM user_ip_history
		WHERE node_id IN (%s)
		  AND last_seen BETWEEN ? AND ?
		ORDER BY last_seen DESC
		LIMIT 200
	`, strings.Join(placeholders, ","))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgeCandidate
	for rows.Next() {
		var c BridgeCandidate
		var lastSeenStr string
		if err := rows.Scan(&c.UserEmail, &c.IPAddress, &c.BridgeNodeID, &lastSeenStr); err != nil {
			return nil, err
		}
		c.LastSeen = parseDateTime(lastSeenStr)
		out = append(out, c)
	}
	return out, nil
}

// LookupRealClientIP (legacy 1:1 by user_email) — kept for direct-inbound
// flows where the same email travels through end-to-end. For bridge flows
// use LookupBridgeCandidates instead.
func (s *Storage) LookupRealClientIP(ctx context.Context, userEmail string, at time.Time, maxAge time.Duration, bridgeNodeIDs []string) (string, string, bool) {
	if userEmail == "" || len(bridgeNodeIDs) == 0 {
		return "", "", false
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}

	placeholders := make([]string, len(bridgeNodeIDs))
	args := make([]interface{}, 0, len(bridgeNodeIDs)+2)
	args = append(args, userEmail)
	for i, id := range bridgeNodeIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	since := at.Add(-maxAge).UTC().Format(time.RFC3339)
	args = append(args, since)

	query := fmt.Sprintf(`
		SELECT ip_address, node_id
		FROM user_ip_history
		WHERE user_email = ?
		  AND node_id IN (%s)
		  AND last_seen >= ?
		ORDER BY last_seen DESC
		LIMIT 1
	`, strings.Join(placeholders, ","))

	var ip, node string
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&ip, &node)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false
		}
		return "", "", false
	}
	return ip, node, true
}

// GetBridgedFlows returns flows matching the filter, newest first.
func (s *Storage) GetBridgedFlows(ctx context.Context, f BridgedFlowsFilter) ([]BridgedFlow, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}

	var (
		conds []string
		args  []interface{}
	)
	if f.UserEmail != "" {
		conds = append(conds, "user_email = ?")
		args = append(args, f.UserEmail)
	}
	if f.RealClientIP != "" {
		conds = append(conds, "real_client_ip = ?")
		args = append(args, f.RealClientIP)
	}
	if f.Destination != "" {
		conds = append(conds, "destination LIKE ?")
		args = append(args, "%"+f.Destination+"%")
	}
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	query := fmt.Sprintf(`
		SELECT id, user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts, created_at
		FROM bridged_flows
		%s
		ORDER BY ts DESC
		LIMIT ?
	`, where)
	args = append(args, f.Limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgedFlow
	for rows.Next() {
		var f BridgedFlow
		var tsStr, createdStr string
		if err := rows.Scan(&f.ID, &f.UserEmail, &f.RealClientIP, &f.BridgeNodeID, &f.ExitNodeID, &f.Destination, &tsStr, &createdStr); err != nil {
			return nil, err
		}
		f.Timestamp = parseDateTime(tsStr)
		f.CreatedAt = parseDateTime(createdStr)
		out = append(out, f)
	}
	return out, nil
}

// CleanupBridgedFlows removes flows older than retentionDays.
func (s *Storage) CleanupBridgedFlows(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `DELETE FROM bridged_flows WHERE ts < ?`, cutoff)
	return err
}

