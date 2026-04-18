package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// BridgedFlow is a single correlated record: an exit-node destination
// resolved back to the real client IP seen on the corresponding bridge node.
type BridgedFlow struct {
	ID           int64     `json:"id"`
	UserEmail    string    `json:"user_email"`
	RealClientIP string    `json:"real_client_ip"`
	BridgeNodeID string    `json:"bridge_node_id"`
	ExitNodeID   string    `json:"exit_node_id"`
	Destination  string    `json:"destination"`
	Timestamp    time.Time `json:"ts"`
	CreatedAt    time.Time `json:"created_at"`
}

// BridgedFlowsFilter narrows GetBridgedFlows. Zero-values mean "no filter".
type BridgedFlowsFilter struct {
	UserEmail    string
	RealClientIP string
	Destination  string // matched as LIKE %dst% — caller controls exactness
	Since        time.Time
	Limit        int
}

// RecordBridgedFlow stores a single resolved flow.
func (s *Storage) RecordBridgedFlow(ctx context.Context, f *BridgedFlow) error {
	if f == nil {
		return fmt.Errorf("nil flow")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO bridged_flows
			(user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, f.UserEmail, f.RealClientIP, f.BridgeNodeID, f.ExitNodeID, f.Destination, f.Timestamp.UTC())
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
// Uses s.pool (native pgx) so []string is passed as a Postgres text[] array.
func (s *Storage) LookupBridgeCandidates(ctx context.Context, at time.Time, window time.Duration, bridgeNodeIDs []string) ([]BridgeCandidate, error) {
	if len(bridgeNodeIDs) == 0 {
		return nil, nil
	}
	if window <= 0 {
		window = 15 * time.Second
	}

	lo := at.Add(-window).UTC()
	hi := at.Add(window).UTC()

	rows, err := s.pool.Query(ctx, `
		SELECT user_email, ip_address, node_id, last_seen
		FROM user_ip_history
		WHERE node_id = ANY($1)
		  AND last_seen BETWEEN $2 AND $3
		ORDER BY last_seen DESC
		LIMIT 200
	`, bridgeNodeIDs, lo, hi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgeCandidate
	for rows.Next() {
		var c BridgeCandidate
		if err := rows.Scan(&c.UserEmail, &c.IPAddress, &c.BridgeNodeID, &c.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LookupRealClientIP (legacy 1:1 by user_email) — kept for direct-inbound
// flows where the same email travels through end-to-end. For bridge flows
// use LookupBridgeCandidates instead.
//
// Uses s.pool (native pgx) so []string is passed as a Postgres text[] array.
func (s *Storage) LookupRealClientIP(ctx context.Context, userEmail string, at time.Time, maxAge time.Duration, bridgeNodeIDs []string) (string, string, bool) {
	if userEmail == "" || len(bridgeNodeIDs) == 0 {
		return "", "", false
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}

	since := at.Add(-maxAge).UTC()

	var ip, node string
	err := s.pool.QueryRow(ctx, `
		SELECT ip_address, node_id
		FROM user_ip_history
		WHERE user_email = $1
		  AND node_id = ANY($2)
		  AND last_seen >= $3
		ORDER BY last_seen DESC
		LIMIT 1
	`, userEmail, bridgeNodeIDs, since).Scan(&ip, &node)
	if err != nil {
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
		conds  []string
		args   []interface{}
		argIdx = 1
	)

	addArg := func(v interface{}) int {
		args = append(args, v)
		n := argIdx
		argIdx++
		return n
	}

	if f.UserEmail != "" {
		conds = append(conds, fmt.Sprintf("user_email = $%d", addArg(f.UserEmail)))
	}
	if f.RealClientIP != "" {
		conds = append(conds, fmt.Sprintf("real_client_ip = $%d", addArg(f.RealClientIP)))
	}
	if f.Destination != "" {
		conds = append(conds, fmt.Sprintf("destination LIKE $%d", addArg("%"+f.Destination+"%")))
	}
	if !f.Since.IsZero() {
		conds = append(conds, fmt.Sprintf("ts >= $%d", addArg(f.Since.UTC())))
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	limitPlaceholder := fmt.Sprintf("$%d", addArg(f.Limit))

	query := fmt.Sprintf(`
		SELECT id, user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts, created_at
		FROM bridged_flows
		%s
		ORDER BY ts DESC
		LIMIT %s
	`, where, limitPlaceholder)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgedFlow
	for rows.Next() {
		var bf BridgedFlow
		if err := rows.Scan(&bf.ID, &bf.UserEmail, &bf.RealClientIP, &bf.BridgeNodeID, &bf.ExitNodeID, &bf.Destination, &bf.Timestamp, &bf.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, bf)
	}
	return out, rows.Err()
}

// CleanupBridgedFlows removes flows older than retentionDays.
func (s *Storage) CleanupBridgedFlows(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	_, err := s.db.ExecContext(ctx, `DELETE FROM bridged_flows WHERE ts < $1`, cutoff)
	return err
}
