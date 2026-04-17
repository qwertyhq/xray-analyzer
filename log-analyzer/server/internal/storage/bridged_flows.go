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

// LookupRealClientIP returns the most recently seen client IP for
// `userEmail` on any of `bridgeNodeIDs`, as long as it was seen no earlier
// than `at.Add(-maxAge)`. Returns (ip, bridge_node_id, true) on hit.
//
// Semantics: "last known real IP for this user on the bridge, within maxAge
// lookback". Xray writes an access-log entry per TCP accept on a bridge
// inbound — with long-lived tunnels that open once and stream for hours,
// that accept happened in the past. A ±window around `at` misses those;
// an open-ended "seen within the last N" picks them up and still evicts
// stale records from previous sessions.
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

