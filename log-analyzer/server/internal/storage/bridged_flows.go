package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BridgedFlow is a single correlated record: an exit-node destination
// resolved back to the real client IP seen on the corresponding bridge node.
type BridgedFlow struct {
	ID           int64     `json:"id"`
	UserEmail    string    `json:"user_email"`     // UUID string (Remnawave user UUID)
	UserDisplay  string    `json:"user_display"`   // Human-readable name: remna username, original email, or UUID fallback
	RealClientIP string    `json:"real_client_ip"` // IP address string
	BridgeNodeID string    `json:"bridge_node_id"` // text node_id (resolved to smallint FK internally)
	ExitNodeID   string    `json:"exit_node_id"`   // text node_id (resolved to smallint FK internally)
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
// BridgeNodeID and ExitNodeID are text node names; they are resolved to
// the nodes(id) smallint FK via LookupNodeID before insert.
func (s *Storage) RecordBridgedFlow(ctx context.Context, f *BridgedFlow) error {
	if f == nil {
		return fmt.Errorf("nil flow")
	}

	// Resolve text node IDs to smallint FKs.
	bridgeID, err := s.LookupNodeID(ctx, f.BridgeNodeID, "bridge")
	if err != nil {
		return fmt.Errorf("resolve bridge_node_id: %w", err)
	}
	exitID, err := s.LookupNodeID(ctx, f.ExitNodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve exit_node_id: %w", err)
	}

	// user_email is uuid in the DB. Resolve via remna_users first; fall back
	// to SHA-1 for synthetic identifiers (e.g. "5117", "u-out") from exit-node logs.
	var userUUID uuid.UUID
	if f.UserEmail != "" {
		userUUID, err = s.ResolveUserEmailToUUID(ctx, f.UserEmail)
		if err != nil {
			return fmt.Errorf("resolve user_email: %w", err)
		}
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO bridged_flows
			(user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts)
		VALUES ($1, $2::inet, $3, $4, $5, $6)
	`, userUUID, f.RealClientIP, int16(bridgeID), int16(exitID), f.Destination, f.Timestamp.UTC())
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
// user_ip_history.node_id is smallint FK so we resolve text → id first.
func (s *Storage) LookupBridgeCandidates(ctx context.Context, at time.Time, window time.Duration, bridgeNodeIDs []string) ([]BridgeCandidate, error) {
	if len(bridgeNodeIDs) == 0 {
		return nil, nil
	}
	if window <= 0 {
		window = 15 * time.Second
	}

	// Resolve text node names to smallint IDs.
	nodeIntIDs := make([]int16, 0, len(bridgeNodeIDs))
	nodeIDToText := make(map[int16]string, len(bridgeNodeIDs))
	for _, n := range bridgeNodeIDs {
		nid, err := s.LookupNodeID(ctx, n, "bridge")
		if err != nil {
			continue
		}
		nodeIntIDs = append(nodeIntIDs, int16(nid))
		nodeIDToText[int16(nid)] = n
	}
	if len(nodeIntIDs) == 0 {
		return nil, nil
	}

	lo := at.Add(-window).UTC()
	hi := at.Add(window).UTC()

	rows, err := s.pool.Query(ctx, `
		SELECT user_email, host(ip_address), node_id, last_seen
		FROM user_ip_history
		WHERE node_id = ANY($1)
		  AND last_seen BETWEEN $2 AND $3
		ORDER BY last_seen DESC
		LIMIT 200
	`, nodeIntIDs, lo, hi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgeCandidate
	for rows.Next() {
		var c BridgeCandidate
		var userUUID uuid.UUID
		var ipStr string
		var nodeIntID int16
		if err := rows.Scan(&userUUID, &ipStr, &nodeIntID, &c.LastSeen); err != nil {
			return nil, err
		}
		c.UserEmail = userUUID.String()
		c.IPAddress = ipStr
		if txt, ok := nodeIDToText[nodeIntID]; ok {
			c.BridgeNodeID = txt
		} else {
			c.BridgeNodeID = fmt.Sprintf("%d", nodeIntID)
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

	// Resolve text node names to smallint IDs.
	nodeIntIDs := make([]int16, 0, len(bridgeNodeIDs))
	nodeIDToText := make(map[int16]string, len(bridgeNodeIDs))
	for _, n := range bridgeNodeIDs {
		nid, err := s.LookupNodeID(ctx, n, "bridge")
		if err != nil {
			continue
		}
		nodeIntIDs = append(nodeIntIDs, int16(nid))
		nodeIDToText[int16(nid)] = n
	}
	if len(nodeIntIDs) == 0 {
		return "", "", false
	}

	userUUID, err := uuid.Parse(userEmail)
	if err != nil {
		return "", "", false
	}

	since := at.Add(-maxAge).UTC()

	var ipStr string
	var nodeIntID int16
	err = s.pool.QueryRow(ctx, `
		SELECT host(ip_address), node_id
		FROM user_ip_history
		WHERE user_email = $1
		  AND node_id = ANY($2)
		  AND last_seen >= $3
		ORDER BY last_seen DESC
		LIMIT 1
	`, userUUID, nodeIntIDs, since).Scan(&ipStr, &nodeIntID)
	if err != nil {
		return "", "", false
	}
	nodeName := nodeIDToText[nodeIntID]
	if nodeName == "" {
		nodeName = fmt.Sprintf("%d", nodeIntID)
	}
	return ipStr, nodeName, true
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
		// user_email is uuid in DB; attempt to parse.
		if uid, err := uuid.Parse(f.UserEmail); err == nil {
			conds = append(conds, fmt.Sprintf("user_email = $%d", addArg(uid)))
		}
	}
	if f.RealClientIP != "" {
		conds = append(conds, fmt.Sprintf("real_client_ip = $%d::inet", addArg(f.RealClientIP)))
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

	// Join with nodes for text names; join remna_users + email_index for user_display.
	query := fmt.Sprintf(`
		SELECT bf.id, bf.user_email, host(bf.real_client_ip),
		       bn.node_id AS bridge_node_id,
		       en.node_id AS exit_node_id,
		       bf.destination, bf.ts, bf.created_at,
		       COALESCE(ru.username, ei.original_email, bf.user_email::text) AS user_display
		FROM bridged_flows bf
		JOIN nodes bn ON bn.id = bf.bridge_node_id
		JOIN nodes en ON en.id = bf.exit_node_id
		LEFT JOIN remna_users ru ON ru.uuid = bf.user_email
		LEFT JOIN email_index ei ON ei.uuid = bf.user_email
		%s
		ORDER BY bf.ts DESC
		LIMIT %s
	`, where, limitPlaceholder)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgedFlow
	for rows.Next() {
		var bf BridgedFlow
		var userUUID uuid.UUID
		var ipStr string
		if err := rows.Scan(&bf.ID, &userUUID, &ipStr, &bf.BridgeNodeID, &bf.ExitNodeID, &bf.Destination, &bf.Timestamp, &bf.CreatedAt, &bf.UserDisplay); err != nil {
			return nil, err
		}
		bf.UserEmail = userUUID.String()
		bf.RealClientIP = ipStr
		out = append(out, bf)
	}
	return out, rows.Err()
}

// CleanupBridgedFlows removes flows older than retentionDays.
func (s *Storage) CleanupBridgedFlows(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	_, err := s.pool.Exec(ctx, `DELETE FROM bridged_flows WHERE ts < $1`, cutoff)
	return err
}
