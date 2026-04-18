//go:build sqlite_legacy

package storage

import (
	"context"
	"time"
)

// OnlineHistoryPoint is one bucket of the history series returned to the UI.
type OnlineHistoryPoint struct {
	Hour         time.Time `json:"hour"`
	OnlineUsers  int       `json:"online_users"`
}

// RecordOnlineSnapshot writes (or overwrites) a single minute-bucket sample.
// ts is stored as a strftime-compatible ISO-8601 string so GetOnlineHistoryHourly
// can bucket via strftime. modernc.org/sqlite binds time.Time to a Go
// representation ("2026-04-17 19:11:00 +0000 UTC") that strftime can't parse.
func (s *Storage) RecordOnlineSnapshot(ctx context.Context, ts time.Time, total int) error {
	bucketed := ts.UTC().Truncate(time.Minute).Format("2006-01-02T15:04:05Z")
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO online_snapshots (ts, total_online)
		VALUES (?, ?)
		ON CONFLICT(ts) DO UPDATE SET total_online = excluded.total_online
	`, bucketed, total)
	return err
}

// TotalRemnaOnline sums users_online across the Remnawave nodes mapped
// from agent NODE_IDs. Zero when no mapping is configured.
func (s *Storage) TotalRemnaOnline(ctx context.Context) (int, error) {
	if len(s.nodeRemnaMap) == 0 {
		return 0, nil
	}
	q := `SELECT COALESCE(SUM(users_online), 0) FROM remna_nodes WHERE name IN (` +
		placeholderList(len(s.nodeRemnaMap)) + `)`
	var n int
	if err := s.db.QueryRowContext(ctx, q, remnaNamesAsArgs(s.nodeRemnaMap)...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetOnlineHistoryHourly returns hourly peak online_users over the last
// `since` duration. Peak (MAX) rather than average so a blip-free trend
// line is easier to read: "there were 650 people online that hour".
func (s *Storage) GetOnlineHistoryHourly(ctx context.Context, since time.Duration) ([]OnlineHistoryPoint, error) {
	if since <= 0 {
		since = 24 * time.Hour
	}
	cutoff := time.Now().UTC().Add(-since).Format("2006-01-02T15:04:05Z")

	// Hour bucket via strftime; literal format (bind-as-param breaks under
	// modernc.org/sqlite). MAX picks the peak minute within the hour.
	rows, err := s.db.QueryContext(ctx, `
		SELECT strftime('%Y-%m-%dT%H:00:00Z', ts) AS hour,
		       MAX(total_online) AS peak
		FROM online_snapshots
		WHERE ts >= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OnlineHistoryPoint
	for rows.Next() {
		var hour string
		var peak int
		if err := rows.Scan(&hour, &peak); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, hour)
		if err != nil {
			continue
		}
		out = append(out, OnlineHistoryPoint{Hour: t, OnlineUsers: peak})
	}
	return out, nil
}

// CleanupOnlineSnapshots trims anything older than retentionDays. The 1/min
// cadence × 30d fits in a few MB, so this is mostly hygiene.
func (s *Storage) CleanupOnlineSnapshots(ctx context.Context, retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	_, err := s.db.ExecContext(ctx, `DELETE FROM online_snapshots WHERE ts < ?`, cutoff)
	return err
}
