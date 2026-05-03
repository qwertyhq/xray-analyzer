package storage

import (
	"context"
	"time"
)

// OnlineHistoryPoint is one bucket of the history series returned to the UI.
type OnlineHistoryPoint struct {
	Hour        time.Time `json:"hour"`
	OnlineUsers int       `json:"online_users"`
}

// RecordOnlineSnapshot writes (or overwrites) a single minute-bucket sample.
// Postgres TIMESTAMPTZ accepts time.Time natively via pgx — no string
// formatting required.
func (s *Storage) RecordOnlineSnapshot(ctx context.Context, ts time.Time, total int) error {
	bucketed := ts.UTC().Truncate(time.Minute)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO online_snapshots (ts, total_online)
		VALUES ($1, $2)
		ON CONFLICT (ts) DO UPDATE SET total_online = EXCLUDED.total_online
	`, bucketed, total)
	return err
}

// TotalRemnaOnline sums users_online across the Remnawave nodes mapped
// from agent NODE_IDs. Zero when no mapping is configured.
// Uses the native pgx pool so []string is encoded as a Postgres text[] array.
func (s *Storage) TotalRemnaOnline(ctx context.Context) (int, error) {
	if len(s.nodeRemnaMap) == 0 {
		return 0, nil
	}
	names := make([]string, 0, len(s.nodeRemnaMap))
	for _, v := range s.nodeRemnaMap {
		names = append(names, v)
	}
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(users_online), 0) FROM remna_nodes WHERE name = ANY($1)`,
		names,
	).Scan(&n); err != nil {
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
	cutoff := time.Now().UTC().Add(-since)

	rows, err := s.db.QueryContext(ctx, `
		SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:00:00"Z"') AS hour,
		       MAX(total_online) AS peak
		FROM online_snapshots
		WHERE ts >= $1
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
	_, err := s.db.ExecContext(ctx, `DELETE FROM online_snapshots WHERE ts < $1`, cutoff)
	return err
}
