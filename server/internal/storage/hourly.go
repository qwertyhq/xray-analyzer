package storage

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// UpdateHourlyStats updates hourly statistics for charts.
// nodeID is a text node name resolved to the nodes(id) smallint FK.
func (s *Storage) UpdateHourlyStats(ctx context.Context, nodeID string, requests int, blacklistHits int, uniqueUsers int) error {
	now := time.Now().UTC().Truncate(time.Hour)

	nid, err := s.LookupNodeID(ctx, nodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve node_id %q: %w", nodeID, err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO hourly_stats (node_id, hour, total_requests, blacklist_hits, unique_users)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (node_id, hour) DO UPDATE SET
			total_requests = hourly_stats.total_requests + EXCLUDED.total_requests,
			blacklist_hits = hourly_stats.blacklist_hits + EXCLUDED.blacklist_hits,
			unique_users = GREATEST(hourly_stats.unique_users, EXCLUDED.unique_users)
	`, int16(nid), now, requests, blacklistHits, uniqueUsers)
	return err
}

// GetHourlyStats gets hourly statistics for the last N hours (cached)
func (s *Storage) GetHourlyStats(ctx context.Context, hours int) ([]models.HourlyStats, error) {
	cacheKey := fmt.Sprintf("hourly_stats_%d", hours)

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.([]models.HourlyStats), nil
	}

	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Hour)

	rows, err := s.db.QueryContext(ctx, `
		SELECT hour, SUM(total_requests) AS total_requests,
			   SUM(blacklist_hits) AS blacklist_hits, SUM(unique_users) AS unique_users
		FROM hourly_stats
		WHERE hour >= $1
		GROUP BY hour
		ORDER BY hour ASC
	`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := []models.HourlyStats{}
	for rows.Next() {
		var stat models.HourlyStats
		if err := rows.Scan(&stat.Hour, &stat.TotalRequests, &stat.BlacklistHits, &stat.UniqueUsers); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.cache.Set(cacheKey, stats, CacheTTLShort)
	return stats, nil
}

// GetHourlyStatsRange gets hourly statistics for a specific time range
func (s *Storage) GetHourlyStatsRange(ctx context.Context, from, to time.Time) ([]models.HourlyStats, error) {
	if from.IsZero() {
		from = time.Now().UTC().Add(-7 * 24 * time.Hour)
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT hour, SUM(total_requests) AS total_requests,
			   SUM(blacklist_hits) AS blacklist_hits, SUM(unique_users) AS unique_users
		FROM hourly_stats
		WHERE hour >= $1 AND hour <= $2
		GROUP BY hour
		ORDER BY hour ASC
	`, from.Truncate(time.Hour), to.Truncate(time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := []models.HourlyStats{}
	for rows.Next() {
		var stat models.HourlyStats
		if err := rows.Scan(&stat.Hour, &stat.TotalRequests, &stat.BlacklistHits, &stat.UniqueUsers); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return stats, nil
}

// CleanupOldData removes data older than retentionDays
// This prevents the database from growing indefinitely
func (s *Storage) CleanupOldData(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)

	// Delete old blacklist matches
	result, err := s.db.ExecContext(ctx, `DELETE FROM blacklist_matches WHERE timestamp < $1`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup blacklist_matches: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old blacklist matches", rows)
	}

	// Delete old alerts
	result, err = s.db.ExecContext(ctx, `DELETE FROM alerts WHERE created_at < $1`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup alerts: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old alerts", rows)
	}

	// Delete old hourly stats
	result, err = s.db.ExecContext(ctx, `DELETE FROM hourly_stats WHERE hour < $1`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup hourly_stats: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old hourly stats", rows)
	}

	// Delete user stats for users not seen in retention period
	result, err = s.db.ExecContext(ctx, `DELETE FROM user_stats WHERE last_seen < $1`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup user_stats: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old user stats", rows)
	}

	// Delete old user destinations
	result, err = s.db.ExecContext(ctx, `DELETE FROM user_destinations WHERE last_seen < $1`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup user_destinations: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old user destinations", rows)
	}

	return nil
}
