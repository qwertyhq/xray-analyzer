//go:build sqlite_legacy

package storage

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// UpdateHourlyStats updates hourly statistics for charts
func (s *Storage) UpdateHourlyStats(ctx context.Context, nodeID string, requests int, blacklistHits int, uniqueUsers int) error {
	now := time.Now().UTC().Truncate(time.Hour).Format(time.RFC3339)

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hourly_stats (node_id, hour, total_requests, blacklist_hits, unique_users)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(node_id, hour) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blacklist_hits = blacklist_hits + excluded.blacklist_hits,
			unique_users = MAX(unique_users, excluded.unique_users)
	`, nodeID, now, requests, blacklistHits, uniqueUsers)
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
		SELECT COALESCE(hour, '') as hour, SUM(total_requests) as total_requests, 
			   SUM(blacklist_hits) as blacklist_hits, SUM(unique_users) as unique_users
		FROM hourly_stats
		WHERE hour >= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := []models.HourlyStats{}
	for rows.Next() {
		var s models.HourlyStats
		var hourStr string
		if err := rows.Scan(&hourStr, &s.TotalRequests, &s.BlacklistHits, &s.UniqueUsers); err != nil {
			return nil, err
		}
		s.Hour = parseDateTime(hourStr)
		stats = append(stats, s)
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
		SELECT COALESCE(hour, '') as hour, SUM(total_requests) as total_requests, 
			   SUM(blacklist_hits) as blacklist_hits, SUM(unique_users) as unique_users
		FROM hourly_stats
		WHERE hour >= ? AND hour <= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, from.Truncate(time.Hour), to.Truncate(time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := []models.HourlyStats{}
	for rows.Next() {
		var s models.HourlyStats
		var hourStr string
		if err := rows.Scan(&hourStr, &s.TotalRequests, &s.BlacklistHits, &s.UniqueUsers); err != nil {
			return nil, err
		}
		s.Hour = parseDateTime(hourStr)
		stats = append(stats, s)
	}
	return stats, nil
}

// CleanupOldData removes data older than retentionDays
// This prevents the database from growing indefinitely
func (s *Storage) CleanupOldData(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)

	// Delete old blacklist matches
	result, err := s.db.ExecContext(ctx, `DELETE FROM blacklist_matches WHERE timestamp < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup blacklist_matches: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old blacklist matches", rows)
	}

	// Delete old alerts
	result, err = s.db.ExecContext(ctx, `DELETE FROM alerts WHERE created_at < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup alerts: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old alerts", rows)
	}

	// Delete old hourly stats
	result, err = s.db.ExecContext(ctx, `DELETE FROM hourly_stats WHERE hour < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup hourly_stats: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old hourly stats", rows)
	}

	// Delete user stats for users not seen in retention period
	result, err = s.db.ExecContext(ctx, `DELETE FROM user_stats WHERE last_seen < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup user_stats: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old user stats", rows)
	}

	// Delete old user destinations
	result, err = s.db.ExecContext(ctx, `DELETE FROM user_destinations WHERE last_seen < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("cleanup user_destinations: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("storage: cleaned up %d old user destinations", rows)
	}

	// Checkpoint WAL to reclaim space
	s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")

	return nil
}
