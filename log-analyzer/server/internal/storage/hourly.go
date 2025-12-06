package storage

import (
	"context"
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

// GetHourlyStats gets hourly statistics for the last N hours
func (s *Storage) GetHourlyStats(ctx context.Context, hours int) ([]models.HourlyStats, error) {
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

// CleanupOldData removes old data
func (s *Storage) CleanupOldData(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)

	result, err := s.db.ExecContext(ctx, `DELETE FROM blacklist_matches WHERE timestamp < ?`, cutoff)
	if err != nil {
		return err
	}

	affected, _ := result.RowsAffected()
	_ = affected // suppress unused

	return nil
}
