package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
	_ "modernc.org/sqlite"
)

// Storage handles database operations
type Storage struct {
	db *sql.DB
}

// New creates a new Storage
func New(dbPath string) (*Storage, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1) // SQLite only supports one writer
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // Keep connection alive

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	// Set busy timeout to wait instead of failing immediately
	if _, err := db.Exec("PRAGMA busy_timeout=30000"); err != nil {
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	// Optimize SQLite performance
	db.Exec("PRAGMA synchronous=NORMAL")
	db.Exec("PRAGMA cache_size=10000")
	db.Exec("PRAGMA temp_store=MEMORY")

	storage := &Storage{db: db}
	if err := storage.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return storage, nil
}

// migrate creates the database schema
func (s *Storage) migrate() error {
	schema := `
	-- Node statistics (aggregated)
	CREATE TABLE IF NOT EXISTS node_stats (
		node_id TEXT PRIMARY KEY,
		total_requests INTEGER DEFAULT 0,
		blacklist_hits INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		last_seen DATETIME,
		last_batch_time DATETIME,
		last_batch_count INTEGER DEFAULT 0
	);

	-- User statistics (aggregated per node)
	CREATE TABLE IF NOT EXISTS user_stats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		user_email TEXT NOT NULL,
		total_requests INTEGER DEFAULT 0,
		blacklist_hits INTEGER DEFAULT 0,
		unique_destinations INTEGER DEFAULT 0,
		last_seen DATETIME,
		last_ip TEXT,
		last_blacklist_hit DATETIME,
		last_blacklist_domain TEXT,
		UNIQUE(node_id, user_email)
	);
	CREATE INDEX IF NOT EXISTS idx_user_stats_node ON user_stats(node_id);
	CREATE INDEX IF NOT EXISTS idx_user_stats_email ON user_stats(user_email);
	CREATE INDEX IF NOT EXISTS idx_user_stats_blacklist ON user_stats(blacklist_hits DESC);

	-- Blacklist matches (recent only, for analysis)
	CREATE TABLE IF NOT EXISTS blacklist_matches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		user_email TEXT NOT NULL,
		source_ip TEXT NOT NULL,
		destination TEXT NOT NULL,
		matched_rule TEXT NOT NULL,
		timestamp DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_blacklist_ts ON blacklist_matches(timestamp);
	CREATE INDEX IF NOT EXISTS idx_blacklist_user ON blacklist_matches(user_email);
	CREATE INDEX IF NOT EXISTS idx_blacklist_node ON blacklist_matches(node_id);

	-- Alerts
	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		node_id TEXT NOT NULL,
		user_email TEXT NOT NULL,
		source_ip TEXT,
		destination TEXT,
		count INTEGER DEFAULT 0,
		message TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		sent INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_alerts_sent ON alerts(sent);
	CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

	-- Hourly aggregates (for charts)
	CREATE TABLE IF NOT EXISTS hourly_stats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		hour DATETIME NOT NULL,
		total_requests INTEGER DEFAULT 0,
		blacklist_hits INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		UNIQUE(node_id, hour)
	);
	CREATE INDEX IF NOT EXISTS idx_hourly_hour ON hourly_stats(hour);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Migration: add last_ip column if not exists
	s.db.Exec("ALTER TABLE user_stats ADD COLUMN last_ip TEXT")

	return nil
}

// UpdateNodeStats updates statistics for a node
func (s *Storage) UpdateNodeStats(ctx context.Context, nodeID string, requests int, blacklistHits int, batchCount int) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO node_stats (node_id, total_requests, blacklist_hits, last_seen, last_batch_time, last_batch_count)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blacklist_hits = blacklist_hits + excluded.blacklist_hits,
			last_seen = excluded.last_seen,
			last_batch_time = excluded.last_batch_time,
			last_batch_count = excluded.last_batch_count
	`, nodeID, requests, blacklistHits, time.Now().UTC(), time.Now().UTC(), batchCount)
	return err
}

// UpdateNodeUniqueUsers updates unique users count for a node
func (s *Storage) UpdateNodeUniqueUsers(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE node_stats 
		SET unique_users = (SELECT COUNT(DISTINCT user_email) FROM user_stats WHERE node_id = ?)
		WHERE node_id = ?
	`, nodeID, nodeID)
	return err
}

// UpdateUserStats updates statistics for a user
func (s *Storage) UpdateUserStats(ctx context.Context, nodeID, userEmail string, requests int, blacklistHits int, lastBlacklistDomain string, uniqueDestinations int, lastIP string) error {
	now := time.Now().UTC()

	var lastHit interface{}
	if blacklistHits > 0 {
		lastHit = now
	} else {
		lastHit = nil
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_stats (node_id, user_email, total_requests, blacklist_hits, unique_destinations, last_seen, last_ip, last_blacklist_hit, last_blacklist_domain)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id, user_email) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blacklist_hits = blacklist_hits + excluded.blacklist_hits,
			unique_destinations = unique_destinations + excluded.unique_destinations,
			last_seen = excluded.last_seen,
			last_ip = COALESCE(excluded.last_ip, last_ip),
			last_blacklist_hit = COALESCE(excluded.last_blacklist_hit, last_blacklist_hit),
			last_blacklist_domain = COALESCE(excluded.last_blacklist_domain, last_blacklist_domain)
	`, nodeID, userEmail, requests, blacklistHits, uniqueDestinations, now, lastIP, lastHit, lastBlacklistDomain)
	return err
}

// RecordBlacklistMatch records a blacklist hit
func (s *Storage) RecordBlacklistMatch(ctx context.Context, match *models.BlacklistMatch) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO blacklist_matches (node_id, user_email, source_ip, destination, matched_rule, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`, match.NodeID, match.UserEmail, match.SourceIP, match.Destination, match.MatchedRule, match.Timestamp)
	return err
}

// CreateAlert creates a new alert
func (s *Storage) CreateAlert(ctx context.Context, alert *models.Alert) error {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts (type, node_id, user_email, source_ip, destination, count, message)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, alert.Type, alert.NodeID, alert.UserEmail, alert.SourceIP, alert.Destination, alert.Count, alert.Message)

	if err != nil {
		return err
	}

	id, _ := result.LastInsertId()
	alert.ID = id
	return nil
}

// GetUnsentAlerts gets alerts that haven't been sent
func (s *Storage) GetUnsentAlerts(ctx context.Context) ([]*models.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, node_id, user_email, source_ip, destination, count, message, created_at
		FROM alerts
		WHERE sent = 0
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &a.UserEmail, &a.SourceIP, &a.Destination, &a.Count, &a.Message, &a.CreatedAt)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// MarkAlertSent marks an alert as sent
func (s *Storage) MarkAlertSent(ctx context.Context, alertID int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE alerts SET sent = 1 WHERE id = ?", alertID)
	return err
}

// GetUserBlacklistCount gets blacklist hit count for a user in a time window
func (s *Storage) GetUserBlacklistCount(ctx context.Context, nodeID, userEmail string, since time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM blacklist_matches
		WHERE node_id = ? AND user_email = ? AND timestamp > ?
	`, nodeID, userEmail, since).Scan(&count)
	return count, err
}

// GetTopBlacklistUsers gets users with most blacklist hits
func (s *Storage) GetTopBlacklistUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, user_email, total_requests, blacklist_hits, last_seen, last_ip, last_blacklist_hit, last_blacklist_domain
		FROM user_stats
		WHERE blacklist_hits > 0
		ORDER BY blacklist_hits DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.UserStats
	for rows.Next() {
		u := &models.UserStats{}
		var lastHit sql.NullTime
		var lastDomain, lastIP sql.NullString
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.TotalRequests, &u.BlacklistHits, &u.LastSeen, &lastIP, &lastHit, &lastDomain)
		if err != nil {
			return nil, err
		}
		if lastHit.Valid {
			u.LastBlacklistHit = lastHit.Time
		}
		if lastDomain.Valid {
			u.LastBlacklistDomain = lastDomain.String
		}
		if lastIP.Valid {
			u.LastIP = lastIP.String
		}
		users = append(users, u)
	}
	return users, nil
}

// GetAllUsers gets all users sorted by requests (aggregated across nodes)
func (s *Storage) GetAllUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			GROUP_CONCAT(DISTINCT node_id) as nodes,
			user_email, 
			SUM(total_requests) as total_requests, 
			SUM(blacklist_hits) as blacklist_hits, 
			MAX(last_seen) as last_seen, 
			MAX(last_ip) as last_ip,
			MAX(last_blacklist_hit) as last_blacklist_hit, 
			(SELECT last_blacklist_domain FROM user_stats u2 WHERE u2.user_email = user_stats.user_email ORDER BY last_blacklist_hit DESC LIMIT 1) as last_blacklist_domain
		FROM user_stats
		GROUP BY user_email
		ORDER BY total_requests DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.UserStats
	for rows.Next() {
		u := &models.UserStats{}
		var lastHit sql.NullTime
		var lastDomain, lastIP, nodes sql.NullString
		err := rows.Scan(&nodes, &u.UserEmail, &u.TotalRequests, &u.BlacklistHits, &u.LastSeen, &lastIP, &lastHit, &lastDomain)
		if err != nil {
			return nil, err
		}
		if nodes.Valid {
			u.NodeID = nodes.String
		}
		if lastHit.Valid {
			u.LastBlacklistHit = lastHit.Time
		}
		if lastDomain.Valid {
			u.LastBlacklistDomain = lastDomain.String
		}
		if lastIP.Valid {
			u.LastIP = lastIP.String
		}
		users = append(users, u)
	}
	return users, nil
}

// GetNodeStats gets statistics for all nodes
func (s *Storage) GetNodeStats(ctx context.Context) ([]*models.NodeStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT 
			n.node_id, 
			n.total_requests, 
			n.blacklist_hits, 
			n.unique_users, 
			COALESCE((SELECT COUNT(DISTINCT user_email) FROM user_stats WHERE node_id = n.node_id AND last_seen > datetime('now', '-5 minutes')), 0) as online_users,
			n.last_seen, 
			n.last_batch_time, 
			n.last_batch_count
		FROM node_stats n
		ORDER BY n.last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.NodeStats
	for rows.Next() {
		n := &models.NodeStats{}
		err := rows.Scan(&n.NodeID, &n.TotalRequests, &n.BlacklistHits, &n.UniqueUsers, &n.OnlineUsers, &n.LastSeen, &n.LastBatchTime, &n.LastBatchCount)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// CleanupOldData removes old blacklist matches
func (s *Storage) CleanupOldData(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)

	result, err := s.db.ExecContext(ctx, `
		DELETE FROM blacklist_matches WHERE timestamp < ?
	`, cutoff)
	if err != nil {
		return err
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		log.Printf("storage: cleaned up %d old blacklist matches", affected)
	}

	return nil
}

// DeleteNode removes a node and all its related data
func (s *Storage) DeleteNode(ctx context.Context, nodeID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete from all related tables
	tx.ExecContext(ctx, "DELETE FROM user_stats WHERE node_id = ?", nodeID)
	tx.ExecContext(ctx, "DELETE FROM blacklist_matches WHERE node_id = ?", nodeID)
	tx.ExecContext(ctx, "DELETE FROM alerts WHERE node_id = ?", nodeID)
	tx.ExecContext(ctx, "DELETE FROM hourly_stats WHERE node_id = ?", nodeID)
	tx.ExecContext(ctx, "DELETE FROM node_stats WHERE node_id = ?", nodeID)

	return tx.Commit()
}

// CleanupInactiveNodes removes nodes that haven't been seen for a while
func (s *Storage) CleanupInactiveNodes(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)

	// Get inactive node IDs
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id FROM node_stats WHERE last_seen < ?
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

	// Delete each node
	for _, nodeID := range nodeIDs {
		if err := s.DeleteNode(ctx, nodeID); err != nil {
			log.Printf("storage: failed to delete node %s: %v", nodeID, err)
		}
	}

	if len(nodeIDs) > 0 {
		log.Printf("storage: cleaned up %d inactive nodes", len(nodeIDs))
	}

	return len(nodeIDs), nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// UpdateHourlyStats updates hourly statistics for charts
func (s *Storage) UpdateHourlyStats(ctx context.Context, nodeID string, requests int, blacklistHits int, uniqueUsers int) error {
	// Round to current hour
	now := time.Now().UTC().Truncate(time.Hour)

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
		SELECT hour, SUM(total_requests) as total_requests, SUM(blacklist_hits) as blacklist_hits, SUM(unique_users) as unique_users
		FROM hourly_stats
		WHERE hour >= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := []models.HourlyStats{} // Initialize as empty slice, not nil
	for rows.Next() {
		var s models.HourlyStats
		if err := rows.Scan(&s.Hour, &s.TotalRequests, &s.BlacklistHits, &s.UniqueUsers); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, nil
}

// GetUserDetails gets detailed stats for a specific user
func (s *Storage) GetUserDetails(ctx context.Context, userEmail string) (*models.UserDetails, error) {
	// Get basic stats across all nodes
	user := &models.UserDetails{
		UserEmail: userEmail,
		Nodes:     []models.UserNodeStats{},
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, total_requests, blacklist_hits, unique_destinations, last_seen, last_blacklist_hit, last_blacklist_domain
		FROM user_stats
		WHERE user_email = ?
		ORDER BY total_requests DESC
	`, userEmail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ns models.UserNodeStats
		var lastHit sql.NullTime
		var lastDomain sql.NullString
		if err := rows.Scan(&ns.NodeID, &ns.TotalRequests, &ns.BlacklistHits, &ns.UniqueDestinations, &ns.LastSeen, &lastHit, &lastDomain); err != nil {
			return nil, err
		}
		if lastHit.Valid {
			ns.LastBlacklistHit = lastHit.Time
		}
		if lastDomain.Valid {
			ns.LastBlacklistDomain = lastDomain.String
		}
		user.TotalRequests += ns.TotalRequests
		user.TotalBlacklistHits += ns.BlacklistHits
		user.Nodes = append(user.Nodes, ns)
	}

	// Get recent blacklist matches
	matchRows, err := s.db.QueryContext(ctx, `
		SELECT node_id, source_ip, destination, matched_rule, timestamp
		FROM blacklist_matches
		WHERE user_email = ?
		ORDER BY timestamp DESC
		LIMIT 50
	`, userEmail)
	if err != nil {
		return nil, err
	}
	defer matchRows.Close()

	for matchRows.Next() {
		var m models.BlacklistMatchInfo
		if err := matchRows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &m.Timestamp); err != nil {
			return nil, err
		}
		user.RecentMatches = append(user.RecentMatches, m)
	}

	return user, nil
}

// GetGlobalStats gets aggregated stats across all nodes
func (s *Storage) GetGlobalStats(ctx context.Context) (*models.GlobalStats, error) {
	stats := &models.GlobalStats{}

	// Total requests and blacklist hits
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(total_requests), 0), COALESCE(SUM(blacklist_hits), 0), COUNT(*)
		FROM node_stats
	`).Scan(&stats.TotalRequests, &stats.TotalBlacklistHits, &stats.TotalNodes)
	if err != nil {
		return nil, err
	}

	// Total unique users (across all nodes)
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM user_stats
	`).Scan(&stats.TotalUniqueUsers)
	if err != nil {
		return nil, err
	}

	// Online users (active in last 5 minutes)
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM user_stats
		WHERE last_seen > datetime('now', '-5 minutes')
	`).Scan(&stats.OnlineUsers)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetHourlyStatsRange gets hourly statistics for a specific time range
func (s *Storage) GetHourlyStatsRange(ctx context.Context, from, to time.Time) ([]models.HourlyStats, error) {
	// Default to last 7 days if not specified
	if from.IsZero() {
		from = time.Now().UTC().Add(-7 * 24 * time.Hour)
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT hour, SUM(total_requests) as total_requests, SUM(blacklist_hits) as blacklist_hits, SUM(unique_users) as unique_users
		FROM hourly_stats
		WHERE hour >= ? AND hour <= ?
		GROUP BY hour
		ORDER BY hour ASC
	`, from.Truncate(time.Hour), to.Truncate(time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := []models.HourlyStats{} // Initialize as empty slice, not nil
	for rows.Next() {
		var s models.HourlyStats
		if err := rows.Scan(&s.Hour, &s.TotalRequests, &s.BlacklistHits, &s.UniqueUsers); err != nil {
			return nil, err
		}
		stats = append(stats, s)
	}
	return stats, nil
}

// GetUserAnomalies finds users with unusual activity spikes
func (s *Storage) GetUserAnomalies(ctx context.Context, limit int) ([]models.Anomaly, error) {
	// Find users whose recent blacklist hits (last 2 hours) are significantly higher than their average
	rows, err := s.db.QueryContext(ctx, `
		WITH user_recent AS (
			SELECT user_email, COUNT(*) as recent_hits
			FROM blacklist_matches
			WHERE timestamp > datetime('now', '-2 hours')
			GROUP BY user_email
		),
		user_baseline AS (
			SELECT user_email, COUNT(*) / 24.0 as avg_hits
			FROM blacklist_matches
			WHERE timestamp > datetime('now', '-24 hours')
			AND timestamp <= datetime('now', '-2 hours')
			GROUP BY user_email
		)
		SELECT r.user_email, r.recent_hits, COALESCE(b.avg_hits, 0) as avg_hits
		FROM user_recent r
		LEFT JOIN user_baseline b ON r.user_email = b.user_email
		WHERE r.recent_hits > 5
		AND (b.avg_hits IS NULL OR r.recent_hits > b.avg_hits * 3)
		ORDER BY r.recent_hits DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anomalies []models.Anomaly
	for rows.Next() {
		var userEmail string
		var recentHits int64
		var avgHits float64
		if err := rows.Scan(&userEmail, &recentHits, &avgHits); err != nil {
			return nil, err
		}

		deviation := float64(recentHits)
		if avgHits > 0 {
			deviation = float64(recentHits) / avgHits
		}

		anomalies = append(anomalies, models.Anomaly{
			Type:      "user_spike",
			Hour:      time.Now().UTC().Truncate(time.Hour),
			UserEmail: userEmail,
			Value:     recentHits,
			Baseline:  int64(avgHits),
			Deviation: deviation,
			Message:   fmt.Sprintf("User %s: %d blacklist hits in last 2h (avg: %.1f/2h)", userEmail, recentHits, avgHits*2),
		})
	}
	return anomalies, nil
}

// GetRecentAlerts gets recent alerts
func (s *Storage) GetRecentAlerts(ctx context.Context, limit int) ([]*models.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, node_id, user_email, source_ip, destination, count, message, created_at, sent
		FROM alerts
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var sourceIP, destination sql.NullString
		err := rows.Scan(&a.ID, &a.Type, &a.NodeID, &a.UserEmail, &sourceIP, &destination, &a.Count, &a.Message, &a.CreatedAt, &a.Sent)
		if err != nil {
			return nil, err
		}
		if sourceIP.Valid {
			a.SourceIP = sourceIP.String
		}
		if destination.Valid {
			a.Destination = destination.String
		}
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// GetBlacklistAnalytics returns detailed blacklist analytics for a time period
func (s *Storage) GetBlacklistAnalytics(ctx context.Context, since time.Time) (*models.BlacklistAnalytics, error) {
	analytics := &models.BlacklistAnalytics{}

	// Total hits in period
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM blacklist_matches WHERE timestamp > ?
	`, since).Scan(&analytics.TotalHits)
	if err != nil {
		return nil, err
	}

	// Unique users
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_email) FROM blacklist_matches WHERE timestamp > ?
	`, since).Scan(&analytics.UniqueUsers)
	if err != nil {
		return nil, err
	}

	// Unique domains
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT destination) FROM blacklist_matches WHERE timestamp > ?
	`, since).Scan(&analytics.UniqueDomains)
	if err != nil {
		return nil, err
	}

	// Top domains
	domainRows, err := s.db.QueryContext(ctx, `
		SELECT destination, matched_rule, COUNT(*) as hits, COUNT(DISTINCT user_email) as users
		FROM blacklist_matches
		WHERE timestamp > ?
		GROUP BY destination
		ORDER BY hits DESC
		LIMIT 50
	`, since)
	if err != nil {
		return nil, err
	}
	defer domainRows.Close()

	for domainRows.Next() {
		var d models.DomainStats
		if err := domainRows.Scan(&d.Domain, &d.MatchedRule, &d.HitCount, &d.UniqueUsers); err != nil {
			return nil, err
		}
		analytics.TopDomains = append(analytics.TopDomains, d)
	}

	// Top users with their domains
	userRows, err := s.db.QueryContext(ctx, `
		SELECT 
			bm.user_email, 
			COUNT(*) as hits, 
			COUNT(DISTINCT bm.destination) as domains,
			GROUP_CONCAT(DISTINCT bm.destination) as top_domains,
			COALESCE(MAX(bm.source_ip), '') as last_ip
		FROM blacklist_matches bm
		WHERE bm.timestamp > ?
		GROUP BY bm.user_email
		ORDER BY hits DESC
		LIMIT 50
	`, since)
	if err != nil {
		return nil, err
	}
	defer userRows.Close()

	for userRows.Next() {
		var u models.UserBlacklistStats
		var topDomainsStr sql.NullString
		if err := userRows.Scan(&u.UserEmail, &u.HitCount, &u.UniqueDomains, &topDomainsStr, &u.LastIP); err != nil {
			return nil, err
		}
		if topDomainsStr.Valid && topDomainsStr.String != "" {
			// Take first 5 domains
			domains := strings.Split(topDomainsStr.String, ",")
			if len(domains) > 5 {
				domains = domains[:5]
			}
			u.TopDomains = domains
		}
		analytics.TopUsers = append(analytics.TopUsers, u)
	}

	// Recent matches
	matchRows, err := s.db.QueryContext(ctx, `
		SELECT node_id, user_email, source_ip, destination, matched_rule, timestamp
		FROM blacklist_matches
		WHERE timestamp > ?
		ORDER BY timestamp DESC
		LIMIT 100
	`, since)
	if err != nil {
		return nil, err
	}
	defer matchRows.Close()

	for matchRows.Next() {
		var m models.BlacklistMatchInfo
		if err := matchRows.Scan(&m.NodeID, &m.UserEmail, &m.SourceIP, &m.Destination, &m.MatchedRule, &m.Timestamp); err != nil {
			return nil, err
		}
		analytics.RecentMatches = append(analytics.RecentMatches, m)
	}

	// Hourly stats
	hourlyRows, err := s.db.QueryContext(ctx, `
		SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, COUNT(*) as hits
		FROM blacklist_matches
		WHERE timestamp > ? AND timestamp IS NOT NULL
		GROUP BY hour
		HAVING hour IS NOT NULL
		ORDER BY hour
	`, since)
	if err != nil {
		return nil, err
	}
	defer hourlyRows.Close()

	for hourlyRows.Next() {
		var h models.HourlyBlacklistStats
		var hourStr string
		if err := hourlyRows.Scan(&hourStr, &h.HitCount); err != nil {
			return nil, err
		}
		h.Hour, _ = time.Parse("2006-01-02 15:04:05", hourStr)
		analytics.HourlyStats = append(analytics.HourlyStats, h)
	}

	return analytics, nil
}

// GetUserBlacklistDetails returns detailed blacklist info for a user
func (s *Storage) GetUserBlacklistDetails(ctx context.Context, userEmail string, since time.Time) ([]models.BlacklistMatchInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, source_ip, destination, matched_rule, timestamp
		FROM blacklist_matches
		WHERE user_email = ? AND timestamp > ?
		ORDER BY timestamp DESC
		LIMIT 500
	`, userEmail, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []models.BlacklistMatchInfo
	for rows.Next() {
		var m models.BlacklistMatchInfo
		if err := rows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &m.Timestamp); err != nil {
			return nil, err
		}
		matches = append(matches, m)
	}
	return matches, nil
}
