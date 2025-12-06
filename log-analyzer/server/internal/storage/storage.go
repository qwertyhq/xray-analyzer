package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

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
	return err
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
func (s *Storage) UpdateUserStats(ctx context.Context, nodeID, userEmail string, requests int, blacklistHits int, lastBlacklistDomain string) error {
	now := time.Now().UTC()

	var lastHit interface{}
	if blacklistHits > 0 {
		lastHit = now
	} else {
		lastHit = nil
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_stats (node_id, user_email, total_requests, blacklist_hits, last_seen, last_blacklist_hit, last_blacklist_domain)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id, user_email) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blacklist_hits = blacklist_hits + excluded.blacklist_hits,
			last_seen = excluded.last_seen,
			last_blacklist_hit = COALESCE(excluded.last_blacklist_hit, last_blacklist_hit),
			last_blacklist_domain = COALESCE(excluded.last_blacklist_domain, last_blacklist_domain)
	`, nodeID, userEmail, requests, blacklistHits, now, lastHit, lastBlacklistDomain)
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
		SELECT node_id, user_email, total_requests, blacklist_hits, last_seen, last_blacklist_hit, last_blacklist_domain
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
		var lastDomain sql.NullString
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.TotalRequests, &u.BlacklistHits, &u.LastSeen, &lastHit, &lastDomain)
		if err != nil {
			return nil, err
		}
		if lastHit.Valid {
			u.LastBlacklistHit = lastHit.Time
		}
		if lastDomain.Valid {
			u.LastBlacklistDomain = lastDomain.String
		}
		users = append(users, u)
	}
	return users, nil
}

// GetAllUsers gets all users sorted by requests
func (s *Storage) GetAllUsers(ctx context.Context, limit int) ([]*models.UserStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, user_email, total_requests, blacklist_hits, last_seen, last_blacklist_hit, last_blacklist_domain
		FROM user_stats
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
		var lastDomain sql.NullString
		err := rows.Scan(&u.NodeID, &u.UserEmail, &u.TotalRequests, &u.BlacklistHits, &u.LastSeen, &lastHit, &lastDomain)
		if err != nil {
			return nil, err
		}
		if lastHit.Valid {
			u.LastBlacklistHit = lastHit.Time
		}
		if lastDomain.Valid {
			u.LastBlacklistDomain = lastDomain.String
		}
		users = append(users, u)
	}
	return users, nil
}

// GetNodeStats gets statistics for all nodes
func (s *Storage) GetNodeStats(ctx context.Context) ([]*models.NodeStats, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node_id, total_requests, blacklist_hits, unique_users, last_seen, last_batch_time, last_batch_count
		FROM node_stats
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.NodeStats
	for rows.Next() {
		n := &models.NodeStats{}
		err := rows.Scan(&n.NodeID, &n.TotalRequests, &n.BlacklistHits, &n.UniqueUsers, &n.LastSeen, &n.LastBatchTime, &n.LastBatchCount)
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

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}
