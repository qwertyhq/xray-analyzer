package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Storage handles database operations
type Storage struct {
	db *sql.DB
}

// New creates a new Storage
func New(dbPath string) (*Storage, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

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

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// migrate creates the database schema
func (s *Storage) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS node_stats (
		node_id TEXT PRIMARY KEY,
		total_requests INTEGER DEFAULT 0,
		blacklist_hits INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		last_seen DATETIME,
		last_batch_time DATETIME,
		last_batch_count INTEGER DEFAULT 0
	);

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

	CREATE TABLE IF NOT EXISTS blacklist_matches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		user_email TEXT NOT NULL,
		source_ip TEXT NOT NULL,
		destination TEXT NOT NULL,
		matched_rule TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_blacklist_node ON blacklist_matches(node_id);
	CREATE INDEX IF NOT EXISTS idx_blacklist_user ON blacklist_matches(user_email);
	CREATE INDEX IF NOT EXISTS idx_blacklist_time ON blacklist_matches(timestamp DESC);

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

	CREATE TABLE IF NOT EXISTS user_destinations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		node_id TEXT NOT NULL,
		destination TEXT NOT NULL,
		request_count INTEGER DEFAULT 1,
		first_seen DATETIME,
		last_seen DATETIME,
		UNIQUE(user_email, node_id, destination)
	);
	CREATE INDEX IF NOT EXISTS idx_user_dest_email ON user_destinations(user_email);
	CREATE INDEX IF NOT EXISTS idx_user_dest_time ON user_destinations(last_seen DESC);

	CREATE TABLE IF NOT EXISTS threat_matches (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		node_id TEXT NOT NULL,
		source_ip TEXT NOT NULL,
		destination TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		source TEXT NOT NULL,
		confidence INTEGER DEFAULT 0,
		description TEXT,
		matched_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_threat_user ON threat_matches(user_email);
	CREATE INDEX IF NOT EXISTS idx_threat_time ON threat_matches(matched_at DESC);
	CREATE INDEX IF NOT EXISTS idx_threat_type ON threat_matches(threat_type);

	-- Aggregated threat statistics (counters that persist)
	CREATE TABLE IF NOT EXISTS threat_stats_agg (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		total_matches INTEGER DEFAULT 0,
		last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT OR IGNORE INTO threat_stats_agg (id, total_matches) VALUES (1, 0);

	-- Stats by threat type (persistent counters)
	CREATE TABLE IF NOT EXISTS threat_type_stats (
		threat_type TEXT PRIMARY KEY,
		match_count INTEGER DEFAULT 0,
		last_match DATETIME
	);

	-- Stats by user and category (persistent counters)
	CREATE TABLE IF NOT EXISTS user_threat_stats (
		user_email TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		match_count INTEGER DEFAULT 0,
		last_match DATETIME,
		PRIMARY KEY (user_email, threat_type)
	);
	CREATE INDEX IF NOT EXISTS idx_user_threat_type ON user_threat_stats(threat_type);
	CREATE INDEX IF NOT EXISTS idx_user_threat_count ON user_threat_stats(match_count DESC);

	-- User domains per category
	CREATE TABLE IF NOT EXISTS user_threat_domains (
		user_email TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		domain TEXT NOT NULL,
		hit_count INTEGER DEFAULT 1,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (user_email, threat_type, domain)
	);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Migration: add last_ip column if not exists
	s.db.Exec("ALTER TABLE user_stats ADD COLUMN last_ip TEXT")

	return nil
}
