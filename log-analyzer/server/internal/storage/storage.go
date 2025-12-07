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

	-- Hourly threat statistics for time-based analytics
	CREATE TABLE IF NOT EXISTS threat_hourly_stats (
		hour TEXT NOT NULL,  -- Format: 2025-12-07T14 (YYYY-MM-DDTHH)
		threat_type TEXT NOT NULL,
		match_count INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		PRIMARY KEY (hour, threat_type)
	);
	CREATE INDEX IF NOT EXISTS idx_threat_hourly_time ON threat_hourly_stats(hour DESC);

	-- Daily threat statistics for trend analysis
	CREATE TABLE IF NOT EXISTS threat_daily_stats (
		day TEXT NOT NULL,  -- Format: 2025-12-07 (YYYY-MM-DD)
		threat_type TEXT NOT NULL,
		match_count INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		PRIMARY KEY (day, threat_type)
	);
	CREATE INDEX IF NOT EXISTS idx_threat_daily_time ON threat_daily_stats(day DESC);

	-- GeoIP statistics for threat matches by country
	CREATE TABLE IF NOT EXISTS threat_geo_stats (
		country_code TEXT NOT NULL,
		country_name TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		match_count INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		last_match DATETIME,
		PRIMARY KEY (country_code, threat_type)
	);
	CREATE INDEX IF NOT EXISTS idx_threat_geo_country ON threat_geo_stats(country_code);

	-- User location tracking for geo analysis
	CREATE TABLE IF NOT EXISTS user_locations (
		user_email TEXT NOT NULL,
		country_code TEXT NOT NULL,
		country_name TEXT NOT NULL,
		city TEXT,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		request_count INTEGER DEFAULT 1,
		PRIMARY KEY (user_email, country_code)
	);
	CREATE INDEX IF NOT EXISTS idx_user_loc_email ON user_locations(user_email);

	-- Anomaly detection table
	CREATE TABLE IF NOT EXISTS anomalies (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		user_email TEXT,
		description TEXT NOT NULL,
		details TEXT,  -- JSON encoded details
		detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		resolved INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_anomaly_time ON anomalies(detected_at DESC);
	CREATE INDEX IF NOT EXISTS idx_anomaly_user ON anomalies(user_email);
	CREATE INDEX IF NOT EXISTS idx_anomaly_type ON anomalies(type);

	-- User activity baseline for anomaly detection
	CREATE TABLE IF NOT EXISTS user_activity_baseline (
		user_email TEXT PRIMARY KEY,
		avg_daily_requests REAL DEFAULT 0,
		avg_daily_threats REAL DEFAULT 0,
		typical_hours TEXT,  -- JSON array of typical active hours
		typical_countries TEXT,  -- JSON array of typical countries
		first_seen DATETIME,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- User risk profiles table
	CREATE TABLE IF NOT EXISTS user_risk_profiles (
		user_email TEXT PRIMARY KEY,
		risk_level TEXT NOT NULL DEFAULT 'low',
		risk_score INTEGER NOT NULL DEFAULT 0,
		total_matches INTEGER DEFAULT 0,
		threats_by_type TEXT,  -- JSON encoded map
		unique_countries INTEGER DEFAULT 0,
		anomaly_count INTEGER DEFAULT 0,
		first_seen DATETIME,
		last_activity DATETIME,
		days_active INTEGER DEFAULT 0,
		top_domains TEXT,  -- JSON array
		risk_factors TEXT,  -- JSON array of risk factors
		trend_direction TEXT DEFAULT 'stable',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_risk_level ON user_risk_profiles(risk_level);
	CREATE INDEX IF NOT EXISTS idx_risk_score ON user_risk_profiles(risk_score DESC);

	-- DNS analysis tables
	CREATE TABLE IF NOT EXISTS dns_domain_stats (
		domain TEXT PRIMARY KEY,
		total_hits INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		threat_types TEXT,  -- JSON array
		sources TEXT,  -- JSON array
		first_seen DATETIME,
		last_seen DATETIME,
		risk_level TEXT DEFAULT 'low',
		category_hits TEXT  -- JSON map of category -> count
	);
	CREATE INDEX IF NOT EXISTS idx_dns_domain_hits ON dns_domain_stats(total_hits DESC);
	CREATE INDEX IF NOT EXISTS idx_dns_domain_risk ON dns_domain_stats(risk_level);

	-- DNS hourly statistics
	CREATE TABLE IF NOT EXISTS dns_hourly_stats (
		hour TEXT PRIMARY KEY,  -- Format: 2006-01-02T15
		total_queries INTEGER DEFAULT 0,
		blocked_queries INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_dns_hourly ON dns_hourly_stats(hour DESC);

	-- DNS daily statistics
	CREATE TABLE IF NOT EXISTS dns_daily_stats (
		day TEXT PRIMARY KEY,  -- Format: 2006-01-02
		total_queries INTEGER DEFAULT 0,
		blocked_queries INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_dns_daily ON dns_daily_stats(day DESC);

	-- User DNS statistics
	CREATE TABLE IF NOT EXISTS user_dns_stats (
		user_email TEXT PRIMARY KEY,
		total_queries INTEGER DEFAULT 0,
		blocked_queries INTEGER DEFAULT 0,
		top_domains TEXT,  -- JSON array
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_user_dns_blocked ON user_dns_stats(blocked_queries DESC);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Migration: add last_ip column if not exists
	s.db.Exec("ALTER TABLE user_stats ADD COLUMN last_ip TEXT")

	return nil
}
