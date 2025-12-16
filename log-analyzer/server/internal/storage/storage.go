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

// DB returns the underlying database connection for advanced queries
func (s *Storage) DB() *sql.DB {
	return s.db
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
	CREATE INDEX IF NOT EXISTS idx_user_stats_node_lastseen ON user_stats(node_id, last_seen DESC);

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
	CREATE INDEX IF NOT EXISTS idx_blacklist_user_time ON blacklist_matches(user_email, timestamp DESC);

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

	-- Unique users tracking per hour/threat_type (for accurate unique_users count)
	CREATE TABLE IF NOT EXISTS threat_hourly_users (
		hour TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		user_email TEXT NOT NULL,
		PRIMARY KEY (hour, threat_type, user_email)
	);

	-- Daily threat statistics for trend analysis
	CREATE TABLE IF NOT EXISTS threat_daily_stats (
		day TEXT NOT NULL,  -- Format: 2025-12-07 (YYYY-MM-DD)
		threat_type TEXT NOT NULL,
		match_count INTEGER DEFAULT 0,
		unique_users INTEGER DEFAULT 0,
		PRIMARY KEY (day, threat_type)
	);
	CREATE INDEX IF NOT EXISTS idx_threat_daily_time ON threat_daily_stats(day DESC);

	-- Unique users tracking per day/threat_type (for accurate unique_users count)
	CREATE TABLE IF NOT EXISTS threat_daily_users (
		day TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		user_email TEXT NOT NULL,
		PRIMARY KEY (day, threat_type, user_email)
	);

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
		latitude REAL,
		longitude REAL,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		request_count INTEGER DEFAULT 1,
		PRIMARY KEY (user_email, country_code)
	);
	CREATE INDEX IF NOT EXISTS idx_user_loc_email ON user_locations(user_email);

	-- User IP history (last 20 IPs per user)
	CREATE TABLE IF NOT EXISTS user_ip_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		node_id TEXT,
		country_code TEXT,
		country_name TEXT,
		city TEXT,
		latitude REAL,
		longitude REAL,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		request_count INTEGER DEFAULT 1,
		UNIQUE(user_email, ip_address)
	);
	CREATE INDEX IF NOT EXISTS idx_user_ip_email ON user_ip_history(user_email);
	CREATE INDEX IF NOT EXISTS idx_user_ip_lastseen ON user_ip_history(user_email, last_seen DESC);

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

	-- Reports table
	CREATE TABLE IF NOT EXISTS reports (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		format TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		start_date DATETIME,
		end_date DATETIME,
		generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT DEFAULT 'pending',
		sections TEXT,      -- JSON array
		top_threats TEXT,   -- JSON array
		top_users TEXT,     -- JSON array
		top_countries TEXT, -- JSON array
		summary TEXT        -- JSON object
	);
	CREATE INDEX IF NOT EXISTS idx_reports_generated ON reports(generated_at DESC);
	CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);

	-- =============================================
	-- User Correlation Tables for AI Analysis
	-- =============================================

	-- IP to Users mapping (which users share the same IP)
	CREATE TABLE IF NOT EXISTS ip_user_map (
		ip_address TEXT NOT NULL,
		user_email TEXT NOT NULL,
		node_id TEXT,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		request_count INTEGER DEFAULT 1,
		PRIMARY KEY (ip_address, user_email)
	);
	CREATE INDEX IF NOT EXISTS idx_ip_user_map_ip ON ip_user_map(ip_address);
	CREATE INDEX IF NOT EXISTS idx_ip_user_map_user ON ip_user_map(user_email);
	CREATE INDEX IF NOT EXISTS idx_ip_user_map_lastseen ON ip_user_map(last_seen DESC);

	-- HWID to Users mapping (which users share the same HWID)
	CREATE TABLE IF NOT EXISTS hwid_user_map (
		hwid TEXT NOT NULL,
		user_email TEXT NOT NULL,
		platform TEXT,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		request_count INTEGER DEFAULT 1,
		PRIMARY KEY (hwid, user_email)
	);
	CREATE INDEX IF NOT EXISTS idx_hwid_user_map_hwid ON hwid_user_map(hwid);
	CREATE INDEX IF NOT EXISTS idx_hwid_user_map_user ON hwid_user_map(user_email);

	-- User identity fingerprint (combo of IP+HWID for unique identification)
	CREATE TABLE IF NOT EXISTS user_fingerprints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		hwid TEXT,
		user_agent TEXT,
		node_id TEXT,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		session_count INTEGER DEFAULT 1,
		UNIQUE(user_email, ip_address, hwid)
	);
	CREATE INDEX IF NOT EXISTS idx_fingerprint_user ON user_fingerprints(user_email);
	CREATE INDEX IF NOT EXISTS idx_fingerprint_ip ON user_fingerprints(ip_address);
	CREATE INDEX IF NOT EXISTS idx_fingerprint_hwid ON user_fingerprints(hwid);

	-- User clusters (groups of users that share IPs or HWIDs)
	CREATE TABLE IF NOT EXISTS user_clusters (
		cluster_id TEXT NOT NULL,
		user_email TEXT NOT NULL,
		reason TEXT NOT NULL,  -- 'shared_ip', 'shared_hwid', 'both'
		shared_value TEXT NOT NULL,  -- the IP or HWID that links them
		confidence REAL DEFAULT 0.5,
		first_linked DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (cluster_id, user_email)
	);
	CREATE INDEX IF NOT EXISTS idx_cluster_id ON user_clusters(cluster_id);
	CREATE INDEX IF NOT EXISTS idx_cluster_user ON user_clusters(user_email);

	-- Enhanced user profile for AI (aggregated view)
	CREATE TABLE IF NOT EXISTS user_ai_profile (
		user_email TEXT PRIMARY KEY,
		-- Identity metrics
		unique_ips INTEGER DEFAULT 0,
		unique_hwids INTEGER DEFAULT 0,
		unique_fingerprints INTEGER DEFAULT 0,
		unique_countries INTEGER DEFAULT 0,
		unique_nodes INTEGER DEFAULT 0,
		-- Activity metrics
		total_requests INTEGER DEFAULT 0,
		total_sessions INTEGER DEFAULT 0,
		avg_session_duration_sec REAL DEFAULT 0,
		-- Threat metrics
		total_threat_matches INTEGER DEFAULT 0,
		threat_categories TEXT,  -- JSON: {"malware": 5, "phishing": 2}
		-- Correlation metrics
		shared_ip_users INTEGER DEFAULT 0,  -- count of other users sharing IPs
		shared_hwid_users INTEGER DEFAULT 0,  -- count of other users sharing HWIDs
		cluster_ids TEXT,  -- JSON array of cluster IDs
		-- Time metrics
		first_seen DATETIME,
		last_seen DATETIME,
		active_days INTEGER DEFAULT 0,
		typical_hours TEXT,  -- JSON array [9,10,11,14,15,16]
		-- Risk assessment
		risk_score INTEGER DEFAULT 0,
		risk_factors TEXT,  -- JSON array
		-- Remnawave data (synced)
		remna_uuid TEXT,
		remna_status TEXT,
		remna_traffic_used INTEGER DEFAULT 0,
		remna_traffic_limit INTEGER DEFAULT 0,
		remna_expire_at DATETIME,
		remna_hwid_devices INTEGER DEFAULT 0,
		remna_hwid_limit INTEGER DEFAULT 0,
		-- Metadata
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_ai_profile_risk ON user_ai_profile(risk_score DESC);
	CREATE INDEX IF NOT EXISTS idx_ai_profile_shared ON user_ai_profile(shared_ip_users DESC, shared_hwid_users DESC);

	-- Connection sessions (for session analysis)
	CREATE TABLE IF NOT EXISTS user_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_email TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		hwid TEXT,
		node_id TEXT,
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		ended_at DATETIME,
		request_count INTEGER DEFAULT 0,
		bytes_transferred INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_email);
	CREATE INDEX IF NOT EXISTS idx_sessions_time ON user_sessions(started_at DESC);

	-- Remnawave Users (synced from API)
	CREATE TABLE IF NOT EXISTS remna_users (
		uuid TEXT PRIMARY KEY,
		id INTEGER,
		short_uuid TEXT,
		username TEXT NOT NULL,
		email TEXT,
		status TEXT NOT NULL,
		traffic_limit_bytes INTEGER DEFAULT 0,
		used_traffic_bytes INTEGER DEFAULT 0,
		lifetime_traffic_bytes INTEGER DEFAULT 0,
		traffic_limit_strategy TEXT,
		expire_at DATETIME,
		online_at DATETIME,
		first_connected_at DATETIME,
		hwid_device_limit INTEGER,
		hwid_device_count INTEGER DEFAULT 0,
		telegram_id INTEGER,
		description TEXT,
		tag TEXT,
		created_at DATETIME,
		updated_at DATETIME,
		synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		real_name TEXT,
		phone TEXT,
		telegram_user TEXT,
		payment_info TEXT,
		plan TEXT,
		us_id TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_remna_users_id ON remna_users(id);
	CREATE INDEX IF NOT EXISTS idx_remna_users_us_id ON remna_users(us_id);
	CREATE INDEX IF NOT EXISTS idx_remna_users_username ON remna_users(username);
	CREATE INDEX IF NOT EXISTS idx_remna_users_email ON remna_users(email);
	CREATE INDEX IF NOT EXISTS idx_remna_users_status ON remna_users(status);
	CREATE INDEX IF NOT EXISTS idx_remna_users_online ON remna_users(online_at DESC);
	CREATE INDEX IF NOT EXISTS idx_remna_users_expire ON remna_users(expire_at);
	CREATE INDEX IF NOT EXISTS idx_remna_users_tag ON remna_users(tag);

	-- Remnawave HWID Devices (synced from API)
	CREATE TABLE IF NOT EXISTS remna_hwid_devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hwid TEXT NOT NULL,
		user_uuid TEXT NOT NULL,
		username TEXT,
		platform TEXT,
		os_version TEXT,
		device_model TEXT,
		app_version TEXT,
		first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_active_at DATETIME,
		synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(hwid, user_uuid)
	);
	CREATE INDEX IF NOT EXISTS idx_remna_hwid_hwid ON remna_hwid_devices(hwid);
	CREATE INDEX IF NOT EXISTS idx_remna_hwid_user ON remna_hwid_devices(user_uuid);
	CREATE INDEX IF NOT EXISTS idx_remna_hwid_active ON remna_hwid_devices(last_active_at DESC);

	-- Remnawave Nodes (synced from API)
	CREATE TABLE IF NOT EXISTS remna_nodes (
		uuid TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		address TEXT,
		port INTEGER,
		is_connected INTEGER DEFAULT 0,
		is_disabled INTEGER DEFAULT 0,
		is_traffic_track INTEGER DEFAULT 0,
		traffic_total INTEGER DEFAULT 0,
		traffic_used INTEGER DEFAULT 0,
		users_online INTEGER DEFAULT 0,
		country_code TEXT,
		synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_remna_nodes_connected ON remna_nodes(is_connected);
	CREATE INDEX IF NOT EXISTS idx_remna_nodes_country ON remna_nodes(country_code);

	-- AI Chat Sessions
	CREATE TABLE IF NOT EXISTS ai_chat_sessions (
		id TEXT PRIMARY KEY,
		title TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		total_tokens INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated ON ai_chat_sessions(updated_at DESC);

	-- AI Chat Messages
	CREATE TABLE IF NOT EXISTS ai_chat_messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		role TEXT NOT NULL,
		content TEXT NOT NULL,
		tokens_used INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (session_id) REFERENCES ai_chat_sessions(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON ai_chat_messages(session_id);
	CREATE INDEX IF NOT EXISTS idx_chat_messages_time ON ai_chat_messages(created_at);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Migration: add last_ip column if not exists
	s.db.Exec("ALTER TABLE user_stats ADD COLUMN last_ip TEXT")

	// Migration: add latitude/longitude columns to user_locations
	s.db.Exec("ALTER TABLE user_locations ADD COLUMN latitude REAL")
	s.db.Exec("ALTER TABLE user_locations ADD COLUMN longitude REAL")

	// Migration: add latitude/longitude columns to user_ip_history
	s.db.Exec("ALTER TABLE user_ip_history ADD COLUMN latitude REAL")
	s.db.Exec("ALTER TABLE user_ip_history ADD COLUMN longitude REAL")

	// Migration: add us_id column to remna_users (Xray log user ID from US_ID: in description)
	s.db.Exec("ALTER TABLE remna_users ADD COLUMN us_id TEXT")
	s.db.Exec("CREATE INDEX IF NOT EXISTS idx_remna_users_us_id ON remna_users(us_id)")

	return nil
}
