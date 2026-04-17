package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds server configuration
type Config struct {
	// Server settings
	ListenAddr     string
	DBPath         string
	AllowedOrigins []string // Allowed origins for WebSocket CORS (empty = allow all for dev)

	// Authentication
	APIToken   string // Bearer token for API/dashboard access (empty = no auth)
	AgentToken string // Token for agent WebSocket connections (empty = no auth)

	// Analysis settings
	BlacklistPath      string
	BlacklistReload    time.Duration
	BlacklistRemoteURL string // URL to fetch additional blocked domains

	// Telegram settings
	TelegramEnabled bool
	TelegramToken   string
	TelegramChatID  string

	// Thresholds
	SuspiciousRequestCount int           // Requests to blacklisted sites to trigger alert
	SuspiciousTimeWindow   time.Duration // Time window for counting

	// Remnawave API settings
	RemnawaveEnabled      bool
	RemnawaveURL          string
	RemnawaveAPIToken     string
	RemnawaveSyncInterval time.Duration // Interval for syncing data from Remnawave

	// Aleria AI settings
	AleriaAPIKey string

	// Bridge filtering: regex matching inbound tags whose source IP is an
	// infrastructure hop (another Xray bridge node), not a real client.
	// When matched, the source IP is suppressed for IP-history / correlation
	// tables. Empty string disables the filter.
	BridgeInboundPattern string

	// BridgeNodeIDs is the list of node_id values that act as bridge ingress
	// (the upstream side of the BRIDGE_*_IN tunnel). Used to resolve the
	// real client IP for an exit-node bridged flow. Empty disables Layer-3
	// correlation.
	BridgeNodeIDs []string

	// BridgeCorrelationWindow is the ± time window used to match an exit-node
	// bridged entry against bridge-node user_ip_history rows. Should stay in
	// the single-digit-seconds range — NTP-synced nodes have sub-second drift,
	// and a wider window fans each destination out to too many candidates.
	BridgeCorrelationWindow time.Duration

	// Redis for persistent L2 cache. Empty RedisAddr disables it (the
	// in-memory L1 still works; startup just means a cold warm-up from SQL).
	RedisAddr      string
	RedisPassword  string
	RedisKeyPrefix string
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		ListenAddr:             getEnv("LISTEN_ADDR", ":8080"),
		DBPath:                 getEnv("DB_PATH", "./data/analyzer.db"),
		AllowedOrigins:         getStringSliceEnv("ALLOWED_ORIGINS", nil),
		APIToken:               getEnv("API_TOKEN", ""),
		AgentToken:             getEnv("AGENT_TOKEN", ""),
		BlacklistPath:          getEnv("BLACKLIST_PATH", "./blacklist.txt"),
		BlacklistReload:        getDurationEnv("BLACKLIST_RELOAD", 5*time.Minute),
		BlacklistRemoteURL:     getEnv("BLACKLIST_REMOTE_URL", ""),
		TelegramEnabled:        getBoolEnv("TELEGRAM_ENABLED", false),
		TelegramToken:          getEnv("TELEGRAM_TOKEN", ""),
		TelegramChatID:         getEnv("TELEGRAM_CHAT_ID", ""),
		SuspiciousRequestCount: getIntEnv("SUSPICIOUS_REQUEST_COUNT", 5),
		SuspiciousTimeWindow:   getDurationEnv("SUSPICIOUS_TIME_WINDOW", 1*time.Hour),
		RemnawaveEnabled:       getBoolEnv("REMNAWAVE_ENABLED", false),
		RemnawaveURL:           getEnv("REMNAWAVE_URL", ""),
		RemnawaveAPIToken:      getEnv("REMNAWAVE_API_TOKEN", ""),
		RemnawaveSyncInterval:  getDurationEnv("REMNAWAVE_SYNC_INTERVAL", 1*time.Minute), // More frequent for accurate online stats
		AleriaAPIKey:           getEnv("ALERIA_API_KEY", ""),
		BridgeInboundPattern:    getEnv("BRIDGE_INBOUND_PATTERN", `^BRIDGE_.*_IN(_\d+)?$`),
		BridgeNodeIDs:           getStringSliceEnv("BRIDGE_NODE_IDS", []string{"ru-white", "ru-bride"}),
		BridgeCorrelationWindow: getDurationEnv("BRIDGE_CORRELATION_WINDOW", 15*time.Second),
		RedisAddr:               getEnv("REDIS_ADDR", ""),
		RedisPassword:           getEnv("REDIS_PASSWORD", ""),
		RedisKeyPrefix:          getEnv("REDIS_KEY_PREFIX", "analyzer:"),
	}
}

func getStringSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}
	return defaultValue
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if dur, err := time.ParseDuration(value); err == nil {
			return dur
		}
	}
	return defaultValue
}
