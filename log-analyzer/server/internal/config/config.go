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
	PostgresURL    string
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

	// AI assistant settings — OpenAI-compatible chat-completions endpoint.
	// Works with OpenAI, Aleria, Together, OpenRouter, local llama.cpp/vLLM.
	OpenAIAPIKey  string
	OpenAIBaseURL string
	OpenAIModel   string

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

	// NodeRemnaMap wires agent NODE_ID values to Remnawave node names so
	// /api/nodes can surface the live online-user count Remnawave already
	// tracks (XTLS active sessions) instead of inferring it from access-log
	// recency. Format: "est-1=Estonia,poland-1=Poland,...". Empty disables.
	NodeRemnaMap map[string]string
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		ListenAddr:             getEnv("LISTEN_ADDR", ":8080"),
		DBPath:                 getEnv("DB_PATH", "./data/analyzer.db"),
		PostgresURL:            getEnv("POSTGRES_URL", "postgres://xray_analyzer:changeme@analyzer-postgres:5432/xray_analyzer?sslmode=disable"),
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
		// OPENAI_* are the canonical env names; ALERIA_API_KEY is kept as
		// a back-compat fallback so existing deployments don't break.
		OpenAIAPIKey:           getEnv("OPENAI_API_KEY", getEnv("ALERIA_API_KEY", "")),
		OpenAIBaseURL:          getEnv("OPENAI_BASE_URL", ""),
		OpenAIModel:            getEnv("OPENAI_MODEL", ""),
		BridgeInboundPattern:    getEnv("BRIDGE_INBOUND_PATTERN", `^BRIDGE_.*_IN(_\d+)?$`),
		BridgeNodeIDs:           getStringSliceEnv("BRIDGE_NODE_IDS", []string{"ru-white", "ru-bride"}),
		BridgeCorrelationWindow: getDurationEnv("BRIDGE_CORRELATION_WINDOW", 15*time.Second),
		RedisAddr:               getEnv("REDIS_ADDR", ""),
		RedisPassword:           getEnv("REDIS_PASSWORD", ""),
		RedisKeyPrefix:          getEnv("REDIS_KEY_PREFIX", "analyzer:"),
		NodeRemnaMap: getMapEnv("NODE_REMNA_MAP", map[string]string{
			"est-1":         "Estonia",
			"poland-1":      "Poland",
			"netherlands-1": "Netherlands",
			"finland-1":     "Finland",
			"usa-1":         "United States",
			"germany-1":     "Germany",
			"ru-white":      "RU-White Bride",
			"ru-bride":      "RU Bride",
		}),
	}
}

// getMapEnv parses a "k1=v1,k2=v2" env var into a map.
func getMapEnv(key string, defaultValue map[string]string) map[string]string {
	raw := os.Getenv(key)
	if raw == "" {
		return defaultValue
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k != "" && v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return defaultValue
	}
	return out
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
