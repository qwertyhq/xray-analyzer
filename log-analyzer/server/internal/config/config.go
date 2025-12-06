package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds server configuration
type Config struct {
	// Server settings
	ListenAddr string
	DBPath     string

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
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		ListenAddr:             getEnv("LISTEN_ADDR", ":8080"),
		DBPath:                 getEnv("DB_PATH", "./data/analyzer.db"),
		BlacklistPath:          getEnv("BLACKLIST_PATH", "./blacklist.txt"),
		BlacklistReload:        getDurationEnv("BLACKLIST_RELOAD", 5*time.Minute),
		BlacklistRemoteURL:     getEnv("BLACKLIST_REMOTE_URL", ""),
		TelegramEnabled:        getBoolEnv("TELEGRAM_ENABLED", false),
		TelegramToken:          getEnv("TELEGRAM_TOKEN", ""),
		TelegramChatID:         getEnv("TELEGRAM_CHAT_ID", ""),
		SuspiciousRequestCount: getIntEnv("SUSPICIOUS_REQUEST_COUNT", 5),
		SuspiciousTimeWindow:   getDurationEnv("SUSPICIOUS_TIME_WINDOW", 1*time.Hour),
	}
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
