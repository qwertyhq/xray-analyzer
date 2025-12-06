package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all agent configuration
type Config struct {
	// Node identification
	NodeID string

	// Log file settings
	LogFilePath string

	// WebSocket server settings
	ServerURL string
	AuthToken string

	// Batching settings
	BatchSize    int
	BatchTimeout time.Duration

	// Reconnection settings
	ReconnectInterval    time.Duration
	MaxReconnectInterval time.Duration
	ReconnectMultiplier  float64

	// Compression
	EnableCompression bool
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *Config {
	return &Config{
		NodeID:               getEnv("NODE_ID", "node-1"),
		LogFilePath:          getEnv("LOG_FILE_PATH", "/var/log/remnanode/access.log"),
		ServerURL:            getEnv("SERVER_URL", "ws://localhost:8080/ws/logs"),
		AuthToken:            getEnv("AUTH_TOKEN", ""),
		BatchSize:            getEnvInt("BATCH_SIZE", 1000),
		BatchTimeout:         getEnvDuration("BATCH_TIMEOUT", 5*time.Second),
		ReconnectInterval:    getEnvDuration("RECONNECT_INTERVAL", 1*time.Second),
		MaxReconnectInterval: getEnvDuration("MAX_RECONNECT_INTERVAL", 30*time.Second),
		ReconnectMultiplier:  getEnvFloat("RECONNECT_MULTIPLIER", 1.5),
		EnableCompression:    getEnvBool("ENABLE_COMPRESSION", true),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
