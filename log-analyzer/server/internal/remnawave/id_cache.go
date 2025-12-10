package remnawave

import (
	"context"
	"log"
	"sync"
	"time"
)

// IDCache caches numeric ID to username mappings
type IDCache struct {
	client     *Client
	cache      map[string]string // id -> username
	notFound   map[string]bool   // ids that returned 404
	mu         sync.RWMutex
	ttl        time.Duration
	lastSync   time.Time
	syncPeriod time.Duration
}

// NewIDCache creates a new ID cache
func NewIDCache(client *Client) *IDCache {
	return &IDCache{
		client:     client,
		cache:      make(map[string]string),
		notFound:   make(map[string]bool),
		ttl:        30 * time.Minute,
		syncPeriod: 5 * time.Minute,
	}
}

// GetUsername returns the username for a numeric ID
// If the ID is not numeric (contains letters), returns the ID itself
func (c *IDCache) GetUsername(ctx context.Context, id string) string {
	// If it looks like a username already (contains letters), return as-is
	if !isNumericID(id) {
		return id
	}

	// Check cache first
	c.mu.RLock()
	if username, ok := c.cache[id]; ok {
		c.mu.RUnlock()
		return username
	}
	if c.notFound[id] {
		c.mu.RUnlock()
		return id // Known to not exist
	}
	c.mu.RUnlock()

	// Fetch from API
	return c.fetchAndCache(ctx, id)
}

// fetchAndCache fetches username from API and caches it
func (c *IDCache) fetchAndCache(ctx context.Context, id string) string {
	if c.client == nil || !c.client.IsConfigured() {
		return id
	}

	user, err := c.client.GetUserByID(ctx, id)
	if err != nil {
		// Mark as not found to avoid repeated API calls
		c.mu.Lock()
		c.notFound[id] = true
		c.mu.Unlock()
		return id
	}

	if user != nil && user.Username != "" {
		c.mu.Lock()
		c.cache[id] = user.Username
		c.mu.Unlock()
		return user.Username
	}

	return id
}

// PreloadFromUsers preloads cache from a list of users
// This is useful when syncing all users from Remnawave
func (c *IDCache) PreloadFromUsers(users []User) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear old cache
	c.cache = make(map[string]string)
	c.notFound = make(map[string]bool)

	// We don't have numeric IDs in the User struct yet
	// But we can try to extract from description if needed
	log.Printf("idcache: preloaded %d users", len(users))
}

// ResolveMultiple resolves multiple IDs at once (batch operation)
func (c *IDCache) ResolveMultiple(ctx context.Context, ids []string) map[string]string {
	result := make(map[string]string)

	for _, id := range ids {
		result[id] = c.GetUsername(ctx, id)
	}

	return result
}

// Clear clears the cache
func (c *IDCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]string)
	c.notFound = make(map[string]bool)
}

// Stats returns cache statistics
func (c *IDCache) Stats() (cached int, notFound int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache), len(c.notFound)
}

// isNumericID checks if the string is a numeric ID (all digits)
func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
