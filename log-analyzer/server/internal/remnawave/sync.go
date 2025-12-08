package remnawave

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// SyncService handles periodic synchronization with Remnawave API
type SyncService struct {
	client       *Client
	syncInterval time.Duration

	// Cached data
	mu              sync.RWMutex
	users           map[string]*User        // by UUID
	usersByEmail    map[string]*User        // by email (lowercase)
	usersByUsername map[string]*User        // by username
	hwidDevices     map[string][]HwidDevice // by user UUID
	lastSync        time.Time

	// Callbacks for external consumers
	onSyncComplete func()
}

// NewSyncService creates a new sync service
func NewSyncService(client *Client, syncInterval time.Duration) *SyncService {
	return &SyncService{
		client:          client,
		syncInterval:    syncInterval,
		users:           make(map[string]*User),
		usersByEmail:    make(map[string]*User),
		usersByUsername: make(map[string]*User),
		hwidDevices:     make(map[string][]HwidDevice),
	}
}

// OnSyncComplete sets a callback to be called when sync completes
func (s *SyncService) OnSyncComplete(fn func()) {
	s.onSyncComplete = fn
}

// ForceSync triggers an immediate synchronization
func (s *SyncService) ForceSync(ctx context.Context) error {
	if !s.client.IsConfigured() {
		return fmt.Errorf("client not configured")
	}
	s.sync(ctx)
	return nil
}

// Start begins the periodic synchronization
func (s *SyncService) Start(ctx context.Context) {
	if !s.client.IsConfigured() {
		log.Println("[remnawave] client not configured, sync disabled")
		return
	}

	// Initial sync in background to not block server startup
	go s.sync(ctx)

	// Periodic sync
	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sync(ctx)
		}
	}
}

// sync performs a full synchronization
func (s *SyncService) sync(ctx context.Context) {
	log.Println("[remnawave] starting sync...")
	start := time.Now()

	// Sync users
	if err := s.syncUsers(ctx); err != nil {
		log.Printf("[remnawave] failed to sync users: %v", err)
	}

	// Sync HWID devices
	if err := s.syncHwidDevices(ctx); err != nil {
		log.Printf("[remnawave] failed to sync HWID devices: %v", err)
	}

	s.mu.Lock()
	s.lastSync = time.Now()
	s.mu.Unlock()

	log.Printf("[remnawave] sync completed in %v, users: %d, hwid records: %d",
		time.Since(start), len(s.users), s.countHwidDevices())

	if s.onSyncComplete != nil {
		s.onSyncComplete()
	}
}

// syncUsers fetches and caches all users
func (s *SyncService) syncUsers(ctx context.Context) error {
	resp, err := s.client.GetUsers(ctx)
	if err != nil {
		return err
	}

	users := make(map[string]*User)
	usersByEmail := make(map[string]*User)
	usersByUsername := make(map[string]*User)

	for i := range resp.Users {
		user := &resp.Users[i]

		// Parse Note/Description field
		if user.Description != nil && *user.Description != "" {
			user.ParsedNote = ParseNote(*user.Description)
		}

		users[user.UUID] = user

		if user.Email != nil && *user.Email != "" {
			usersByEmail[normalizeEmail(*user.Email)] = user
		}
		if user.Username != "" {
			usersByUsername[user.Username] = user
		}
	}

	s.mu.Lock()
	s.users = users
	s.usersByEmail = usersByEmail
	s.usersByUsername = usersByUsername
	s.mu.Unlock()

	return nil
}

// syncHwidDevices fetches and caches HWID devices
func (s *SyncService) syncHwidDevices(ctx context.Context) error {
	devices := make(map[string][]HwidDevice)
	start := 0
	pageSize := 1000

	for {
		resp, err := s.client.GetAllHwidDevices(ctx, start, pageSize)
		if err != nil {
			return err
		}

		for _, d := range resp.Devices {
			devices[d.UserUUID] = append(devices[d.UserUUID], d)
		}

		if len(resp.Devices) < pageSize {
			break
		}
		start += pageSize
	}

	s.mu.Lock()
	s.hwidDevices = devices
	s.mu.Unlock()

	return nil
}

// countHwidDevices returns total number of HWID devices
func (s *SyncService) countHwidDevices() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, devices := range s.hwidDevices {
		count += len(devices)
	}
	return count
}

// GetUserByUUID returns a cached user by UUID
func (s *SyncService) GetUserByUUID(uuid string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[uuid]
}

// GetUserByEmail returns a cached user by email
func (s *SyncService) GetUserByEmail(email string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usersByEmail[normalizeEmail(email)]
}

// GetUserByUsername returns a cached user by username
func (s *SyncService) GetUserByUsername(username string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usersByUsername[username]
}

// GetUserHwidDevices returns cached HWID devices for a user
func (s *SyncService) GetUserHwidDevices(userUUID string) []HwidDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hwidDevices[userUUID]
}

// ClearUserHwidDevices deletes all HWID devices for a user via API and updates cache
func (s *SyncService) ClearUserHwidDevices(ctx context.Context, userUUID string) error {
	log.Printf("[remnawave] ClearUserHwidDevices called for user %s", userUUID)

	// Call API to delete all HWID devices
	resp, err := s.client.DeleteAllUserHwidDevices(ctx, userUUID)
	if err != nil {
		log.Printf("[remnawave] ERROR clearing HWID devices for user %s: %v", userUUID, err)
		return err
	}

	log.Printf("[remnawave] API response: total=%d devices remaining", resp.Total)

	// Update local cache
	s.mu.Lock()
	delete(s.hwidDevices, userUUID)
	s.mu.Unlock()

	log.Printf("[remnawave] cleared all HWID devices for user %s", userUUID)
	return nil
}

// GetAllUsers returns all cached users
func (s *SyncService) GetAllUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		result = append(result, u)
	}
	return result
}

// GetLastSyncTime returns the time of the last successful sync
func (s *SyncService) GetLastSyncTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSync
}

// GetStats returns sync service statistics
func (s *SyncService) GetStats() SyncStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return SyncStats{
		TotalUsers:       len(s.users),
		TotalHwidDevices: s.countHwidDevicesUnsafe(),
		LastSync:         s.lastSync,
		IsConfigured:     s.client.IsConfigured(),
	}
}

func (s *SyncService) countHwidDevicesUnsafe() int {
	count := 0
	for _, devices := range s.hwidDevices {
		count += len(devices)
	}
	return count
}

// SyncStats represents sync service statistics
type SyncStats struct {
	TotalUsers       int       `json:"total_users"`
	TotalHwidDevices int       `json:"total_hwid_devices"`
	LastSync         time.Time `json:"last_sync"`
	IsConfigured     bool      `json:"is_configured"`
}

// normalizeEmail converts email to lowercase for comparison
func normalizeEmail(email string) string {
	return email
}
