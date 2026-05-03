package remnawave

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/xray-log-analyzer/server/internal/rediscache"
)

// StorageWriter interface for writing Remnawave data to storage
type StorageWriter interface {
	UpsertRemnaUser(ctx context.Context, user *RemnaUserData) error
	UpsertRemnaHwidDevice(ctx context.Context, device *RemnaHwidData) error
	UpsertRemnaNode(ctx context.Context, node *RemnaNodeData) error
	UpdateRemnaUserHwidCounts(ctx context.Context) error
	// PruneRemnaUsers removes rows whose uuid is not in liveUUIDs. Called
	// at the end of a successful syncUsers() so that users deleted on the
	// Remnawave panel disappear from analyzer counts. Returns the number
	// of rows deleted.
	PruneRemnaUsers(ctx context.Context, liveUUIDs []string) (int, error)
}

// RemnaUserData represents user data for storage
type RemnaUserData struct {
	UUID                 string
	ID                   int64
	ShortUUID            string
	Username             string
	Email                *string
	Status               string
	TrafficLimitBytes    int64
	UsedTrafficBytes     int64
	LifetimeTrafficBytes int64
	TrafficLimitStrategy string
	ExpireAt             *time.Time
	OnlineAt             *time.Time
	FirstConnectedAt     *time.Time
	HwidDeviceLimit      *int
	HwidDeviceCount      int
	TelegramID           *int64
	Description          *string
	Tag                  *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	SyncedAt             time.Time
	RealName             *string
	Phone                *string
	TelegramUser         *string
	PaymentInfo          *string
	Plan                 *string
	USID                 *string // Xray log user ID from US_ID: <number> in description
}

// RemnaHwidData represents HWID device data for storage
type RemnaHwidData struct {
	Hwid         string
	UserUUID     string
	Username     string
	Platform     *string
	OSVersion    *string
	DeviceModel  *string
	AppVersion   *string
	FirstSeenAt  time.Time
	LastActiveAt *time.Time
	SyncedAt     time.Time
}

// RemnaNodeData represents node data for storage
type RemnaNodeData struct {
	UUID           string
	Name           string
	Address        string
	Port           int
	IsConnected    bool
	IsDisabled     bool
	IsTrafficTrack bool
	TrafficTotal   int64
	TrafficUsed    int64
	UsersOnline    int
	CountryCode    string
	SyncedAt       time.Time
}

// SyncService handles periodic synchronization with Remnawave API
type SyncService struct {
	client       *Client
	syncInterval time.Duration
	storage      StorageWriter

	// ID Cache for resolving numeric IDs to usernames
	idCache *IDCache

	// Cached data
	mu              sync.RWMutex
	users           map[string]*User        // by UUID
	usersByEmail    map[string]*User        // by email (lowercase)
	usersByUsername map[string]*User        // by username
	usersByID       map[int64]*User         // by numeric ID
	hwidDevices     map[string][]HwidDevice // by user UUID
	lastSync        time.Time

	// Callbacks for external consumers
	onSyncComplete func()
}

// NewSyncService creates a new sync service
func NewSyncService(client *Client, syncInterval time.Duration) *SyncService {
	svc := &SyncService{
		client:          client,
		syncInterval:    syncInterval,
		users:           make(map[string]*User),
		usersByEmail:    make(map[string]*User),
		usersByUsername: make(map[string]*User),
		usersByID:       make(map[int64]*User),
		hwidDevices:     make(map[string][]HwidDevice),
	}
	svc.idCache = NewIDCache(client)
	return svc
}

// SetStorage sets the storage writer for persisting data
func (s *SyncService) SetStorage(storage StorageWriter) {
	s.storage = storage
}

// SetIDCacheRedis wires the persistent L2 cache into the id cache. Nil is
// allowed and disables L2 (the L1 map keeps working).
func (s *SyncService) SetIDCacheRedis(r *rediscache.Client) {
	if s.idCache != nil {
		s.idCache.SetRedis(r)
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

	// Update HWID counts in user table after syncing devices
	if s.storage != nil {
		if err := s.storage.UpdateRemnaUserHwidCounts(ctx); err != nil {
			log.Printf("[remnawave] failed to update HWID counts: %v", err)
		}
	}

	// Sync nodes
	if err := s.syncNodes(ctx); err != nil {
		log.Printf("[remnawave] failed to sync nodes: %v", err)
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
	usersByID := make(map[int64]*User)
	now := time.Now()

	for i := range resp.Users {
		user := &resp.Users[i]

		// Populate legacy fields from nested UserTraffic (API v2.3.x)
		user.PopulateFromTraffic()

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
		if user.ID > 0 {
			usersByID[user.ID] = user
		}

		// Persist to storage if configured
		if s.storage != nil {
			userData := &RemnaUserData{
				UUID:                 user.UUID,
				ID:                   user.ID,
				ShortUUID:            user.ShortUUID,
				Username:             user.Username,
				Email:                user.Email,
				Status:               user.Status,
				TrafficLimitBytes:    user.TrafficLimitBytes,
				UsedTrafficBytes:     user.UsedTrafficBytes,
				LifetimeTrafficBytes: user.LifetimeUsedTraffic,
				TrafficLimitStrategy: user.TrafficLimitStrategy,
				ExpireAt:             &user.ExpireAt,
				OnlineAt:             user.OnlineAt,
				FirstConnectedAt:     user.FirstConnectedAt,
				HwidDeviceLimit:      user.HwidDeviceLimit,
				HwidDeviceCount:      0, // Updated after HWID sync
				TelegramID:           user.TelegramID,
				Description:          user.Description,
				Tag:                  user.Tag,
				CreatedAt:            user.CreatedAt,
				UpdatedAt:            user.UpdatedAt,
				SyncedAt:             now,
			}

			// Add parsed note fields
			if user.ParsedNote != nil {
				if user.ParsedNote.RealName != "" {
					userData.RealName = &user.ParsedNote.RealName
				}
				if user.ParsedNote.Phone != "" {
					userData.Phone = &user.ParsedNote.Phone
				}
				if user.ParsedNote.TelegramUser != "" {
					userData.TelegramUser = &user.ParsedNote.TelegramUser
				}
				if user.ParsedNote.PaymentInfo != "" {
					userData.PaymentInfo = &user.ParsedNote.PaymentInfo
				}
				if user.ParsedNote.Plan != "" {
					userData.Plan = &user.ParsedNote.Plan
				}
				if user.ParsedNote.USID != "" {
					userData.USID = &user.ParsedNote.USID
				}
			}

			if err := s.storage.UpsertRemnaUser(ctx, userData); err != nil {
				log.Printf("[remnawave] failed to persist user %s: %v", user.Username, err)
			}
		}
	}

	s.mu.Lock()
	s.users = users
	s.usersByEmail = usersByEmail
	s.usersByUsername = usersByUsername
	s.usersByID = usersByID
	s.mu.Unlock()

	// Prune storage rows for users that no longer exist in Remnawave.
	// Skipped if no users were fetched — guards against pruning
	// everything when GetUsers returns empty due to a transient error
	// that didn't surface as an err.
	if s.storage != nil && len(users) > 0 {
		liveUUIDs := make([]string, 0, len(users))
		for u := range users {
			liveUUIDs = append(liveUUIDs, u)
		}
		if deleted, perr := s.storage.PruneRemnaUsers(ctx, liveUUIDs); perr != nil {
			log.Printf("[remnawave] prune remna_users failed: %v", perr)
		} else if deleted > 0 {
			log.Printf("[remnawave] pruned %d stale remna_users rows", deleted)
		}
	}

	return nil
}

// syncHwidDevices fetches and caches HWID devices
func (s *SyncService) syncHwidDevices(ctx context.Context) error {
	devices := make(map[string][]HwidDevice)
	start := 0
	pageSize := 1000
	now := time.Now()

	// Track device count per user for updating user records
	userDeviceCounts := make(map[string]int)

	for {
		resp, err := s.client.GetAllHwidDevices(ctx, start, pageSize)
		if err != nil {
			return err
		}

		for _, d := range resp.Devices {
			devices[d.UserUUID] = append(devices[d.UserUUID], d)
			userDeviceCounts[d.UserUUID]++

			// Persist to storage if configured
			if s.storage != nil {
				// Get username from cached users
				username := ""
				s.mu.RLock()
				if user, ok := s.users[d.UserUUID]; ok {
					username = user.Username
				}
				s.mu.RUnlock()

				hwidData := &RemnaHwidData{
					Hwid:         d.Hwid,
					UserUUID:     d.UserUUID,
					Username:     username,
					Platform:     d.Platform,
					OSVersion:    d.OSVersion,
					DeviceModel:  d.DeviceModel,
					AppVersion:   nil, // Not in API response
					FirstSeenAt:  d.CreatedAt,
					LastActiveAt: &d.UpdatedAt,
					SyncedAt:     now,
				}

				if err := s.storage.UpsertRemnaHwidDevice(ctx, hwidData); err != nil {
					log.Printf("[remnawave] failed to persist hwid device: %v", err)
				}
			}
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

// syncNodes fetches and persists node data
func (s *SyncService) syncNodes(ctx context.Context) error {
	if s.storage == nil {
		return nil // Skip if no storage configured
	}

	nodes, err := s.client.GetNodes(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, node := range nodes {
		var port int
		var trafficTotal, trafficUsed int64
		var usersOnline int
		if node.Port != nil {
			port = *node.Port
		}
		if node.TrafficLimitBytes != nil {
			trafficTotal = *node.TrafficLimitBytes
		}
		if node.TrafficUsedBytes != nil {
			trafficUsed = *node.TrafficUsedBytes
		}
		if node.UsersOnline != nil {
			usersOnline = *node.UsersOnline
		}

		nodeData := &RemnaNodeData{
			UUID:           node.UUID,
			Name:           node.Name,
			Address:        node.Address,
			Port:           port,
			IsConnected:    node.IsConnected,
			IsDisabled:     node.IsDisabled,
			IsTrafficTrack: false, // Поля нет в API
			TrafficTotal:   trafficTotal,
			TrafficUsed:    trafficUsed,
			UsersOnline:    usersOnline,
			CountryCode:    node.CountryCode,
			SyncedAt:       now,
		}

		if err := s.storage.UpsertRemnaNode(ctx, nodeData); err != nil {
			log.Printf("[remnawave] failed to persist node %s: %v", node.Name, err)
		}
	}

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

// GetUserByID returns a cached user by numeric ID
func (s *SyncService) GetUserByID(id int64) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usersByID[id]
}

// GetUserByIDOrUsername returns a user by UUID, numeric ID, or username.
// After the schema v2 refactor, storage tables hold user_email as a real
// Remnawave UUID (resolved via remna_users.id/us_id at write time), so the
// UUID lookup path is the common case.
func (s *SyncService) GetUserByIDOrUsername(idOrUsername string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try as UUID first (post-v2 storage path)
	if user := s.users[idOrUsername]; user != nil {
		return user
	}

	// Try as numeric ID
	if id, err := strconv.ParseInt(idOrUsername, 10, 64); err == nil {
		if user := s.usersByID[id]; user != nil {
			return user
		}
	}

	// Try as username
	return s.usersByUsername[idOrUsername]
}

// ResolveUsername resolves a numeric ID or username to the actual username
// If the input is a numeric ID, it looks up the username via Remnawave API
// If the input already looks like a username, returns it as-is
func (s *SyncService) ResolveUsername(ctx context.Context, idOrUsername string) string {
	// Try local cache first (usersByID)
	if user := s.GetUserByIDOrUsername(idOrUsername); user != nil {
		return user.Username
	}

	// Fallback to idCache (makes API calls if needed)
	if s.idCache != nil {
		return s.idCache.GetUsername(ctx, idOrUsername)
	}
	return idOrUsername
}

// ResolveUsernames resolves multiple IDs/usernames at once
func (s *SyncService) ResolveUsernames(ctx context.Context, ids []string) map[string]string {
	result := make(map[string]string)

	for _, id := range ids {
		// Try local cache first
		if user := s.GetUserByIDOrUsername(id); user != nil {
			result[id] = user.Username
		} else if s.idCache != nil {
			result[id] = s.idCache.GetUsername(ctx, id)
		} else {
			result[id] = id
		}
	}

	return result
}

// GetIDCacheStats returns ID cache statistics
func (s *SyncService) GetIDCacheStats() (cached, notFound int) {
	if s.idCache == nil {
		return 0, 0
	}
	return s.idCache.Stats()
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

// UserHwidCount represents a user with their HWID device count
type UserHwidCount struct {
	User        *User
	DeviceCount int
	Devices     []HwidDevice
}

// GetTopUsersByHwid returns users sorted by HWID device count (descending)
func (s *SyncService) GetTopUsersByHwid(limit int) []UserHwidCount {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build list of users with their device counts
	var result []UserHwidCount
	for userUUID, devices := range s.hwidDevices {
		if len(devices) == 0 {
			continue
		}
		user := s.users[userUUID]
		if user == nil {
			continue
		}
		result = append(result, UserHwidCount{
			User:        user,
			DeviceCount: len(devices),
			Devices:     devices,
		})
	}

	// Sort by device count descending
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].DeviceCount > result[i].DeviceCount {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	// Limit results
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result
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
