package correlation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/xray-log-analyzer/server/internal/remnawave"
	"github.com/xray-log-analyzer/server/internal/storage"
)

// Service handles user correlation analysis
type Service struct {
	storage   *storage.Storage
	remnaSync *remnawave.SyncService

	// Rate limiting for profile updates
	mu             sync.Mutex
	lastUpdates    map[string]time.Time
	updateInterval time.Duration
}

// NewService creates a new correlation service
func NewService(store *storage.Storage, remnaSync *remnawave.SyncService) *Service {
	return &Service{
		storage:        store,
		remnaSync:      remnaSync,
		lastUpdates:    make(map[string]time.Time),
		updateInterval: 5 * time.Minute,
	}
}

// ProcessConnection records a user connection for correlation analysis
func (s *Service) ProcessConnection(ctx context.Context, userEmail, ip, hwid, userAgent, nodeID string) error {
	if userEmail == "" {
		return nil
	}

	// Record IP -> User mapping
	if ip != "" {
		if err := s.storage.RecordIPUserMapping(ctx, ip, userEmail, nodeID); err != nil {
			log.Printf("[correlation] failed to record IP mapping: %v", err)
		}
	}

	// Record HWID -> User mapping
	if hwid != "" {
		platform := extractPlatform(userAgent)
		if err := s.storage.RecordHWIDUserMapping(ctx, hwid, userEmail, platform); err != nil {
			log.Printf("[correlation] failed to record HWID mapping: %v", err)
		}
	}

	// Record unique fingerprint
	if ip != "" {
		if err := s.storage.RecordUserFingerprint(ctx, userEmail, ip, hwid, userAgent, nodeID); err != nil {
			log.Printf("[correlation] failed to record fingerprint: %v", err)
		}
	}

	// Trigger profile update (rate limited)
	s.triggerProfileUpdate(ctx, userEmail)

	return nil
}

// triggerProfileUpdate updates user's AI profile (rate limited)
func (s *Service) triggerProfileUpdate(ctx context.Context, userEmail string) {
	s.mu.Lock()
	lastUpdate, exists := s.lastUpdates[userEmail]
	if exists && time.Since(lastUpdate) < s.updateInterval {
		s.mu.Unlock()
		return
	}
	s.lastUpdates[userEmail] = time.Now()
	// Opportunistic cleanup: remove stale entries (avoid unbounded growth).
	// Only sweep when map grows large to avoid repeated O(n) scans.
	if len(s.lastUpdates) > 10000 {
		cutoff := time.Now().Add(-2 * s.updateInterval)
		for k, v := range s.lastUpdates {
			if v.Before(cutoff) {
				delete(s.lastUpdates, k)
			}
		}
	}
	s.mu.Unlock()

	// Update in background
	go func() {
		if err := s.UpdateUserAIProfile(context.Background(), userEmail); err != nil {
			log.Printf("[correlation] failed to update profile for %s: %v", userEmail, err)
		}
	}()
}

// UpdateUserAIProfile rebuilds the AI profile for a user
func (s *Service) UpdateUserAIProfile(ctx context.Context, userEmail string) error {
	profile := &storage.UserAIProfile{
		UserEmail:        userEmail,
		ThreatCategories: make(map[string]int),
	}

	// Get fingerprints to calculate unique IPs/HWIDs
	fingerprints, err := s.storage.GetUserFingerprints(ctx, userEmail)
	if err == nil {
		ips := make(map[string]bool)
		hwids := make(map[string]bool)
		nodes := make(map[string]bool)

		for _, f := range fingerprints {
			ips[f.IPAddress] = true
			if f.HWID != "" {
				hwids[f.HWID] = true
			}
			if f.NodeID != "" {
				nodes[f.NodeID] = true
			}
			profile.TotalSessions += f.SessionCount
		}

		profile.UniqueIPs = len(ips)
		profile.UniqueHWIDs = len(hwids)
		profile.UniqueNodes = len(nodes)
		profile.UniqueFingerprints = len(fingerprints)
	}

	// Get shared users
	sharedIPUsers, err := s.storage.GetSharedIPUsers(ctx, userEmail)
	if err == nil {
		// Count unique users sharing IPs
		uniqueUsers := make(map[string]bool)
		for _, u := range sharedIPUsers {
			uniqueUsers[u.UserEmail] = true
		}
		profile.SharedIPUsers = len(uniqueUsers)
	}

	sharedHWIDUsers, err := s.storage.GetSharedHWIDUsers(ctx, userEmail)
	if err == nil {
		uniqueUsers := make(map[string]bool)
		for _, u := range sharedHWIDUsers {
			uniqueUsers[u.UserEmail] = true
		}
		profile.SharedHWIDUsers = len(uniqueUsers)
	}

	// Get threat stats from user_threat_stats table
	// (We'll aggregate this from existing data)
	profile.TotalThreatMatches = s.getThreatMatchCount(ctx, userEmail)
	profile.ThreatCategories = s.getThreatCategories(ctx, userEmail)

	// Get activity stats from user_stats
	profile.TotalRequests, profile.FirstSeen, profile.LastSeen = s.getActivityStats(ctx, userEmail)

	// Calculate active days
	if !profile.FirstSeen.IsZero() && !profile.LastSeen.IsZero() {
		profile.ActiveDays = int(profile.LastSeen.Sub(profile.FirstSeen).Hours()/24) + 1
	}

	// Get unique countries from user_locations
	profile.UniqueCountries = s.getUniqueCountries(ctx, userEmail)

	// Enrich with Remnawave data
	if s.remnaSync != nil {
		// Try to find user by ID (if userEmail is numeric) or by username
		if remnaUser := s.remnaSync.GetUserByIDOrUsername(userEmail); remnaUser != nil {
			profile.RemnaUsername = remnaUser.Username
			profile.RemnaUUID = remnaUser.UUID
			profile.RemnaStatus = remnaUser.Status
			profile.RemnaTrafficUsed = remnaUser.UsedTrafficBytes
			profile.RemnaTrafficLimit = remnaUser.TrafficLimitBytes
			profile.RemnaExpireAt = &remnaUser.ExpireAt
			if remnaUser.HwidDeviceLimit != nil {
				profile.RemnaHWIDLimit = *remnaUser.HwidDeviceLimit
			}
			// Get HWID device count from sync service
			devices := s.remnaSync.GetUserHwidDevices(remnaUser.UUID)
			profile.RemnaHWIDDevices = len(devices)
		}
	}

	// Calculate risk score
	profile.RiskScore, profile.RiskFactors = s.calculateRiskScore(profile)

	// Generate cluster ID if user shares resources
	if profile.SharedIPUsers > 0 || profile.SharedHWIDUsers > 0 {
		profile.ClusterIDs = s.generateClusterIDs(ctx, userEmail)
	}

	profile.LastSeen = time.Now()

	return s.storage.UpsertUserAIProfile(ctx, profile)
}

// getThreatMatchCount gets total threat matches for a user
func (s *Service) getThreatMatchCount(ctx context.Context, userEmail string) int {
	var count int
	s.storage.DB().QueryRowContext(ctx, `
		SELECT COALESCE(SUM(match_count), 0) FROM user_threat_stats WHERE user_email = ?
	`, userEmail).Scan(&count)
	return count
}

// getThreatCategories gets threat categories breakdown for a user
func (s *Service) getThreatCategories(ctx context.Context, userEmail string) map[string]int {
	result := make(map[string]int)
	rows, err := s.storage.DB().QueryContext(ctx, `
		SELECT threat_type, match_count FROM user_threat_stats WHERE user_email = ?
	`, userEmail)
	if err != nil {
		return result
	}
	defer rows.Close()

	for rows.Next() {
		var threatType string
		var count int
		if err := rows.Scan(&threatType, &count); err == nil {
			result[threatType] = count
		}
	}
	return result
}

// getActivityStats gets basic activity stats from user_stats
func (s *Service) getActivityStats(ctx context.Context, userEmail string) (totalRequests int, firstSeen, lastSeen time.Time) {
	s.storage.DB().QueryRowContext(ctx, `
		SELECT COALESCE(SUM(total_requests), 0), MIN(last_seen), MAX(last_seen)
		FROM user_stats WHERE user_email = ?
	`, userEmail).Scan(&totalRequests, &firstSeen, &lastSeen)
	return
}

// getUniqueCountries gets count of unique countries for a user
func (s *Service) getUniqueCountries(ctx context.Context, userEmail string) int {
	var count int
	s.storage.DB().QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT country_code) FROM user_locations WHERE user_email = ?
	`, userEmail).Scan(&count)
	return count
}

// calculateRiskScore calculates a risk score based on profile data
func (s *Service) calculateRiskScore(profile *storage.UserAIProfile) (int, []string) {
	score := 0
	var factors []string

	// Multiple IPs is normal for VPN users, but excessive is suspicious
	if profile.UniqueIPs > 50 {
		score += 15
		factors = append(factors, "excessive_unique_ips")
	} else if profile.UniqueIPs > 20 {
		score += 5
	}

	// Multiple HWIDs can indicate account sharing
	if profile.UniqueHWIDs > 5 {
		score += 20
		factors = append(factors, "multiple_hwids")
	} else if profile.UniqueHWIDs > 3 {
		score += 10
		factors = append(factors, "elevated_hwid_count")
	}

	// Sharing IP with other users
	if profile.SharedIPUsers > 10 {
		score += 25
		factors = append(factors, "highly_shared_ip")
	} else if profile.SharedIPUsers > 3 {
		score += 10
		factors = append(factors, "shared_ip")
	}

	// Sharing HWID with other users is very suspicious
	if profile.SharedHWIDUsers > 0 {
		score += 30
		factors = append(factors, "shared_hwid")
	}

	// Threat matches
	if profile.TotalThreatMatches > 100 {
		score += 30
		factors = append(factors, "high_threat_activity")
	} else if profile.TotalThreatMatches > 20 {
		score += 15
		factors = append(factors, "elevated_threat_activity")
	} else if profile.TotalThreatMatches > 5 {
		score += 5
	}

	// Multiple countries can be suspicious
	if profile.UniqueCountries > 10 {
		score += 15
		factors = append(factors, "many_countries")
	} else if profile.UniqueCountries > 5 {
		score += 5
	}

	// Remnawave-specific risks
	if profile.RemnaStatus == "DISABLED" || profile.RemnaStatus == "EXPIRED" {
		score += 10
		factors = append(factors, "account_inactive")
	}

	// HWID device limit exceeded
	if profile.RemnaHWIDLimit > 0 && profile.RemnaHWIDDevices > profile.RemnaHWIDLimit {
		score += 20
		factors = append(factors, "hwid_limit_exceeded")
	}

	// Traffic limit nearly exhausted
	if profile.RemnaTrafficLimit > 0 {
		usage := float64(profile.RemnaTrafficUsed) / float64(profile.RemnaTrafficLimit)
		if usage > 0.95 {
			score += 5
			factors = append(factors, "traffic_nearly_exhausted")
		}
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	return score, factors
}

// generateClusterIDs generates cluster IDs based on shared resources
func (s *Service) generateClusterIDs(ctx context.Context, userEmail string) []string {
	var clusterIDs []string
	seen := make(map[string]bool)

	// Cluster by shared IPs
	sharedIPUsers, _ := s.storage.GetSharedIPUsers(ctx, userEmail)
	for _, u := range sharedIPUsers {
		clusterID := generateClusterID("ip", u.SharedValue)
		if !seen[clusterID] {
			clusterIDs = append(clusterIDs, clusterID)
			seen[clusterID] = true
		}
	}

	// Cluster by shared HWIDs
	sharedHWIDUsers, _ := s.storage.GetSharedHWIDUsers(ctx, userEmail)
	for _, u := range sharedHWIDUsers {
		clusterID := generateClusterID("hwid", u.SharedValue)
		if !seen[clusterID] {
			clusterIDs = append(clusterIDs, clusterID)
			seen[clusterID] = true
		}
	}

	return clusterIDs
}

// generateClusterID creates a unique cluster ID
func generateClusterID(clusterType, value string) string {
	h := sha256.Sum256([]byte(clusterType + ":" + value))
	return clusterType + "_" + hex.EncodeToString(h[:8])
}

// extractPlatform extracts platform from user agent
func extractPlatform(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "mac"):
		return "macOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}

// RefreshAllProfiles rebuilds all user AI profiles (for background job)
func (s *Service) RefreshAllProfiles(ctx context.Context) error {
	log.Println("[correlation] starting full profile refresh...")
	start := time.Now()

	// Get all unique users from ip_user_map
	rows, err := s.storage.DB().QueryContext(ctx, `SELECT DISTINCT user_email FROM ip_user_map`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var users []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err == nil {
			users = append(users, email)
		}
	}

	// Update profiles
	updated := 0
	for _, email := range users {
		if err := s.UpdateUserAIProfile(ctx, email); err != nil {
			log.Printf("[correlation] failed to update %s: %v", email, err)
			continue
		}
		updated++
	}

	log.Printf("[correlation] profile refresh completed in %v, updated %d/%d users", time.Since(start), updated, len(users))
	return nil
}

// GetUserCorrelations returns all correlation data for a user
func (s *Service) GetUserCorrelations(ctx context.Context, userEmail string) (*UserCorrelations, error) {
	result := &UserCorrelations{
		UserEmail: userEmail,
	}

	// Get AI profile
	profile, err := s.storage.GetUserAIProfile(ctx, userEmail)
	if err != nil {
		return nil, err
	}
	result.Profile = profile

	// Get fingerprints
	fingerprints, err := s.storage.GetUserFingerprints(ctx, userEmail)
	if err == nil {
		result.Fingerprints = fingerprints
	}

	// Get shared IP users
	sharedIPUsers, err := s.storage.GetSharedIPUsers(ctx, userEmail)
	if err == nil {
		result.SharedIPUsers = sharedIPUsers
	}

	// Get shared HWID users
	sharedHWIDUsers, err := s.storage.GetSharedHWIDUsers(ctx, userEmail)
	if err == nil {
		result.SharedHWIDUsers = sharedHWIDUsers
	}

	// Get Remnawave data if available
	if s.remnaSync != nil {
		if remnaUser := s.remnaSync.GetUserByUsername(userEmail); remnaUser != nil {
			result.RemnaUser = remnaUser
			result.RemnaHWIDDevices = s.remnaSync.GetUserHwidDevices(remnaUser.UUID)
		}
	}

	return result, nil
}

// UserCorrelations contains all correlation data for a user
type UserCorrelations struct {
	UserEmail        string                    `json:"user_email"`
	Profile          *storage.UserAIProfile    `json:"profile"`
	Fingerprints     []storage.UserFingerprint `json:"fingerprints"`
	SharedIPUsers    []storage.SharedUserInfo  `json:"shared_ip_users"`
	SharedHWIDUsers  []storage.SharedUserInfo  `json:"shared_hwid_users"`
	RemnaUser        *remnawave.User           `json:"remna_user,omitempty"`
	RemnaHWIDDevices []remnawave.HwidDevice    `json:"remna_hwid_devices,omitempty"`
}
