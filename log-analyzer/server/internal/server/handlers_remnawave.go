package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// RemnawaveStatsResponse represents the response for /api/remnawave/stats
type RemnawaveStatsResponse struct {
	Enabled            bool               `json:"enabled"`
	TotalUsers         int                `json:"totalUsers"`
	ActiveUsers        int                `json:"activeUsers"`
	DisabledUsers      int                `json:"disabledUsers"`
	LimitedUsers       int                `json:"limitedUsers"`
	ExpiredUsers       int                `json:"expiredUsers"`
	TotalTrafficUsed   int64              `json:"totalTrafficUsed"`
	OnlineLastHour     int                `json:"onlineLastHour"`
	OnlineLast24h      int                `json:"onlineLast24h"`
	NeverOnline        int                `json:"neverOnline"`
	UsersWithHwidLimit int                `json:"usersWithHwidLimit"`
	HwidStats          *HwidStatsResponse `json:"hwidStats,omitempty"`
	LastSync           string             `json:"lastSync"`
}

type HwidStatsResponse struct {
	TotalDevices      int            `json:"totalDevices"`
	UniqueUsers       int            `json:"uniqueUsers"`
	PlatformBreakdown map[string]int `json:"platformBreakdown"`
}

// handleRemnawaveSync triggers a force synchronization
func (s *Server) handleRemnawaveSync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.remnawave == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Remnawave not configured",
		})
		return
	}

	// Trigger force sync
	if err := s.remnawave.ForceSync(r.Context()); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	stats := s.remnawave.GetStats()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"total_users": stats.TotalUsers,
		"total_hwids": stats.TotalHwidDevices,
		"last_sync":   stats.LastSync.Format("2006-01-02T15:04:05Z"),
	})
}

// handleRemnawaveStats returns Remnawave sync statistics
func (s *Server) handleRemnawaveStats(w http.ResponseWriter, r *http.Request) {
	if s.remnawave == nil {
		json.NewEncoder(w).Encode(RemnawaveStatsResponse{Enabled: false})
		return
	}

	stats := s.remnawave.GetStats()
	lastSync := ""
	if !stats.LastSync.IsZero() {
		lastSync = stats.LastSync.Format("2006-01-02T15:04:05Z")
	}

	// Get all users to calculate detailed stats
	users := s.remnawave.GetAllUsers()

	response := RemnawaveStatsResponse{
		Enabled:    stats.IsConfigured,
		TotalUsers: len(users),
		LastSync:   lastSync,
	}

	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)
	oneDayAgo := now.Add(-24 * time.Hour)

	platformCounts := make(map[string]int)
	uniqueHwidUsers := make(map[string]bool)
	totalDevices := 0

	for _, u := range users {
		// Status counts
		switch u.Status {
		case "ACTIVE":
			response.ActiveUsers++
		case "DISABLED":
			response.DisabledUsers++
		case "LIMITED":
			response.LimitedUsers++
		case "EXPIRED":
			response.ExpiredUsers++
		}

		// Traffic
		response.TotalTrafficUsed += u.UsedTrafficBytes

		// Online activity
		if u.OnlineAt == nil {
			response.NeverOnline++
		} else {
			if u.OnlineAt.After(oneHourAgo) {
				response.OnlineLastHour++
			}
			if u.OnlineAt.After(oneDayAgo) {
				response.OnlineLast24h++
			}
		}

		// HWID limit
		if u.HwidDeviceLimit != nil {
			response.UsersWithHwidLimit++
		}

		// HWID devices
		devices := s.remnawave.GetUserHwidDevices(u.UUID)
		if len(devices) > 0 {
			uniqueHwidUsers[u.UUID] = true
			totalDevices += len(devices)
			for _, d := range devices {
				if d.Platform != nil {
					platformCounts[*d.Platform]++
				} else {
					platformCounts["Unknown"]++
				}
			}
		}
	}

	response.HwidStats = &HwidStatsResponse{
		TotalDevices:      totalDevices,
		UniqueUsers:       len(uniqueHwidUsers),
		PlatformBreakdown: platformCounts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRemnawaveUsers returns all Remnawave users with enriched data
func (s *Server) handleRemnawaveUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.remnawave == nil {
		// Return empty array when not configured
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	users := s.remnawave.GetAllUsers()

	// Build response with enriched data
	type EnrichedUser struct {
		UUID               string  `json:"uuid"`
		Username           string  `json:"username"`
		Email              *string `json:"email"`
		Status             string  `json:"status"`
		UsedTrafficBytes   int64   `json:"used_traffic_bytes"`
		TrafficLimitBytes  int64   `json:"traffic_limit_bytes"`
		TrafficPercent     float64 `json:"traffic_percent"`
		HwidDeviceCount    int     `json:"hwid_device_count"`
		HwidDeviceLimit    *int    `json:"hwid_device_limit"`
		HwidExceedsLimit   bool    `json:"hwid_exceeds_limit"`
		OnlineAt           *string `json:"online_at"`
		ExpireAt           string  `json:"expire_at"`
		LastConnectedNode  *string `json:"last_connected_node"`
		Tag                *string `json:"tag"`
		TelegramID         *int64  `json:"telegram_id"`
		Description        *string `json:"description"`
		ParsedRealName     *string `json:"parsed_real_name,omitempty"`
		ParsedPhone        *string `json:"parsed_phone,omitempty"`
		ParsedTelegramUser *string `json:"parsed_telegram_user,omitempty"`
		ParsedPlan         *string `json:"parsed_plan,omitempty"`
	}

	result := make([]EnrichedUser, 0, len(users))
	for _, u := range users {
		eu := EnrichedUser{
			UUID:              u.UUID,
			Username:          u.Username,
			Email:             u.Email,
			Status:            u.Status,
			UsedTrafficBytes:  u.UsedTrafficBytes,
			TrafficLimitBytes: u.TrafficLimitBytes,
			HwidDeviceLimit:   u.HwidDeviceLimit,
			ExpireAt:          u.ExpireAt.Format("2006-01-02T15:04:05Z"),
			Tag:               u.Tag,
			TelegramID:        u.TelegramID,
			Description:       u.Description,
		}

		// Calculate traffic percentage
		if u.TrafficLimitBytes > 0 {
			eu.TrafficPercent = float64(u.UsedTrafficBytes) / float64(u.TrafficLimitBytes) * 100
		}

		// Get HWID devices count
		devices := s.remnawave.GetUserHwidDevices(u.UUID)
		eu.HwidDeviceCount = len(devices)

		// Check if exceeds limit
		if u.HwidDeviceLimit != nil && len(devices) > *u.HwidDeviceLimit {
			eu.HwidExceedsLimit = true
		}

		// Format optional timestamps
		if u.OnlineAt != nil {
			ts := u.OnlineAt.Format("2006-01-02T15:04:05Z")
			eu.OnlineAt = &ts
		}
		if u.LastConnectedNode != nil {
			eu.LastConnectedNode = &u.LastConnectedNode.NodeName
		}

		// Add parsed note fields
		if u.ParsedNote != nil {
			if u.ParsedNote.RealName != "" {
				eu.ParsedRealName = &u.ParsedNote.RealName
			}
			if u.ParsedNote.Phone != "" {
				eu.ParsedPhone = &u.ParsedNote.Phone
			}
			if u.ParsedNote.TelegramUser != "" {
				eu.ParsedTelegramUser = &u.ParsedNote.TelegramUser
			}
			if u.ParsedNote.Plan != "" {
				eu.ParsedPlan = &u.ParsedNote.Plan
			}
		}

		result = append(result, eu)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleRemnawaveUser returns a single Remnawave user by UUID or username
func (s *Server) handleRemnawaveUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.remnawave == nil {
		// Return null when not configured
		json.NewEncoder(w).Encode(map[string]interface{}{"enabled": false, "user": nil})
		return
	}

	// Extract identifier from path: /api/remnawave/user/{identifier}
	path := r.URL.Path
	prefix := "/api/remnawave/user/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "user identifier required", http.StatusBadRequest)
		return
	}
	identifier := strings.TrimPrefix(path, prefix)

	// Try to find user
	var user interface{}

	// Try by UUID first
	u := s.remnawave.GetUserByUUID(identifier)
	if u == nil {
		// Try by username
		u = s.remnawave.GetUserByUsername(identifier)
	}
	if u == nil {
		// Try by email
		u = s.remnawave.GetUserByEmail(identifier)
	}

	if u == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Build detailed response
	devices := s.remnawave.GetUserHwidDevices(u.UUID)

	type DeviceInfo struct {
		Hwid        string  `json:"hwid"`
		Platform    *string `json:"platform"`
		OSVersion   *string `json:"os_version"`
		DeviceModel *string `json:"device_model"`
		UserAgent   *string `json:"user_agent"`
		CreatedAt   string  `json:"created_at"`
	}

	deviceList := make([]DeviceInfo, 0, len(devices))
	for _, d := range devices {
		deviceList = append(deviceList, DeviceInfo{
			Hwid:        d.Hwid,
			Platform:    d.Platform,
			OSVersion:   d.OSVersion,
			DeviceModel: d.DeviceModel,
			UserAgent:   d.UserAgent,
			CreatedAt:   d.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	response := struct {
		UUID              string       `json:"uuid"`
		ShortUUID         string       `json:"short_uuid"`
		Username          string       `json:"username"`
		Email             *string      `json:"email"`
		Status            string       `json:"status"`
		UsedTrafficBytes  int64        `json:"used_traffic_bytes"`
		TrafficLimitBytes int64        `json:"traffic_limit_bytes"`
		ExpireAt          string       `json:"expire_at"`
		OnlineAt          *string      `json:"online_at"`
		Tag               *string      `json:"tag"`
		TelegramID        *int64       `json:"telegram_id"`
		Description       *string      `json:"description"`
		ParsedNote        interface{}  `json:"parsed_note"`
		HwidDevices       []DeviceInfo `json:"hwid_devices"`
		HwidDeviceLimit   *int         `json:"hwid_device_limit"`
		SubscriptionURL   string       `json:"subscription_url"`
		CreatedAt         string       `json:"created_at"`
	}{
		UUID:              u.UUID,
		ShortUUID:         u.ShortUUID,
		Username:          u.Username,
		Email:             u.Email,
		Status:            u.Status,
		UsedTrafficBytes:  u.UsedTrafficBytes,
		TrafficLimitBytes: u.TrafficLimitBytes,
		ExpireAt:          u.ExpireAt.Format("2006-01-02T15:04:05Z"),
		Tag:               u.Tag,
		TelegramID:        u.TelegramID,
		Description:       u.Description,
		ParsedNote:        u.ParsedNote,
		HwidDevices:       deviceList,
		HwidDeviceLimit:   u.HwidDeviceLimit,
		SubscriptionURL:   u.SubscriptionURL,
		CreatedAt:         u.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	if u.OnlineAt != nil {
		ts := u.OnlineAt.Format("2006-01-02T15:04:05Z")
		response.OnlineAt = &ts
	}

	user = response

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// handleRemnawaveHwid returns HWID devices for a user
func (s *Server) handleRemnawaveHwid(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.remnawave == nil {
		// Return empty response when not configured
		json.NewEncoder(w).Encode(map[string]interface{}{"enabled": false, "devices": []interface{}{}, "count": 0})
		return
	}

	// Extract user UUID from path: /api/remnawave/hwid/{userUUID}
	path := r.URL.Path
	prefix := "/api/remnawave/hwid/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "user UUID required", http.StatusBadRequest)
		return
	}
	userUUID := strings.TrimPrefix(path, prefix)

	devices := s.remnawave.GetUserHwidDevices(userUUID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_uuid": userUUID,
		"devices":   devices,
		"count":     len(devices),
	})
}

// handleRemnawaveAbuse detects subscription abuse based on HWID device limits
// Uses optimized GetTopUsersByHwid which works directly with cached data
func (s *Server) handleRemnawaveAbuse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.remnawave == nil {
		// Return empty response instead of error when not configured
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":      false,
			"totalAbusers": 0,
			"users":        []interface{}{},
		})
		return
	}

	// Get all users with HWID devices, sorted by device count (limit 0 = all)
	topUsers := s.remnawave.GetTopUsersByHwid(0)

	type DeviceInfo struct {
		Hwid        string  `json:"hwid"`
		Platform    *string `json:"platform,omitempty"`
		OSVersion   *string `json:"osVersion,omitempty"`
		DeviceModel *string `json:"deviceModel,omitempty"`
		UserAgent   *string `json:"userAgent,omitempty"`
		CreatedAt   string  `json:"createdAt"`
	}

	type ParsedNoteInfo struct {
		RealName     string `json:"real_name,omitempty"`
		Phone        string `json:"phone,omitempty"`
		TelegramUser string `json:"telegram_user,omitempty"`
		Plan         string `json:"plan,omitempty"`
	}

	type AbuseUser struct {
		UUID          string          `json:"uuid"`
		Username      string          `json:"username"`
		Email         *string         `json:"email,omitempty"`
		Status        string          `json:"status"`
		DeviceCount   int             `json:"deviceCount"`
		DeviceLimit   int             `json:"deviceLimit"`
		ExcessDevices int             `json:"excessDevices"`
		Platforms     []string        `json:"platforms"`
		LastActivity  *string         `json:"lastActivity,omitempty"`
		Devices       []DeviceInfo    `json:"devices"`
		ParsedNote    *ParsedNoteInfo `json:"parsedNote,omitempty"`
	}

	var abuseUsers []AbuseUser

	// Default HWID limit if not set in Remnawave
	const defaultHwidLimit = 5

	for _, uc := range topUsers {
		u := uc.User

		// Determine effective limit: use user's limit or default
		effectiveLimit := defaultHwidLimit
		if u.HwidDeviceLimit != nil {
			effectiveLimit = *u.HwidDeviceLimit
		}

		// Check if user is at or exceeds HWID limit (show both at limit and over limit)
		if uc.DeviceCount >= effectiveLimit && effectiveLimit > 0 {
			record := AbuseUser{
				UUID:          u.UUID,
				Username:      u.Username,
				Email:         u.Email,
				Status:        u.Status,
				DeviceCount:   uc.DeviceCount,
				DeviceLimit:   effectiveLimit,
				ExcessDevices: uc.DeviceCount - effectiveLimit,
			}

			// Add last activity
			if u.OnlineAt != nil {
				ts := u.OnlineAt.Format("2006-01-02T15:04:05Z")
				record.LastActivity = &ts
			}

			// Collect unique platforms and device info
			platforms := make(map[string]bool)
			for _, d := range uc.Devices {
				di := DeviceInfo{
					Hwid:        d.Hwid,
					Platform:    d.Platform,
					OSVersion:   d.OSVersion,
					DeviceModel: d.DeviceModel,
					UserAgent:   d.UserAgent,
					CreatedAt:   d.CreatedAt.Format("2006-01-02T15:04:05Z"),
				}
				record.Devices = append(record.Devices, di)
				if d.Platform != nil {
					platforms[*d.Platform] = true
				}
			}
			for p := range platforms {
				record.Platforms = append(record.Platforms, p)
			}

			// Add parsed note data
			if u.ParsedNote != nil {
				record.ParsedNote = &ParsedNoteInfo{
					RealName:     u.ParsedNote.RealName,
					Phone:        u.ParsedNote.Phone,
					TelegramUser: u.ParsedNote.TelegramUser,
					Plan:         u.ParsedNote.Plan,
				}
			}

			abuseUsers = append(abuseUsers, record)
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalAbusers": len(abuseUsers),
		"users":        abuseUsers,
	})
}

// handleRemnawaveOnline returns online users statistics from Remnawave
// This data is more accurate than log-based stats as it comes directly from Remnawave
func (s *Server) handleRemnawaveOnline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.remnawave == nil {
		// Return empty stats when not configured
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":      false,
			"now":          0,
			"recent":       0,
			"lastHour":     0,
			"last24h":      0,
			"neverOnline":  0,
			"totalActive":  0,
			"onlineUsers":  []interface{}{},
			"lastSync":     "",
			"syncInterval": "",
		})
		return
	}

	users := s.remnawave.GetAllUsers()
	now := time.Now()

	// Time windows for different online categories
	fiveMinAgo := now.Add(-5 * time.Minute)
	fifteenMinAgo := now.Add(-15 * time.Minute)
	oneHourAgo := now.Add(-1 * time.Hour)
	oneDayAgo := now.Add(-24 * time.Hour)

	type OnlineUser struct {
		UUID              string  `json:"uuid"`
		Username          string  `json:"username"`
		Email             *string `json:"email,omitempty"`
		OnlineAt          string  `json:"onlineAt"`
		MinutesAgo        int     `json:"minutesAgo"`
		LastConnectedNode *string `json:"lastConnectedNode,omitempty"`
		CountryCode       *string `json:"countryCode,omitempty"`
		Status            string  `json:"status"`
		ParsedRealName    *string `json:"parsedRealName,omitempty"`
	}

	type OnlineStats struct {
		Now          int          `json:"now"`         // Last 5 min
		Recent       int          `json:"recent"`      // Last 15 min
		LastHour     int          `json:"lastHour"`    // Last hour
		Last24h      int          `json:"last24h"`     // Last 24 hours
		NeverOnline  int          `json:"neverOnline"` // Never been online
		TotalActive  int          `json:"totalActive"` // Total active users
		OnlineUsers  []OnlineUser `json:"onlineUsers"` // Currently online (last 15 min)
		LastSync     string       `json:"lastSync"`
		SyncInterval string       `json:"syncInterval"` // How often data is refreshed
	}

	stats := OnlineStats{
		OnlineUsers:  make([]OnlineUser, 0),
		SyncInterval: "1m", // Default sync interval
	}

	lastSync := s.remnawave.GetLastSyncTime()
	if !lastSync.IsZero() {
		stats.LastSync = lastSync.Format("2006-01-02T15:04:05Z")
	}

	// "Online now" = real-time XTLS-tracked sum across all Remnawave nodes,
	// rather than `OnlineAt > now() - 5min` (which was always 0 in the gap
	// between 5-min sync cycles). Falls back to OnlineAt-window count if
	// the storage path isn't available.
	if s.storage != nil {
		var nodesOnline sql.NullInt64
		if err := s.storage.DB().QueryRowContext(r.Context(),
			`SELECT COALESCE(SUM(users_online), 0) FROM remna_nodes`).Scan(&nodesOnline); err == nil {
			stats.Now = int(nodesOnline.Int64)
		}
	}

	for _, u := range users {
		if u.Status == "ACTIVE" {
			stats.TotalActive++
		}

		if u.OnlineAt == nil {
			stats.NeverOnline++
			continue
		}

		if stats.Now == 0 && u.OnlineAt.After(fiveMinAgo) {
			// Only used when XTLS sum unavailable above.
			stats.Now++
		}
		if u.OnlineAt.After(fifteenMinAgo) {
			stats.Recent++

			// Add to online users list
			ou := OnlineUser{
				UUID:       u.UUID,
				Username:   u.Username,
				Email:      u.Email,
				OnlineAt:   u.OnlineAt.Format("2006-01-02T15:04:05Z"),
				MinutesAgo: int(now.Sub(*u.OnlineAt).Minutes()),
				Status:     u.Status,
			}
			if u.LastConnectedNode != nil {
				ou.LastConnectedNode = &u.LastConnectedNode.NodeName
				ou.CountryCode = &u.LastConnectedNode.CountryCode
			}
			if u.ParsedNote != nil && u.ParsedNote.RealName != "" {
				ou.ParsedRealName = &u.ParsedNote.RealName
			}
			stats.OnlineUsers = append(stats.OnlineUsers, ou)
		}
		if u.OnlineAt.After(oneHourAgo) {
			stats.LastHour++
		}
		if u.OnlineAt.After(oneDayAgo) {
			stats.Last24h++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleRemnawaveHwidTop returns top users by HWID device count
func (s *Server) handleRemnawaveHwidTop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.remnawave == nil {
		http.Error(w, "remnawave not configured", http.StatusServiceUnavailable)
		return
	}

	// Get top 50 users by HWID count
	topUsers := s.remnawave.GetTopUsersByHwid(50)

	type DeviceInfo struct {
		Hwid        string  `json:"hwid"`
		Platform    *string `json:"platform"`
		DeviceModel *string `json:"device_model"`
		CreatedAt   string  `json:"created_at"`
	}

	type UserHwidInfo struct {
		UUID        string       `json:"uuid"`
		Username    string       `json:"username"`
		Email       *string      `json:"email"`
		Status      string       `json:"status"`
		HwidLimit   *int         `json:"hwid_limit"`
		DeviceCount int          `json:"device_count"`
		OverLimit   bool         `json:"over_limit"`
		Devices     []DeviceInfo `json:"devices"`
		TelegramID  *int64       `json:"telegram_id"`
		Tag         *string      `json:"tag"`
	}

	result := make([]UserHwidInfo, 0, len(topUsers))
	for _, uc := range topUsers {
		u := uc.User

		// Check if over limit
		overLimit := false
		if u.HwidDeviceLimit != nil && *u.HwidDeviceLimit > 0 {
			overLimit = uc.DeviceCount > *u.HwidDeviceLimit
		}

		// Build device list
		devices := make([]DeviceInfo, 0, len(uc.Devices))
		for _, d := range uc.Devices {
			devices = append(devices, DeviceInfo{
				Hwid:        d.Hwid,
				Platform:    d.Platform,
				DeviceModel: d.DeviceModel,
				CreatedAt:   d.CreatedAt.Format("2006-01-02T15:04:05Z"),
			})
		}

		result = append(result, UserHwidInfo{
			UUID:        u.UUID,
			Username:    u.Username,
			Email:       u.Email,
			Status:      u.Status,
			HwidLimit:   u.HwidDeviceLimit,
			DeviceCount: uc.DeviceCount,
			OverLimit:   overLimit,
			Devices:     devices,
			TelegramID:  u.TelegramID,
			Tag:         u.Tag,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": result,
		"total": len(result),
	})
}

// handleRemnawavelClearHwid clears all HWID devices for a specific user
func (s *Server) handleRemnawavelClearHwid(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.remnawave == nil {
		http.Error(w, "remnawave not configured", http.StatusServiceUnavailable)
		return
	}

	// Parse request body
	var req struct {
		UserUUID string `json:"userUuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[hwid-clear] ERROR parsing request body: %v", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("[hwid-clear] Request to clear HWID for userUuid: %s", req.UserUUID)

	if req.UserUUID == "" {
		log.Printf("[hwid-clear] ERROR: userUuid is empty")
		http.Error(w, "userUuid is required", http.StatusBadRequest)
		return
	}

	// Call the sync service to clear HWID devices
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.remnawave.ClearUserHwidDevices(ctx, req.UserUUID); err != nil {
		log.Printf("[hwid-clear] ERROR clearing HWID for %s: %v", req.UserUUID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[hwid-clear] Successfully cleared HWID for user %s", req.UserUUID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"userUuid": req.UserUUID,
		"message":  "All HWID devices cleared successfully",
	})
}
