package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/remnawave"
	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// Ensure remnawave is used (for type reference in enrichAbusersWithHWID)
var _ *remnawave.User

// resolveUserDisplayNames resolves numeric IDs to usernames via Remnawave API
func (s *Server) resolveUserDisplayNames(ctx context.Context, users []*models.UserStats) {
	for _, u := range users {
		// If display_name is empty or same as user_email (not resolved), try to resolve
		if u.DisplayName == "" || u.DisplayName == u.UserEmail {
			if s.remnawave != nil {
				resolved := s.remnawave.ResolveUsername(ctx, u.UserEmail)
				u.DisplayName = resolved
			} else {
				// Fallback to user_email if remnawave not configured
				u.DisplayName = u.UserEmail
			}
		}
	}
}

// resolveCategoryUserStats resolves numeric IDs to usernames in CategoryUserStats
func (s *Server) resolveCategoryUserStats(ctx context.Context, stats []*threatintel.CategoryUserStats) {
	if s.remnawave == nil {
		return
	}
	for _, stat := range stats {
		if stat.DisplayName == "" || stat.DisplayName == stat.UserEmail {
			stat.DisplayName = s.remnawave.ResolveUsername(ctx, stat.UserEmail)
		}
	}
}

// resolveCategoryTopUsers resolves usernames for all categories in map
func (s *Server) resolveCategoryTopUsers(ctx context.Context, topUsers map[string][]*threatintel.CategoryUserStats) {
	for _, stats := range topUsers {
		s.resolveCategoryUserStats(ctx, stats)
	}
}

// resolveThreatMatches resolves numeric IDs to usernames in ThreatMatch
func (s *Server) resolveThreatMatches(ctx context.Context, matches []*threatintel.ThreatMatch) {
	if s.remnawave == nil {
		return
	}
	for _, m := range matches {
		if m.DisplayName == "" || m.DisplayName == m.UserEmail {
			m.DisplayName = s.remnawave.ResolveUsername(ctx, m.UserEmail)
		}
	}
}

// handleStats returns overall statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	globalStats, err := s.storage.GetGlobalStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.clientsMu.RLock()
	globalStats.NodesConnected = len(s.clients)
	s.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalStats)
}

// handleNodes returns node statistics
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nodes, err := s.storage.GetNodeStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Mark connected nodes
	s.clientsMu.RLock()
	for _, n := range nodes {
		_, n.IsConnected = s.clients[n.NodeID]
	}
	s.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

// handleUsers returns top users by blacklist hits
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := s.storage.GetTopBlacklistUsers(ctx, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Resolve numeric IDs to usernames via Remnawave API
	s.resolveUserDisplayNames(ctx, users)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// handleAllUsers returns all users sorted by requests
func (s *Server) handleAllUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 10000
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	users, err := s.storage.GetAllUsers(ctx, limit)
	if err != nil {
		log.Printf("Error getting all users: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Resolve numeric IDs to usernames via Remnawave API
	s.resolveUserDisplayNames(ctx, users)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// handleUserRouter routes user-specific requests
func (s *Server) handleUserRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for /api/users/{email}/destinations
	if strings.HasSuffix(path, "/destinations") {
		s.handleUserDestinations(w, r)
		return
	}

	// Check for /api/users/{email}/alerts
	if strings.HasSuffix(path, "/alerts") {
		s.handleUserAlerts(w, r)
		return
	}

	// Check for /api/users/{email}/blacklist
	if strings.HasSuffix(path, "/blacklist") {
		s.handleUserBlacklistMatches(w, r)
		return
	}

	// Check for /api/users/{email}/ip-history
	if strings.HasSuffix(path, "/ip-history") {
		s.handleUserIPHistory(w, r)
		return
	}

	// Default: user details
	s.handleUserDetails(w, r)
}

// handleUserDetails returns detailed stats for a specific user
func (s *Server) handleUserDetails(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	prefix := "/api/users/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "user email required", http.StatusBadRequest)
		return
	}
	userEmail := strings.TrimPrefix(path, prefix)

	userEmail, err := url.QueryUnescape(userEmail)
	if err != nil {
		http.Error(w, "invalid user email", http.StatusBadRequest)
		return
	}

	details, err := s.storage.GetUserDetails(r.Context(), userEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

// handleUserIPHistory returns IP address history for a user
func (s *Server) handleUserIPHistory(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	// Extract email from path like /api/users/{email}/ip-history
	path = strings.TrimSuffix(path, "/ip-history")
	prefix := "/api/users/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "user email required", http.StatusBadRequest)
		return
	}
	userEmail := strings.TrimPrefix(path, prefix)

	userEmail, err := url.QueryUnescape(userEmail)
	if err != nil {
		http.Error(w, "invalid user email", http.StatusBadRequest)
		return
	}

	history, err := s.storage.GetUserIPHistory(r.Context(), userEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

// handleDeleteNode deletes a node and its data
func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var nodeID string
	var hasNodeID bool

	if qp := r.URL.Query().Get("node_id"); r.URL.Query().Has("node_id") {
		nodeID = qp
		hasNodeID = true
	} else {
		var body struct {
			NodeID string `json:"node_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			nodeID = body.NodeID
			hasNodeID = true
		}
	}

	if !hasNodeID {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	s.clientsMu.RLock()
	_, isConnected := s.clients[nodeID]
	s.clientsMu.RUnlock()
	if isConnected {
		http.Error(w, "cannot delete connected node", http.StatusBadRequest)
		return
	}

	if err := s.storage.DeleteNode(r.Context(), nodeID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "node_id": nodeID})
}

// handleHealth returns server health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleHourlyStats returns hourly statistics for charts
func (s *Server) handleHourlyStats(w http.ResponseWriter, r *http.Request) {
	hoursStr := r.URL.Query().Get("hours")
	hours := 24
	if hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 && h <= 720 {
			hours = h
		}
	}

	var from, to time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}

	var stats []models.HourlyStats
	var err error

	if !from.IsZero() || !to.IsZero() {
		stats, err = s.storage.GetHourlyStatsRange(r.Context(), from, to)
	} else {
		stats, err = s.storage.GetHourlyStats(r.Context(), hours)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleAnomalies detects and returns anomalies
func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := s.storage.GetHourlyStats(ctx, 48)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(stats) < 6 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Anomaly{})
		return
	}

	var sumRequests, sumBlacklist int64
	baseline := stats[:len(stats)-2]
	for _, s := range baseline {
		sumRequests += s.TotalRequests
		sumBlacklist += s.BlacklistHits
	}
	avgRequests := float64(sumRequests) / float64(len(baseline))
	avgBlacklist := float64(sumBlacklist) / float64(len(baseline))

	var anomalies []models.Anomaly
	recent := stats[len(stats)-2:]
	for _, s := range recent {
		if avgBlacklist > 0 && float64(s.BlacklistHits) > avgBlacklist*2 {
			anomalies = append(anomalies, models.Anomaly{
				Type:      "blacklist_spike",
				Hour:      s.Hour,
				Value:     s.BlacklistHits,
				Baseline:  int64(avgBlacklist),
				Deviation: float64(s.BlacklistHits) / avgBlacklist,
				Message:   fmt.Sprintf("Blacklist hits spike: %d (avg: %.0f)", s.BlacklistHits, avgBlacklist),
			})
		}
		if avgRequests > 0 && float64(s.TotalRequests) > avgRequests*3 {
			anomalies = append(anomalies, models.Anomaly{
				Type:      "traffic_spike",
				Hour:      s.Hour,
				Value:     s.TotalRequests,
				Baseline:  int64(avgRequests),
				Deviation: float64(s.TotalRequests) / avgRequests,
				Message:   fmt.Sprintf("Traffic spike: %d (avg: %.0f)", s.TotalRequests, avgRequests),
			})
		}
	}

	userAnomalies, _ := s.storage.GetUserAnomalies(ctx, 5)
	anomalies = append(anomalies, userAnomalies...)

	// Сортируем по времени (новые сверху)
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Hour.After(anomalies[j].Hour)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anomalies)
}

// handleAlerts returns recent alerts
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}

	alerts, err := s.storage.GetRecentAlerts(ctx, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

// handleBlacklistStats returns blacklist statistics
func (s *Server) handleBlacklistStats(w http.ResponseWriter, r *http.Request) {
	exact, wildcards, lastRemote := s.blacklist.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"exact_domains":      exact,
		"wildcard_rules":     wildcards,
		"total":              exact + wildcards,
		"last_remote_update": lastRemote,
	})
}

// handleBlacklistAnalytics returns detailed blacklist analytics
func (s *Server) handleBlacklistAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	period := 24 * time.Hour
	if p := r.URL.Query().Get("period"); p != "" {
		switch p {
		case "1h":
			period = 1 * time.Hour
		case "6h":
			period = 6 * time.Hour
		case "24h":
			period = 24 * time.Hour
		case "7d":
			period = 7 * 24 * time.Hour
		case "30d":
			period = 30 * 24 * time.Hour
		}
	}

	since := time.Now().Add(-period)
	analytics, err := s.storage.GetBlacklistAnalytics(ctx, since)
	if err != nil {
		log.Printf("Error getting blacklist analytics: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if analytics.TopDomains == nil {
		analytics.TopDomains = []models.DomainStats{}
	}
	if analytics.TopUsers == nil {
		analytics.TopUsers = []models.UserBlacklistStats{}
	}
	if analytics.RecentMatches == nil {
		analytics.RecentMatches = []models.BlacklistMatchInfo{}
	}
	if analytics.HourlyStats == nil {
		analytics.HourlyStats = []models.HourlyBlacklistStats{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analytics)
}

// handleSubscriptionAbuse returns users suspected of sharing subscriptions
func (s *Server) handleSubscriptionAbuse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse period parameter
	period := 24 * time.Hour
	if p := r.URL.Query().Get("period"); p != "" {
		switch p {
		case "1h":
			period = time.Hour
		case "6h":
			period = 6 * time.Hour
		case "24h":
			period = 24 * time.Hour
		case "7d":
			period = 7 * 24 * time.Hour
		case "30d":
			period = 30 * 24 * time.Hour
		}
	}

	// Parse minimum IPs threshold (default 3)
	minIPs := 3
	if m := r.URL.Query().Get("min_ips"); m != "" {
		if parsed, err := strconv.Atoi(m); err == nil && parsed > 0 {
			minIPs = parsed
		}
	}

	since := time.Now().Add(-period)
	abusers, err := s.storage.GetSubscriptionAbusers(ctx, since, minIPs)
	if err != nil {
		log.Printf("Error getting subscription abusers: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if abusers == nil {
		abusers = []*models.SubscriptionAbuse{}
	}

	// Enrich with HWID data from Remnawave if client is available
	if s.remnawave != nil {
		s.enrichAbusersWithHWID(abusers)
	}

	// Resolve usernames via Remnawave API for users not found in cache
	if s.remnawave != nil {
		for _, abuser := range abusers {
			if abuser.Username == "" {
				abuser.Username = s.remnawave.ResolveUsername(ctx, abuser.UserEmail)
			}
		}
	}

	// Calculate abuse score for each user
	for _, abuser := range abusers {
		abuser.AbuseScore = calculateAbuseScore(abuser)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(abusers)
}

// enrichAbusersWithHWID adds HWID information from Remnawave to abuse records
func (s *Server) enrichAbusersWithHWID(abusers []*models.SubscriptionAbuse) {
	// Get user mapping from Remnawave (email -> uuid)
	users := s.remnawave.GetAllUsers()
	if users == nil {
		return
	}

	// Build email to user mapping (by username which is the email)
	emailToUser := make(map[string]*remnawave.User)
	for _, user := range users {
		if user != nil && user.Username != "" {
			emailToUser[user.Username] = user
		}
	}

	// For each abuser, try to get HWID devices
	for _, abuser := range abusers {
		user, ok := emailToUser[abuser.UserEmail]
		if !ok {
			continue
		}

		abuser.UserUUID = user.UUID
		abuser.Username = user.Username

		// Get HWID devices for this user from cache
		hwidDevices := s.remnawave.GetUserHwidDevices(user.UUID)
		if len(hwidDevices) > 0 {
			abuser.UniqueHWIDs = len(hwidDevices)
			abuser.HWIDs = make([]models.HWIDInfo, 0, len(hwidDevices))
			for _, device := range hwidDevices {
				hwid := models.HWIDInfo{
					HWID:      device.Hwid,
					CreatedAt: device.CreatedAt,
				}
				if device.Platform != nil {
					hwid.Platform = *device.Platform
				}
				if device.DeviceModel != nil {
					hwid.DeviceModel = *device.DeviceModel
				}
				abuser.HWIDs = append(abuser.HWIDs, hwid)
			}
		}
	}
} // calculateAbuseScore computes a risk score (0-100) based on IP, node, and HWID diversity
func calculateAbuseScore(abuser *models.SubscriptionAbuse) int {
	score := 0

	// IP score: more unique IPs = higher risk (max 40 points)
	// 3 IPs = 10, 5 IPs = 20, 10+ IPs = 40
	switch {
	case abuser.UniqueIPs >= 10:
		score += 40
	case abuser.UniqueIPs >= 5:
		score += 20
	case abuser.UniqueIPs >= 3:
		score += 10
	}

	// Node score: multiple nodes from different IPs = higher risk (max 30 points)
	// 3+ nodes = 30, 2 nodes = 15
	switch {
	case abuser.UniqueNodes >= 3:
		score += 30
	case abuser.UniqueNodes >= 2:
		score += 15
	}

	// HWID score: multiple devices = higher risk (max 30 points)
	// 3+ devices = 30, 2 devices = 15
	switch {
	case abuser.UniqueHWIDs >= 3:
		score += 30
	case abuser.UniqueHWIDs >= 2:
		score += 15
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// handleUserDestinations returns paginated destinations for a user
func (s *Server) handleUserDestinations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract email from URL path: /api/users/{email}/destinations
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}

	email, err := url.PathUnescape(parts[3])
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	// Parse pagination params
	page := 1
	pageSize := 50
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Default: last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	if p := r.URL.Query().Get("period"); p != "" {
		switch p {
		case "1h":
			since = time.Now().Add(-1 * time.Hour)
		case "6h":
			since = time.Now().Add(-6 * time.Hour)
		case "24h":
			since = time.Now().Add(-24 * time.Hour)
		case "7d":
			since = time.Now().Add(-7 * 24 * time.Hour)
		case "30d":
			since = time.Now().Add(-30 * 24 * time.Hour)
		}
	}

	response, err := s.storage.GetUserDestinations(ctx, email, since, page, pageSize)
	if err != nil {
		log.Printf("Error getting user destinations: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if response.Destinations == nil {
		response.Destinations = []models.UserDestination{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUserAlerts returns paginated alerts for a user
func (s *Server) handleUserAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract email from URL path: /api/users/{email}/alerts
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}

	email, err := url.PathUnescape(parts[3])
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	// Parse pagination params
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	response, err := s.storage.GetUserAlerts(ctx, email, page, pageSize)
	if err != nil {
		log.Printf("Error getting user alerts: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if response.Alerts == nil {
		response.Alerts = []models.Alert{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUserBlacklistMatches returns paginated blacklist matches for a user
func (s *Server) handleUserBlacklistMatches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract email from URL path: /api/users/{email}/blacklist
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}

	email, err := url.PathUnescape(parts[3])
	if err != nil {
		http.Error(w, "invalid email", http.StatusBadRequest)
		return
	}

	// Parse pagination params
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Default: last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	if p := r.URL.Query().Get("period"); p != "" {
		switch p {
		case "1h":
			since = time.Now().Add(-1 * time.Hour)
		case "6h":
			since = time.Now().Add(-6 * time.Hour)
		case "24h":
			since = time.Now().Add(-24 * time.Hour)
		case "7d":
			since = time.Now().Add(-7 * 24 * time.Hour)
		case "30d":
			since = time.Now().Add(-30 * 24 * time.Hour)
		}
	}

	response, err := s.storage.GetUserBlacklistMatches(ctx, email, since, page, pageSize)
	if err != nil {
		log.Printf("Error getting user blacklist matches: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if response.Matches == nil {
		response.Matches = []models.BlacklistMatchInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleThreatIntelStats returns threat intelligence statistics
func (s *Server) handleThreatIntelStats(w http.ResponseWriter, r *http.Request) {
	if s.threatIntel == nil {
		http.Error(w, "Threat intelligence not available", http.StatusServiceUnavailable)
		return
	}

	stats := s.threatIntel.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleThreatIntelMatches returns recent threat matches
func (s *Server) handleThreatIntelMatches(w http.ResponseWriter, r *http.Request) {
	if s.threatIntel == nil {
		http.Error(w, "Threat intelligence not available", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	// Check query parameters
	userEmail := r.URL.Query().Get("user")
	threatType := r.URL.Query().Get("type")

	var matches []*threatintel.ThreatMatch
	var err error

	if userEmail != "" {
		matches, err = s.threatIntel.GetUserMatches(ctx, userEmail, limit)
	} else if threatType != "" {
		matches, err = s.threatIntel.GetMatchesByType(ctx, threatType, limit)
	} else {
		matches, err = s.threatIntel.GetRecentMatches(ctx, limit)
	}

	if err != nil {
		log.Printf("Error getting threat matches: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Resolve usernames via Remnawave API
	if s.remnawave != nil && matches != nil {
		for _, m := range matches {
			if m.DisplayName == "" || m.DisplayName == m.UserEmail {
				m.DisplayName = s.remnawave.ResolveUsername(ctx, m.UserEmail)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(matches)
}

// handleThreatIntelFeeds returns threat feed statuses
func (s *Server) handleThreatIntelFeeds(w http.ResponseWriter, r *http.Request) {
	if s.threatIntel == nil {
		http.Error(w, "Threat intelligence not available", http.StatusServiceUnavailable)
		return
	}

	feeds := s.threatIntel.GetFeedStatus()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(feeds)
}

// handleThreatIntelTopUsers returns top users by content category violations
func (s *Server) handleThreatIntelTopUsers(w http.ResponseWriter, r *http.Request) {
	if s.threatIntel == nil {
		http.Error(w, "Threat intelligence not available", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 50 {
			limit = parsed
		}
	}

	// Check if category-specific query
	category := r.URL.Query().Get("category")

	if category != "" {
		result, err := s.threatIntel.GetRecentUsersByCategory(ctx, category, limit)
		if err != nil {
			log.Printf("Error getting recent users: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.resolveCategoryUserStats(ctx, result)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	} else {
		result, err := s.threatIntel.GetRecentUsersByAllCategories(ctx, limit)
		if err != nil {
			log.Printf("Error getting recent users: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Resolve usernames for all categories
		s.resolveCategoryTopUsers(ctx, result)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// handleThreatIntelTimeStats returns hourly and daily threat statistics
func (s *Server) handleThreatIntelTimeStats(w http.ResponseWriter, r *http.Request) {
	if s.storage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	// Get hours (default 24)
	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if parsed, err := strconv.Atoi(h); err == nil && parsed > 0 && parsed <= 168 {
			hours = parsed
		}
	}

	// Get days (default 7)
	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 30 {
			days = parsed
		}
	}

	// Get hourly stats
	hourlyStats, err := s.storage.GetHourlyThreatStats(ctx, hours)
	if err != nil {
		log.Printf("Error getting hourly threat stats: %v", err)
		hourlyStats = []*threatintel.HourlyThreatStats{}
	}

	// Get daily stats
	dailyStats, err := s.storage.GetDailyThreatStats(ctx, days)
	if err != nil {
		log.Printf("Error getting daily threat stats: %v", err)
		dailyStats = []*threatintel.DailyThreatStats{}
	}

	response := map[string]interface{}{
		"hourly": hourlyStats,
		"daily":  dailyStats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleThreatIntelClear clears all ThreatIntel data to reset statistics
func (s *Server) handleThreatIntelClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.storage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	// Check if we should clear all user data too
	clearAll := r.URL.Query().Get("all") == "true"

	err := s.storage.ClearThreatIntelData(ctx)
	if err != nil {
		log.Printf("Error clearing ThreatIntel data: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if clearAll {
		err = s.storage.ClearAllUserData(ctx)
		if err != nil {
			log.Printf("Error clearing user data: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Println("All data cleared successfully (ThreatIntel + Users)")
	} else {
		log.Println("ThreatIntel data cleared successfully")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"message":     "Data cleared successfully",
		"cleared_all": clearAll,
	})
}

// handleThreatIntelGeoStats returns geographic threat statistics
func (s *Server) handleThreatIntelGeoStats(w http.ResponseWriter, r *http.Request) {
	if s.storage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	// Check for cities mode (all connections by city with coordinates)
	if r.URL.Query().Get("type") == "cities" {
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
				limit = parsed
			}
		}
		stats, err := s.storage.GetCityGeoStats(ctx, limit)
		if err != nil {
			log.Printf("Error getting city geo stats: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "cities",
			"cities": stats,
		})
		return
	}

	// Check for connections mode (all connections, not just threats)
	if r.URL.Query().Get("type") == "connections" {
		limit := 50
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
				limit = parsed
			}
		}
		stats, err := s.storage.GetConnectionGeoStats(ctx, limit)
		if err != nil {
			log.Printf("Error getting connection geo stats: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":          "connections",
			"top_countries": stats,
		})
		return
	}

	// Check for summary request
	if r.URL.Query().Get("summary") == "true" {
		summary, err := s.storage.GetGeoSummary(ctx)
		if err != nil {
			log.Printf("Error getting geo summary: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
		return
	}

	// Get limit
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	stats, err := s.storage.GetGeoStats(ctx, limit)
	if err != nil {
		log.Printf("Error getting geo stats: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleThreatIntelAnomalies returns anomaly detection results
func (s *Server) handleThreatIntelAnomalies(w http.ResponseWriter, r *http.Request) {
	if s.storage == nil {
		http.Error(w, "Storage not available", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	// POST to run detection
	if r.Method == http.MethodPost {
		anomalies, err := s.storage.DetectAnomalies(ctx)
		if err != nil {
			log.Printf("Error detecting anomalies: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"detected":  len(anomalies),
			"anomalies": anomalies,
		})
		return
	}

	// DELETE to resolve an anomaly
	if r.Method == http.MethodDelete {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing anomaly id", http.StatusBadRequest)
			return
		}
		if err := s.storage.ResolveAnomaly(ctx, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// GET - return summary or list
	if r.URL.Query().Get("summary") == "true" {
		summary, err := s.storage.GetAnomalySummary(ctx)
		if err != nil {
			log.Printf("Error getting anomaly summary: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
		return
	}

	// Get limit
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	includeResolved := r.URL.Query().Get("resolved") == "true"

	anomalies, err := s.storage.GetAnomalies(ctx, limit, includeResolved)
	if err != nil {
		log.Printf("Error getting anomalies: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anomalies)
}

// handleIPInfo returns geolocation info for IP addresses
func (s *Server) handleIPInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Single IP lookup
	if ip := r.URL.Query().Get("ip"); ip != "" {
		info, err := s.ipInfo.Lookup(ctx, ip)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
		return
	}

	// Batch lookup via POST
	if r.Method == http.MethodPost {
		var ips []string
		if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		result, err := s.ipInfo.LookupBatch(ctx, ips)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	http.Error(w, "IP address required", http.StatusBadRequest)
}

// handleUserRiskProfiles handles user risk profile requests
func (s *Server) handleUserRiskProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		// Get summary or specific user
		if email := r.URL.Query().Get("email"); email != "" {
			profile, err := s.storage.GetUserRiskProfile(ctx, email)
			if err != nil {
				log.Printf("Error getting risk profile: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(profile)
			return
		}

		// Return summary
		summary, err := s.storage.GetUserRiskSummary(ctx)
		if err != nil {
			log.Printf("Error getting risk summary: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)

	case http.MethodPost:
		// Recalculate specific user or all
		if email := r.URL.Query().Get("email"); email != "" {
			profile, err := s.storage.CalculateUserRiskProfile(ctx, email)
			if err != nil {
				log.Printf("Error calculating risk profile: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(profile)
			return
		}

		// Recalculate all
		if err := s.storage.RecalculateAllUserRiskProfiles(ctx); err != nil {
			log.Printf("Error recalculating all profiles: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		summary, _ := s.storage.GetUserRiskSummary(ctx)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDNSAnalysis handles DNS analysis requests
func (s *Server) handleDNSAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Check what data to return
	dataType := r.URL.Query().Get("type")

	switch dataType {
	case "stats":
		stats, err := s.storage.GetDNSQueryStats(ctx)
		if err != nil {
			log.Printf("Error getting DNS stats: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)

	case "users":
		limit := 20
		if l := r.URL.Query().Get("limit"); l != "" {
			fmt.Sscanf(l, "%d", &limit)
		}
		users, err := s.storage.GetTopUsersByDNS(ctx, limit)
		if err != nil {
			log.Printf("Error getting top DNS users: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	default:
		// Return full summary
		summary, err := s.storage.GetDNSAnalysisSummary(ctx)
		if err != nil {
			log.Printf("Error getting DNS summary: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}
}

// handleReports handles report generation and export
func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		// Get report by ID or list reports
		reportID := r.URL.Query().Get("id")
		if reportID != "" {
			report, err := s.storage.GetReport(ctx, reportID)
			if err != nil {
				log.Printf("Error getting report: %v", err)
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}

			// Check if specific format requested
			format := r.URL.Query().Get("format")
			if format != "" {
				s.exportReport(w, report, format)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(report)
			return
		}

		// List reports
		summary, err := s.storage.GetReportSummary(ctx)
		if err != nil {
			log.Printf("Error getting report summary: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)

	case http.MethodPost:
		// Generate new report
		var config threatintel.ReportConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		report, err := s.storage.GenerateReport(ctx, config)
		if err != nil {
			log.Printf("Error generating report: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(report)

	case http.MethodDelete:
		// Delete report
		reportID := r.URL.Query().Get("id")
		if reportID == "" {
			http.Error(w, "Report ID required", http.StatusBadRequest)
			return
		}

		if err := s.storage.DeleteReport(ctx, reportID); err != nil {
			log.Printf("Error deleting report: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// exportReport exports report in specified format
func (s *Server) exportReport(w http.ResponseWriter, report *threatintel.Report, format string) {
	switch threatintel.ReportFormat(format) {
	case threatintel.FormatJSON:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.json\"", report.Title))
		json.NewEncoder(w).Encode(report)

	case threatintel.FormatCSV:
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.csv\"", report.Title))
		s.writeReportCSV(w, report)

	case threatintel.FormatHTML:
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.html\"", report.Title))
		s.writeReportHTML(w, report)

	default:
		http.Error(w, "Unsupported format", http.StatusBadRequest)
	}
}

// writeReportCSV writes report data as CSV
func (s *Server) writeReportCSV(w http.ResponseWriter, report *threatintel.Report) {
	// Header
	fmt.Fprintf(w, "Threat Intelligence Report: %s\n", report.Title)
	fmt.Fprintf(w, "Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Period: %s to %s\n\n", report.StartDate.Format("2006-01-02"), report.EndDate.Format("2006-01-02"))

	// Summary section
	fmt.Fprintln(w, "=== SUMMARY ===")
	fmt.Fprintf(w, "Total Threats,%d\n", report.Summary.TotalThreats)
	fmt.Fprintf(w, "Blocked,%d\n", report.Summary.BlockedThreats)
	fmt.Fprintf(w, "Unique Users,%d\n", report.Summary.UniqueUsers)
	fmt.Fprintf(w, "Countries,%d\n", report.Summary.UniqueCountries)
	fmt.Fprintf(w, "High Risk Users,%d\n", report.Summary.HighRiskUsers)
	fmt.Fprintf(w, "DNS Queries,%d\n", report.Summary.DNSQueries)
	fmt.Fprintf(w, "Suspicious Domains,%d\n\n", report.Summary.SuspiciousDomains)

	// Sections
	for _, section := range report.Sections {
		fmt.Fprintf(w, "=== %s ===\n", section.Title)
		fmt.Fprintf(w, "%s\n\n", section.Content)
	}

	// Top threats
	if len(report.TopThreats) > 0 {
		fmt.Fprintln(w, "=== TOP THREATS ===")
		fmt.Fprintln(w, "Type,Source,Count,Blocked")
		for _, t := range report.TopThreats {
			fmt.Fprintf(w, "%s,%s,%d,%v\n", t.Type, t.Source, t.Count, t.Blocked)
		}
		fmt.Fprintln(w)
	}

	// Top users
	if len(report.TopUsers) > 0 {
		fmt.Fprintln(w, "=== TOP AFFECTED USERS ===")
		fmt.Fprintln(w, "Email,Threats,Risk Score")
		for _, u := range report.TopUsers {
			fmt.Fprintf(w, "%s,%d,%.1f\n", u.Email, u.ThreatCount, u.RiskScore)
		}
		fmt.Fprintln(w)
	}

	// Top countries
	if len(report.TopCountries) > 0 {
		fmt.Fprintln(w, "=== TOP COUNTRIES ===")
		fmt.Fprintln(w, "Country,Threats")
		for _, c := range report.TopCountries {
			fmt.Fprintf(w, "%s,%d\n", c.Country, c.Count)
		}
	}
}

// writeReportHTML writes report as HTML
func (s *Server) writeReportHTML(w http.ResponseWriter, report *threatintel.Report) {
	fmt.Fprintln(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Threat Intelligence Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
.container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
h2 { color: #16213e; margin-top: 30px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 20px 0; }
.stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
.stat-card .value { font-size: 2em; font-weight: bold; }
.stat-card .label { opacity: 0.9; margin-top: 5px; }
table { width: 100%; border-collapse: collapse; margin: 20px 0; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
th { background: #16213e; color: white; }
tr:hover { background: #f5f5f5; }
.section { margin: 30px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; }
.high-risk { color: #e94560; font-weight: bold; }
.footer { margin-top: 40px; text-align: center; color: #666; font-size: 0.9em; }
</style>
</head>
<body>
<div class="container">`)

	fmt.Fprintf(w, "<h1>%s</h1>\n", report.Title)
	fmt.Fprintf(w, "<p><strong>Generated:</strong> %s</p>\n", report.GeneratedAt.Format("January 2, 2006 at 3:04 PM"))
	fmt.Fprintf(w, "<p><strong>Period:</strong> %s to %s</p>\n",
		report.StartDate.Format("January 2, 2006"),
		report.EndDate.Format("January 2, 2006"))

	// Summary cards
	fmt.Fprintln(w, `<h2>Summary</h2><div class="summary">`)
	fmt.Fprintf(w, `<div class="stat-card"><div class="value">%d</div><div class="label">Total Threats</div></div>`, report.Summary.TotalThreats)
	fmt.Fprintf(w, `<div class="stat-card"><div class="value">%d</div><div class="label">Blocked</div></div>`, report.Summary.BlockedThreats)
	fmt.Fprintf(w, `<div class="stat-card"><div class="value">%d</div><div class="label">Unique Users</div></div>`, report.Summary.UniqueUsers)
	fmt.Fprintf(w, `<div class="stat-card"><div class="value">%d</div><div class="label">Countries</div></div>`, report.Summary.UniqueCountries)
	fmt.Fprintf(w, `<div class="stat-card"><div class="value">%d</div><div class="label">High Risk Users</div></div>`, report.Summary.HighRiskUsers)
	fmt.Fprintf(w, `<div class="stat-card"><div class="value">%d</div><div class="label">DNS Queries</div></div>`, report.Summary.DNSQueries)
	fmt.Fprintln(w, `</div>`)

	// Sections
	for _, section := range report.Sections {
		fmt.Fprintf(w, `<div class="section"><h2>%s</h2><p>%s</p></div>`, section.Title, section.Content)
	}

	// Top threats table
	if len(report.TopThreats) > 0 {
		fmt.Fprintln(w, `<h2>Top Threats</h2><table><tr><th>Type</th><th>Source</th><th>Count</th><th>Blocked</th></tr>`)
		for _, t := range report.TopThreats {
			blocked := "No"
			if t.Blocked {
				blocked = "Yes"
			}
			fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`, t.Type, t.Source, t.Count, blocked)
		}
		fmt.Fprintln(w, `</table>`)
	}

	// Top users table
	if len(report.TopUsers) > 0 {
		fmt.Fprintln(w, `<h2>Top Affected Users</h2><table><tr><th>User</th><th>Threats</th><th>Risk Score</th></tr>`)
		for _, u := range report.TopUsers {
			riskClass := ""
			if u.RiskScore >= 70 {
				riskClass = ` class="high-risk"`
			}
			fmt.Fprintf(w, `<tr><td>%s</td><td>%d</td><td%s>%.1f</td></tr>`, u.Email, u.ThreatCount, riskClass, u.RiskScore)
		}
		fmt.Fprintln(w, `</table>`)
	}

	// Top countries table
	if len(report.TopCountries) > 0 {
		fmt.Fprintln(w, `<h2>Top Countries</h2><table><tr><th>Country</th><th>Threats</th></tr>`)
		for _, c := range report.TopCountries {
			fmt.Fprintf(w, `<tr><td>%s</td><td>%d</td></tr>`, c.Country, c.Count)
		}
		fmt.Fprintln(w, `</table>`)
	}

	fmt.Fprintln(w, `<div class="footer">Generated by Xray Threat Intelligence System</div></div></body></html>`)
}
