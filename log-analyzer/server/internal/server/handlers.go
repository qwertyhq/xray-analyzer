package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
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
