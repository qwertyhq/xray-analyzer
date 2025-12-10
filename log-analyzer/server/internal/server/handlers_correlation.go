package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// handleCorrelationStats returns correlation statistics
func (s *Server) handleCorrelationStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.storage.GetCorrelationStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(stats)
}

// handleCorrelationProfiles returns AI profiles for users
func (s *Server) handleCorrelationProfiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	limit := 100
	minRiskScore := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	if m := r.URL.Query().Get("min_risk"); m != "" {
		if parsed, err := strconv.Atoi(m); err == nil && parsed >= 0 {
			minRiskScore = parsed
		}
	}

	profiles, err := s.storage.GetAllUserAIProfiles(r.Context(), limit, minRiskScore)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"profiles": profiles,
		"total":    len(profiles),
	})
}

// handleCorrelationUser returns detailed correlation data for a specific user
func (s *Server) handleCorrelationUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract username from path: /api/correlation/user/{username}
	path := strings.TrimPrefix(r.URL.Path, "/api/correlation/user/")
	userEmail := strings.TrimSuffix(path, "/")

	if userEmail == "" {
		http.Error(w, "User email required", http.StatusBadRequest)
		return
	}

	if s.correlation == nil {
		http.Error(w, "Correlation service not available", http.StatusServiceUnavailable)
		return
	}

	correlations, err := s.correlation.GetUserCorrelations(r.Context(), userEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(correlations)
}

// handleCorrelationSharedIPs returns IPs shared by multiple users
func (s *Server) handleCorrelationSharedIPs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	sharedIPs, err := s.storage.GetTopSharedIPs(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enrich with users for each IP
	type EnrichedSharedIP struct {
		IPAddress     string   `json:"ip_address"`
		UserCount     int      `json:"user_count"`
		LastSeen      string   `json:"last_seen"`
		TotalRequests int      `json:"total_requests"`
		Users         []string `json:"users"`
	}

	var enriched []EnrichedSharedIP
	for _, ip := range sharedIPs {
		eip := EnrichedSharedIP{
			IPAddress:     ip.IPAddress,
			UserCount:     ip.UserCount,
			LastSeen:      ip.LastSeen.Format("2006-01-02 15:04:05"),
			TotalRequests: ip.TotalRequests,
		}

		// Get users for this IP and resolve their usernames
		users, err := s.storage.GetUsersForIP(r.Context(), ip.IPAddress)
		if err == nil {
			for _, u := range users {
				username := u.UserEmail
				if s.remnawave != nil {
					username = s.remnawave.ResolveUsername(r.Context(), u.UserEmail)
				}
				eip.Users = append(eip.Users, username)
			}
		}

		enriched = append(enriched, eip)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"shared_ips": enriched,
		"total":      len(enriched),
	})
}

// handleCorrelationSharedHWIDs returns HWIDs shared by multiple users
func (s *Server) handleCorrelationSharedHWIDs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	sharedHWIDs, err := s.storage.GetTopSharedHWIDs(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enrich with users for each HWID
	type EnrichedSharedHWID struct {
		HWID          string   `json:"hwid"`
		Platform      string   `json:"platform"`
		UserCount     int      `json:"user_count"`
		LastSeen      string   `json:"last_seen"`
		TotalRequests int      `json:"total_requests"`
		Users         []string `json:"users"`
	}

	var enriched []EnrichedSharedHWID
	for _, hwid := range sharedHWIDs {
		ehwid := EnrichedSharedHWID{
			HWID:          hwid.HWID,
			Platform:      hwid.Platform,
			UserCount:     hwid.UserCount,
			LastSeen:      hwid.LastSeen.Format("2006-01-02 15:04:05"),
			TotalRequests: hwid.TotalRequests,
		}

		// Get users for this HWID and resolve their usernames
		users, err := s.storage.GetUsersForHWID(r.Context(), hwid.HWID)
		if err == nil {
			for _, u := range users {
				username := u.UserEmail
				if s.remnawave != nil {
					username = s.remnawave.ResolveUsername(r.Context(), u.UserEmail)
				}
				ehwid.Users = append(ehwid.Users, username)
			}
		}

		enriched = append(enriched, ehwid)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"shared_hwids": enriched,
		"total":        len(enriched),
	})
}
