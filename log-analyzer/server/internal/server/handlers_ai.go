package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/xray-log-analyzer/server/internal/aleria"
)

// handleAIChat handles AI chat requests
func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.aleria == nil || !s.aleria.IsConfigured() {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "AI service not configured",
			"enabled": false,
		})
		return
	}

	var req aleria.ChatQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	resp, err := s.aleria.Query(r.Context(), &req)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"response":    resp.Response,
		"tokens_used": resp.TokensUsed,
	})
}

// handleAIAnalyzeUser handles AI analysis of a specific user
func (s *Server) handleAIAnalyzeUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.aleria == nil || !s.aleria.IsConfigured() {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "AI service not configured",
			"enabled": false,
		})
		return
	}

	// Extract user email from path
	prefix := "/api/ai/analyze-user/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	email := strings.TrimPrefix(r.URL.Path, prefix)
	if email == "" {
		http.Error(w, "user email required", http.StatusBadRequest)
		return
	}

	resp, err := s.aleria.AnalyzeUser(r.Context(), email)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_email":  email,
		"analysis":    resp.Response,
		"tokens_used": resp.TokensUsed,
	})
}
