package server

import (
	"encoding/json"
	"fmt"
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

// handleAIChatStream handles streaming AI chat requests
func (s *Server) handleAIChatStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.aleria == nil || !s.aleria.IsConfigured() {
		http.Error(w, "AI service not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		Message   string `json:"message"`
		History   []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"history,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	// Set up SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Save user message to DB if session provided
	if req.SessionID != "" {
		s.storage.AddChatMessage(r.Context(), req.SessionID, "user", req.Message, 0)

		// Update session title with first user message (truncated)
		session, _ := s.storage.GetChatSession(r.Context(), req.SessionID)
		if session != nil && session.Title == "Новый чат" {
			title := req.Message
			if len(title) > 50 {
				title = title[:50] + "..."
			}
			s.storage.UpdateChatSessionTitle(r.Context(), req.SessionID, title)
		}
	}

	// Build history for AI
	chatReq := &aleria.ChatQueryRequest{
		Message: req.Message,
	}
	for _, h := range req.History {
		chatReq.History = append(chatReq.History, struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{
			Role:    h.Role,
			Content: h.Content,
		})
	}

	var fullResponse strings.Builder

	err := s.aleria.QueryStream(r.Context(), chatReq, func(content string, done bool) {
		if done {
			// Save assistant response to DB
			if req.SessionID != "" && fullResponse.Len() > 0 {
				s.storage.AddChatMessage(r.Context(), req.SessionID, "assistant", fullResponse.String(), 0)
			}

			// Send done event
			fmt.Fprintf(w, "data: {\"done\": true}\n\n")
			flusher.Flush()
			return
		}

		fullResponse.WriteString(content)

		// Send chunk
		chunk := map[string]interface{}{
			"content": content,
			"done":    false,
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	})

	if err != nil {
		errData, _ := json.Marshal(map[string]interface{}{
			"error": err.Error(),
			"done":  true,
		})
		fmt.Fprintf(w, "data: %s\n\n", errData)
		flusher.Flush()
	}
}

// handleAIChatSessions handles chat session management
func (s *Server) handleAIChatSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		// List all sessions
		sessions, err := s.storage.GetChatSessions(ctx, 50)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(sessions)

	case http.MethodPost:
		// Create new session
		var req struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req.Title = "Новый чат"
		}
		if req.Title == "" {
			req.Title = "Новый чат"
		}

		session, err := s.storage.CreateChatSession(ctx, req.Title)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(session)

	case http.MethodDelete:
		// Clear all sessions
		if err := s.storage.ClearAllChatSessions(ctx); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAIChatSession handles single session operations
func (s *Server) handleAIChatSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	// Extract session ID from path: /api/ai/sessions/{id}
	prefix := "/api/ai/sessions/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	sessionID := strings.TrimPrefix(r.URL.Path, prefix)
	if sessionID == "" {
		http.Error(w, "session ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get session with messages
		session, err := s.storage.GetChatSession(ctx, sessionID)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		if session == nil {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}

		messages, err := s.storage.GetChatMessages(ctx, sessionID, 100)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"session":  session,
			"messages": messages,
		})

	case http.MethodPatch:
		// Update session title
		var req struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Title == "" {
			http.Error(w, "title required", http.StatusBadRequest)
			return
		}

		if err := s.storage.UpdateChatSessionTitle(ctx, sessionID, req.Title); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})

	case http.MethodDelete:
		// Delete session
		if err := s.storage.DeleteChatSession(ctx, sessionID); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
