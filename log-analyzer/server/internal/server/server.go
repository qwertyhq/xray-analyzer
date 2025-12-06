package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xray-log-analyzer/server/internal/analyzer"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/storage"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 64,
	WriteBufferSize: 1024 * 64,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for now
	},
}

// Server handles WebSocket connections from agents
type Server struct {
	addr      string
	analyzer  *analyzer.Analyzer
	storage   *storage.Storage
	clients   map[string]*Client
	clientsMu sync.RWMutex
}

// Client represents a connected agent
type Client struct {
	NodeID      string
	Conn        *websocket.Conn
	ConnectedAt time.Time
	LastBatch   time.Time
	mu          sync.Mutex
}

// New creates a new Server
func New(addr string, analyzer *analyzer.Analyzer, storage *storage.Storage) *Server {
	return &Server{
		addr:     addr,
		analyzer: analyzer,
		storage:  storage,
		clients:  make(map[string]*Client),
	}
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/nodes", s.handleNodes)
	mux.HandleFunc("/api/nodes/delete", s.handleDeleteNode)
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/users/all", s.handleAllUsers)
	mux.HandleFunc("/api/users/", s.handleUserDetails)
	mux.HandleFunc("/api/hourly", s.handleHourlyStats)
	mux.HandleFunc("/api/anomalies", s.handleAnomalies)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/health", s.handleHealth)

	// Start cleanup job for inactive nodes (older than 24 hours)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.storage.CleanupInactiveNodes(context.Background(), 24*time.Hour)
			}
		}
	}()

	server := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		log.Println("server: shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Printf("server: listening on %s", s.addr)
	return server.ListenAndServe()
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("server: upgrade error: %v", err)
		return
	}

	// Wait for handshake
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Printf("server: handshake error: %v", err)
		conn.Close()
		return
	}

	var handshake struct {
		Type   string `json:"type"`
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(message, &handshake); err != nil || handshake.Type != "handshake" || handshake.NodeID == "" {
		log.Printf("server: invalid handshake")
		conn.Close()
		return
	}

	// Reset deadline
	conn.SetReadDeadline(time.Time{})

	client := &Client{
		NodeID:      handshake.NodeID,
		Conn:        conn,
		ConnectedAt: time.Now(),
	}

	s.clientsMu.Lock()
	// Close existing connection for this node
	if existing, ok := s.clients[handshake.NodeID]; ok {
		existing.Conn.Close()
	}
	s.clients[handshake.NodeID] = client
	s.clientsMu.Unlock()

	log.Printf("server: agent connected: %s", handshake.NodeID)

	// Handle messages
	s.handleClient(client)

	// Cleanup
	s.clientsMu.Lock()
	delete(s.clients, handshake.NodeID)
	s.clientsMu.Unlock()

	log.Printf("server: agent disconnected: %s", handshake.NodeID)
}

// handleClient processes messages from a client
func (s *Server) handleClient(client *Client) {
	ctx := context.Background()

	// Start ping ticker
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	go func() {
		for range pingTicker.C {
			client.mu.Lock()
			err := client.Conn.WriteJSON(map[string]string{"type": "ping"})
			client.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	for {
		messageType, message, err := client.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("server: read error from %s: %v", client.NodeID, err)
			}
			return
		}

		if messageType == websocket.BinaryMessage {
			// Decompress gzip
			gz, err := gzip.NewReader(bytes.NewReader(message))
			if err != nil {
				log.Printf("server: gzip error from %s: %v", client.NodeID, err)
				continue
			}

			data, err := io.ReadAll(gz)
			gz.Close()
			if err != nil {
				log.Printf("server: decompress error from %s: %v", client.NodeID, err)
				continue
			}
			message = data
		}

		// Parse batch
		var batch models.LogBatch
		if err := json.Unmarshal(message, &batch); err != nil {
			log.Printf("server: parse error from %s: %v", client.NodeID, err)
			continue
		}

		client.LastBatch = time.Now()

		// Process batch
		processed, blacklistHits, err := s.analyzer.ProcessBatch(ctx, &batch)
		if err != nil {
			log.Printf("server: process error: %v", err)
		}

		log.Printf("server: processed batch from %s: %d entries, %d blacklist hits",
			client.NodeID, processed, blacklistHits)

		// Send acknowledgement
		ack := models.ServerMessage{
			Type:      "ack",
			Processed: processed,
		}
		client.mu.Lock()
		client.Conn.WriteJSON(ack)
		client.mu.Unlock()
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// handleAllUsers returns all users sorted by requests
func (s *Server) handleAllUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := s.storage.GetAllUsers(ctx, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// handleHealth returns server health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleDeleteNode deletes a node and its data
func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Try query param first, then JSON body
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		var body struct {
			NodeID string `json:"node_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			nodeID = body.NodeID
		}
	}

	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	// Don't delete connected nodes
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

	log.Printf("server: deleted node %s via API", nodeID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "node_id": nodeID})
}

// GetConnectedClients returns list of connected node IDs
func (s *Server) GetConnectedClients() []string {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	nodes := make([]string, 0, len(s.clients))
	for nodeID := range s.clients {
		nodes = append(nodes, nodeID)
	}
	return nodes
}

// handleUserDetails returns detailed stats for a specific user
func (s *Server) handleUserDetails(w http.ResponseWriter, r *http.Request) {
	// Extract user email from URL path: /api/users/{email}
	path := r.URL.Path
	prefix := "/api/users/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "user email required", http.StatusBadRequest)
		return
	}
	userEmail := strings.TrimPrefix(path, prefix)

	// URL decode the email
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

// handleHourlyStats returns hourly statistics for charts
func (s *Server) handleHourlyStats(w http.ResponseWriter, r *http.Request) {
	hoursStr := r.URL.Query().Get("hours")
	hours := 24 // default
	if hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 && h <= 168 {
			hours = h
		}
	}

	// Time range filter
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

// handleAnomalies detects and returns anomalies (spikes in blacklist hits)
func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get hourly stats for the last 48 hours to calculate baseline
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

	// Calculate baseline (average) excluding last 2 hours
	var sumRequests, sumBlacklist int64
	baseline := stats[:len(stats)-2]
	for _, s := range baseline {
		sumRequests += s.TotalRequests
		sumBlacklist += s.BlacklistHits
	}
	avgRequests := float64(sumRequests) / float64(len(baseline))
	avgBlacklist := float64(sumBlacklist) / float64(len(baseline))

	// Detect anomalies in recent hours (2x or more than average)
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

	// Also check for users with sudden spikes
	userAnomalies, _ := s.storage.GetUserAnomalies(ctx, 5) // Top 5 users with spikes
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
