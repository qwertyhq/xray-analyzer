package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
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
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/users/all", s.handleAllUsers)
	mux.HandleFunc("/health", s.handleHealth)

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

	nodes, err := s.storage.GetNodeStats(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var totalRequests, totalBlacklist int64
	for _, n := range nodes {
		totalRequests += n.TotalRequests
		totalBlacklist += n.BlacklistHits
	}

	s.clientsMu.RLock()
	connectedCount := len(s.clients)
	s.clientsMu.RUnlock()

	stats := map[string]interface{}{
		"total_requests":  totalRequests,
		"total_blacklist": totalBlacklist,
		"nodes_total":     len(nodes),
		"nodes_connected": connectedCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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
