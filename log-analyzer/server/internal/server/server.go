package server

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xray-log-analyzer/server/internal/analyzer"
	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/storage"
)

// Server handles WebSocket connections from agents and HTTP API
type Server struct {
	addr      string
	analyzer  *analyzer.Analyzer
	storage   *storage.Storage
	blacklist *blacklist.Blacklist
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
func New(addr string, analyzer *analyzer.Analyzer, storage *storage.Storage, bl *blacklist.Blacklist) *Server {
	return &Server{
		addr:      addr,
		analyzer:  analyzer,
		storage:   storage,
		blacklist: bl,
		clients:   make(map[string]*Client),
	}
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.handleWebSocket)

	// API endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/nodes", s.handleNodes)
	mux.HandleFunc("/api/nodes/delete", s.handleDeleteNode)
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/users/all", s.handleAllUsers)
	mux.HandleFunc("/api/users/", s.handleUserDetails)
	mux.HandleFunc("/api/hourly", s.handleHourlyStats)
	mux.HandleFunc("/api/anomalies", s.handleAnomalies)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/blacklist/stats", s.handleBlacklistStats)
	mux.HandleFunc("/api/blacklist/analytics", s.handleBlacklistAnalytics)
	mux.HandleFunc("/health", s.handleHealth)

	// Start cleanup job for inactive nodes
	go s.startCleanupJob(ctx)

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

	return server.ListenAndServe()
}

// startCleanupJob runs periodic cleanup of inactive nodes
func (s *Server) startCleanupJob(ctx context.Context) {
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
}
