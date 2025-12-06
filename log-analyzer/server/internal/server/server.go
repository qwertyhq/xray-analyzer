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

	// Dashboard WebSocket clients
	dashboardClients   map[*websocket.Conn]bool
	dashboardClientsMu sync.RWMutex
	broadcastChan      chan *DashboardUpdate
}

// Client represents a connected agent
type Client struct {
	NodeID      string
	Conn        *websocket.Conn
	ConnectedAt time.Time
	LastBatch   time.Time
	mu          sync.Mutex
}

// DashboardUpdate represents an update to send to dashboard clients
type DashboardUpdate struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// New creates a new Server
func New(addr string, analyzer *analyzer.Analyzer, storage *storage.Storage, bl *blacklist.Blacklist) *Server {
	s := &Server{
		addr:             addr,
		analyzer:         analyzer,
		storage:          storage,
		blacklist:        bl,
		clients:          make(map[string]*Client),
		dashboardClients: make(map[*websocket.Conn]bool),
		broadcastChan:    make(chan *DashboardUpdate, 100),
	}
	return s
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// WebSocket endpoints
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/ws/dashboard", s.handleDashboardWebSocket)

	// API endpoints (keep for backwards compatibility)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/nodes", s.handleNodes)
	mux.HandleFunc("/api/nodes/delete", s.handleDeleteNode)
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/users/all", s.handleAllUsers)
	mux.HandleFunc("/api/hourly", s.handleHourlyStats)
	mux.HandleFunc("/api/anomalies", s.handleAnomalies)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/blacklist/stats", s.handleBlacklistStats)
	mux.HandleFunc("/api/blacklist/analytics", s.handleBlacklistAnalytics)
	mux.HandleFunc("/health", s.handleHealth)

	// User-specific endpoints (must be registered before /api/users/)
	mux.HandleFunc("/api/users/", s.handleUserRouter)

	// Start background jobs
	go s.startCleanupJob(ctx)
	go s.startBroadcastLoop(ctx)
	go s.startPeriodicBroadcast(ctx)

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

// startCleanupJob runs periodic cleanup of inactive nodes and old data
func (s *Server) startCleanupJob(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Run cleanup on startup
	s.storage.CleanupOldData(context.Background(), 30) // 30 days retention

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.storage.CleanupInactiveNodes(context.Background(), 24*time.Hour)
			s.storage.CleanupOldData(context.Background(), 30) // 30 days retention
		}
	}
}
