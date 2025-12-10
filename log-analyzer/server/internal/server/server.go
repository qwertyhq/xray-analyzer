package server

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xray-log-analyzer/server/internal/aleria"
	"github.com/xray-log-analyzer/server/internal/analyzer"
	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/correlation"
	"github.com/xray-log-analyzer/server/internal/ipinfo"
	"github.com/xray-log-analyzer/server/internal/remnawave"
	"github.com/xray-log-analyzer/server/internal/storage"
	"github.com/xray-log-analyzer/server/internal/threatintel"
)

// Server handles WebSocket connections from agents and HTTP API
type Server struct {
	addr           string
	allowedOrigins []string
	analyzer       *analyzer.Analyzer
	storage        *storage.Storage
	blacklist      *blacklist.Blacklist
	threatIntel    *threatintel.Service
	remnawave      *remnawave.SyncService
	correlation    *correlation.Service
	ipInfo         *ipinfo.Service
	aleria         *aleria.Service
	clients        map[string]*Client
	clientsMu      sync.RWMutex

	// Dashboard WebSocket clients
	dashboardClients   map[*DashboardClient]bool
	dashboardClientsMu sync.RWMutex
	broadcastChan      chan *DashboardUpdate
}

// DashboardClient wraps websocket connection with mutex for thread-safe writes
type DashboardClient struct {
	Conn *websocket.Conn
	mu   sync.Mutex
}

// WriteJSON writes JSON to websocket with mutex protection
func (c *DashboardClient) WriteJSON(v interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.WriteJSON(v)
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
func New(addr string, allowedOrigins []string, analyzer *analyzer.Analyzer, storage *storage.Storage, bl *blacklist.Blacklist) *Server {
	s := &Server{
		addr:             addr,
		allowedOrigins:   allowedOrigins,
		analyzer:         analyzer,
		storage:          storage,
		blacklist:        bl,
		ipInfo:           ipinfo.NewService(),
		clients:          make(map[string]*Client),
		dashboardClients: make(map[*DashboardClient]bool),
		broadcastChan:    make(chan *DashboardUpdate, 100),
	}
	return s
}

// SetThreatIntel sets the threat intelligence service
func (s *Server) SetThreatIntel(ti *threatintel.Service) {
	s.threatIntel = ti
}

// SetRemnawave sets the Remnawave sync service
func (s *Server) SetRemnawave(rw *remnawave.SyncService) {
	s.remnawave = rw
}

// SetCorrelation sets the correlation service
func (s *Server) SetCorrelation(c *correlation.Service) {
	s.correlation = c
}

// SetAleria sets the Aleria AI service
func (s *Server) SetAleria(a *aleria.Service) {
	s.aleria = a
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
	mux.HandleFunc("/api/blacklist/abuse", s.handleSubscriptionAbuse)
	mux.HandleFunc("/api/threatintel/stats", s.handleThreatIntelStats)
	mux.HandleFunc("/api/threatintel/matches", s.handleThreatIntelMatches)
	mux.HandleFunc("/api/threatintel/feeds", s.handleThreatIntelFeeds)
	mux.HandleFunc("/api/threatintel/top-users", s.handleThreatIntelTopUsers)
	mux.HandleFunc("/api/threatintel/time-stats", s.handleThreatIntelTimeStats)
	mux.HandleFunc("/api/threatintel/geo-stats", s.handleThreatIntelGeoStats)
	mux.HandleFunc("/api/threatintel/anomalies", s.handleThreatIntelAnomalies)
	mux.HandleFunc("/api/threatintel/risk-profiles", s.handleUserRiskProfiles)
	mux.HandleFunc("/api/threatintel/dns-analysis", s.handleDNSAnalysis)
	mux.HandleFunc("/api/threatintel/reports", s.handleReports)
	mux.HandleFunc("/api/threatintel/clear", s.handleThreatIntelClear)
	mux.HandleFunc("/api/ipinfo", s.handleIPInfo)
	mux.HandleFunc("/health", s.handleHealth)

	// Remnawave API endpoints
	mux.HandleFunc("/api/remnawave/stats", s.handleRemnawaveStats)
	mux.HandleFunc("/api/remnawave/users", s.handleRemnawaveUsers)
	mux.HandleFunc("/api/remnawave/user/", s.handleRemnawaveUser)
	mux.HandleFunc("/api/remnawave/hwid/", s.handleRemnawaveHwid)
	mux.HandleFunc("/api/remnawave/hwid-top", s.handleRemnawaveHwidTop)
	mux.HandleFunc("/api/remnawave/hwid-clear", s.handleRemnawavelClearHwid)
	mux.HandleFunc("/api/remnawave/abuse", s.handleRemnawaveAbuse)
	mux.HandleFunc("/api/remnawave/online", s.handleRemnawaveOnline)
	mux.HandleFunc("/api/remnawave/sync", s.handleRemnawaveSync)

	// Correlation API endpoints
	mux.HandleFunc("/api/correlation/stats", s.handleCorrelationStats)
	mux.HandleFunc("/api/correlation/profiles", s.handleCorrelationProfiles)
	mux.HandleFunc("/api/correlation/user/", s.handleCorrelationUser)
	mux.HandleFunc("/api/correlation/shared-ips", s.handleCorrelationSharedIPs)
	mux.HandleFunc("/api/correlation/shared-hwids", s.handleCorrelationSharedHWIDs)

	// AI Chat endpoints
	mux.HandleFunc("/api/ai/chat", s.handleAIChat)
	mux.HandleFunc("/api/ai/chat/stream", s.handleAIChatStream)
	mux.HandleFunc("/api/ai/sessions", s.handleAIChatSessions)
	mux.HandleFunc("/api/ai/sessions/", s.handleAIChatSession)

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
