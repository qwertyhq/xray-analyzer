package server

import (
	"context"
	"log"
	"net/http"
	"strings"
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
	apiToken       string // Bearer token for API/dashboard (empty = no auth)
	agentToken     string // Token for agent WebSocket (empty = no auth)
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
func New(addr string, allowedOrigins []string, apiToken, agentToken string, analyzer *analyzer.Analyzer, storage *storage.Storage, bl *blacklist.Blacklist) *Server {
	s := &Server{
		addr:             addr,
		allowedOrigins:   allowedOrigins,
		apiToken:         apiToken,
		agentToken:       agentToken,
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

// requireAPIToken wraps a handler with Bearer token authentication
func (s *Server) requireAPIToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiToken == "" {
			next(w, r)
			return
		}
		// Trust requests from localhost (Next.js SSR in same container)
		if isLocalRequest(r) {
			next(w, r)
			return
		}
		token := extractToken(r)
		if token != s.apiToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// isLocalRequest checks if the request comes from localhost
func isLocalRequest(r *http.Request) bool {
	host := r.RemoteAddr
	return strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "[::1]:") || strings.HasPrefix(host, "localhost:")
}

// requireAgentToken wraps a handler with agent token authentication
func (s *Server) requireAgentToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.agentToken == "" {
			next(w, r)
			return
		}
		token := extractToken(r)
		if token != s.agentToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// extractToken gets token from Authorization header or query param
func extractToken(r *http.Request) string {
	// Check Authorization: Bearer <token>
	if auth := r.Header.Get("Authorization"); auth != "" {
		const prefix = "Bearer "
		if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
			return auth[len(prefix):]
		}
	}
	// Check ?token=<token> query param (for WebSocket connections from browser)
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}
	return ""
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// WebSocket endpoints
	mux.HandleFunc("/ws", s.requireAgentToken(s.handleWebSocket))
	mux.HandleFunc("/ws/dashboard", s.requireAPIToken(s.handleDashboardWebSocket))

	// Health (no auth)
	mux.HandleFunc("/health", s.handleHealth)

	// API endpoints (require API token)
	mux.HandleFunc("/api/stats", s.requireAPIToken(s.handleStats))
	mux.HandleFunc("/api/nodes", s.requireAPIToken(s.handleNodes))
	mux.HandleFunc("/api/nodes/delete", s.requireAPIToken(s.handleDeleteNode))
	mux.HandleFunc("/api/users", s.requireAPIToken(s.handleUsers))
	mux.HandleFunc("/api/users/all", s.requireAPIToken(s.handleAllUsers))
	mux.HandleFunc("/api/hourly", s.requireAPIToken(s.handleHourlyStats))
	mux.HandleFunc("/api/anomalies", s.requireAPIToken(s.handleAnomalies))
	mux.HandleFunc("/api/alerts", s.requireAPIToken(s.handleAlerts))
	mux.HandleFunc("/api/blacklist/stats", s.requireAPIToken(s.handleBlacklistStats))
	mux.HandleFunc("/api/blacklist/analytics", s.requireAPIToken(s.handleBlacklistAnalytics))
	mux.HandleFunc("/api/blacklist/abuse", s.requireAPIToken(s.handleSubscriptionAbuse))
	mux.HandleFunc("/api/threatintel/stats", s.requireAPIToken(s.handleThreatIntelStats))
	mux.HandleFunc("/api/threatintel/matches", s.requireAPIToken(s.handleThreatIntelMatches))
	mux.HandleFunc("/api/threatintel/feeds", s.requireAPIToken(s.handleThreatIntelFeeds))
	mux.HandleFunc("/api/threatintel/top-users", s.requireAPIToken(s.handleThreatIntelTopUsers))
	mux.HandleFunc("/api/threatintel/time-stats", s.requireAPIToken(s.handleThreatIntelTimeStats))
	mux.HandleFunc("/api/threatintel/geo-stats", s.requireAPIToken(s.handleThreatIntelGeoStats))
	mux.HandleFunc("/api/threatintel/anomalies", s.requireAPIToken(s.handleThreatIntelAnomalies))
	mux.HandleFunc("/api/threatintel/risk-profiles", s.requireAPIToken(s.handleUserRiskProfiles))
	mux.HandleFunc("/api/threatintel/dns-analysis", s.requireAPIToken(s.handleDNSAnalysis))
	mux.HandleFunc("/api/threatintel/reports", s.requireAPIToken(s.handleReports))
	mux.HandleFunc("/api/threatintel/clear", s.requireAPIToken(s.handleThreatIntelClear))
	mux.HandleFunc("/api/ipinfo", s.requireAPIToken(s.handleIPInfo))

	// Remnawave API endpoints
	mux.HandleFunc("/api/remnawave/stats", s.requireAPIToken(s.handleRemnawaveStats))
	mux.HandleFunc("/api/remnawave/users", s.requireAPIToken(s.handleRemnawaveUsers))
	mux.HandleFunc("/api/remnawave/user/", s.requireAPIToken(s.handleRemnawaveUser))
	mux.HandleFunc("/api/remnawave/hwid/", s.requireAPIToken(s.handleRemnawaveHwid))
	mux.HandleFunc("/api/remnawave/hwid-top", s.requireAPIToken(s.handleRemnawaveHwidTop))
	mux.HandleFunc("/api/remnawave/hwid-clear", s.requireAPIToken(s.handleRemnawavelClearHwid))
	mux.HandleFunc("/api/remnawave/abuse", s.requireAPIToken(s.handleRemnawaveAbuse))
	mux.HandleFunc("/api/remnawave/online", s.requireAPIToken(s.handleRemnawaveOnline))
	mux.HandleFunc("/api/remnawave/sync", s.requireAPIToken(s.handleRemnawaveSync))

	// Correlation API endpoints
	mux.HandleFunc("/api/correlation/stats", s.requireAPIToken(s.handleCorrelationStats))
	mux.HandleFunc("/api/correlation/profiles", s.requireAPIToken(s.handleCorrelationProfiles))
	mux.HandleFunc("/api/correlation/user/", s.requireAPIToken(s.handleCorrelationUser))
	mux.HandleFunc("/api/correlation/shared-ips", s.requireAPIToken(s.handleCorrelationSharedIPs))
	mux.HandleFunc("/api/correlation/shared-hwids", s.requireAPIToken(s.handleCorrelationSharedHWIDs))

	// AI Chat endpoints
	mux.HandleFunc("/api/ai/chat", s.requireAPIToken(s.handleAIChat))
	mux.HandleFunc("/api/ai/chat/stream", s.requireAPIToken(s.handleAIChatStream))
	mux.HandleFunc("/api/ai/sessions", s.requireAPIToken(s.handleAIChatSessions))
	mux.HandleFunc("/api/ai/sessions/", s.requireAPIToken(s.handleAIChatSession))

	// Debug endpoints
	mux.HandleFunc("/api/debug/users", s.requireAPIToken(s.handleDebugUsers))

	// User-specific endpoints (must be registered before /api/users/)
	mux.HandleFunc("/api/users/", s.requireAPIToken(s.handleUserRouter))

	// Start background jobs
	go s.startCleanupJob(ctx)
	go s.startBroadcastLoop(ctx)

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
