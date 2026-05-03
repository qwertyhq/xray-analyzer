package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xray-log-analyzer/server/internal/models"
)

// createUpgrader creates a WebSocket upgrader with origin checking
func (s *Server) createUpgrader(readBuf, writeBuf int) websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  readBuf,
		WriteBufferSize: writeBuf,
		CheckOrigin: func(r *http.Request) bool {
			// If no allowed origins configured, allow all (for development)
			if len(s.allowedOrigins) == 0 {
				return true
			}
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // Allow requests without Origin header (non-browser clients)
			}
			for _, allowed := range s.allowedOrigins {
				if origin == allowed {
					return true
				}
			}
			log.Printf("server: rejected WebSocket connection from origin: %s", origin)
			return false
		},
	}
}

// handleWebSocket handles WebSocket connections from agents
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := s.createUpgrader(1024*64, 1024*64)
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

	// Handle messages
	s.handleClient(client)

	// Cleanup — only delete the map entry if it's still *this* client.
	// A concurrent reconnect may have already replaced us; removing the
	// entry blindly would orphan the active reconnect and make its node
	// look Offline in the UI even though batches still arrive.
	s.clientsMu.Lock()
	if s.clients[handshake.NodeID] == client {
		delete(s.clients, handshake.NodeID)
	}
	s.clientsMu.Unlock()
}

// handleClient processes messages from a connected client
func (s *Server) handleClient(client *Client) {
	ctx := context.Background()

	// Start ping ticker with done channel for cleanup
	pingTicker := time.NewTicker(30 * time.Second)
	pingDone := make(chan struct{})
	defer func() {
		pingTicker.Stop()
		close(pingDone)
	}()

	go func() {
		for {
			select {
			case <-pingDone:
				return
			case <-pingTicker.C:
				client.mu.Lock()
				err := client.Conn.WriteJSON(map[string]string{"type": "ping"})
				client.mu.Unlock()
				if err != nil {
					return
				}
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

		if messageType != websocket.BinaryMessage {
			// Text messages are control messages (pong, etc.) — ignore
			continue
		}

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

		// Parse batch
		var batch models.LogBatch
		if err := json.Unmarshal(message, &batch); err != nil {
			log.Printf("server: parse error from %s: %v", client.NodeID, err)
			continue
		}

		// Safety: ignore batches without node_id (shouldn't happen after handshake)
		if batch.NodeID == "" {
			batch.NodeID = client.NodeID
		}

		client.LastBatch = time.Now()

		// Process batch
		processed, _, err := s.analyzer.ProcessBatch(ctx, &batch)
		if err != nil {
			log.Printf("server: process error: %v", err)
		}

		// Send acknowledgement
		ack := models.ServerMessage{
			Type:      "ack",
			Processed: processed,
		}
		client.mu.Lock()
		client.Conn.WriteJSON(ack)
		client.mu.Unlock()

		// Broadcast update to dashboard clients
		s.BroadcastDashboardUpdate()
	}
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

// handleDashboardWebSocket handles WebSocket connections from dashboard
func (s *Server) handleDashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := s.createUpgrader(1024, 1024*64)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("server: dashboard upgrade error: %v", err)
		return
	}

	// Create dashboard client wrapper
	client := &DashboardClient{Conn: conn}

	// Register client
	s.dashboardClientsMu.Lock()
	s.dashboardClients[client] = true
	clientCount := len(s.dashboardClients)
	s.dashboardClientsMu.Unlock()

	log.Printf("server: dashboard client connected, total: %d", clientCount)

	// Send initial data
	s.sendFullDashboardData(client)

	// Handle incoming messages (for ping/pong)
	defer func() {
		s.dashboardClientsMu.Lock()
		delete(s.dashboardClients, client)
		remainingCount := len(s.dashboardClients)
		s.dashboardClientsMu.Unlock()
		conn.Close()
		log.Printf("server: dashboard client disconnected, total: %d", remainingCount)
	}()

	// Keep connection alive
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("server: dashboard read error: %v", err)
			}
			break
		}
	}
}

// sendFullDashboardData sends all dashboard data to a single client
func (s *Server) sendFullDashboardData(client *DashboardClient) {
	ctx := context.Background()

	// Stats
	if stats, err := s.storage.GetGlobalStats(ctx); err == nil {
		connectedNodes := s.GetConnectedClients()
		stats.NodesConnected = len(connectedNodes)
		client.mu.Lock()
		client.Conn.WriteJSON(&DashboardUpdate{Type: "stats", Data: stats})
		client.mu.Unlock()
	}

	// Nodes
	if nodes, err := s.storage.GetNodeStats(ctx); err == nil {
		connectedNodes := s.GetConnectedClients()
		connectedMap := make(map[string]bool)
		for _, n := range connectedNodes {
			connectedMap[n] = true
		}
		for _, n := range nodes {
			n.IsConnected = connectedMap[n.NodeID]
		}
		client.mu.Lock()
		client.Conn.WriteJSON(&DashboardUpdate{Type: "nodes", Data: nodes})
		client.mu.Unlock()
	}

	// Users (top 500 for dashboard)
	if users, err := s.storage.GetAllUsers(ctx, 500); err == nil {
		// Resolve numeric IDs to usernames via Remnawave API
		s.resolveUserDisplayNames(ctx, users)
		client.mu.Lock()
		client.Conn.WriteJSON(&DashboardUpdate{Type: "users", Data: users})
		client.mu.Unlock()
	}

	// Hourly stats (24h)
	if hourly, err := s.storage.GetHourlyStats(ctx, 24); err == nil {
		client.mu.Lock()
		client.Conn.WriteJSON(&DashboardUpdate{Type: "hourly", Data: hourly})
		client.mu.Unlock()
	}

	// Anomalies
	if anomalies := s.getAnomalies(ctx); anomalies != nil {
		client.mu.Lock()
		client.Conn.WriteJSON(&DashboardUpdate{Type: "anomalies", Data: anomalies})
		client.mu.Unlock()
	}

	// Blacklist analytics
	since := time.Now().Add(-24 * time.Hour)
	if analytics, err := s.storage.GetBlacklistAnalytics(ctx, since); err == nil {
		// Resolve usernames for recent matches
		s.resolveBlacklistMatches(ctx, analytics.RecentMatches)
		client.mu.Lock()
		client.Conn.WriteJSON(&DashboardUpdate{Type: "blacklist", Data: analytics})
		client.mu.Unlock()
	}

	// Threat intelligence
	s.sendThreatIntelUpdate(client)
}

// BroadcastDashboardUpdate triggers a broadcast to all dashboard clients
func (s *Server) BroadcastDashboardUpdate() {
	select {
	case s.broadcastChan <- &DashboardUpdate{Type: "refresh"}:
	default:
		// Channel full, skip
	}
}

// startBroadcastLoop handles broadcasting updates to dashboard clients with throttling.
// Broadcasts are triggered by events (incoming batches) but rate-limited to avoid
// hammering the DB when many nodes send batches at once.
func (s *Server) startBroadcastLoop(ctx context.Context) {
	const minInterval = 3 * time.Second // throttle window
	const maxInterval = 10 * time.Second // keepalive (send even if no events)

	var lastBroadcast time.Time
	pending := false
	timer := time.NewTimer(maxInterval)
	defer timer.Stop()

	broadcast := func() {
		// Skip if no dashboard clients connected
		s.dashboardClientsMu.RLock()
		hasClients := len(s.dashboardClients) > 0
		s.dashboardClientsMu.RUnlock()
		if !hasClients {
			pending = false
			return
		}
		s.broadcastToDashboards()
		lastBroadcast = time.Now()
		pending = false
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.broadcastChan:
			// Event received — broadcast if enough time passed, otherwise mark pending
			if time.Since(lastBroadcast) >= minInterval {
				broadcast()
				timer.Reset(maxInterval)
			} else {
				pending = true
			}
		case <-timer.C:
			// Timer fired — flush pending or send keepalive
			if pending || time.Since(lastBroadcast) >= maxInterval {
				broadcast()
			}
			timer.Reset(minInterval)
		}
	}
}

// broadcastToDashboards sends current data to all connected dashboard clients
func (s *Server) broadcastToDashboards() {
	s.dashboardClientsMu.RLock()
	clients := make([]*DashboardClient, 0, len(s.dashboardClients))
	for client := range s.dashboardClients {
		clients = append(clients, client)
	}
	s.dashboardClientsMu.RUnlock()

	if len(clients) == 0 {
		return
	}

	ctx := context.Background()

	// Prepare all data
	var updates []DashboardUpdate

	// Stats
	if stats, err := s.storage.GetGlobalStats(ctx); err == nil {
		connectedNodes := s.GetConnectedClients()
		stats.NodesConnected = len(connectedNodes)
		updates = append(updates, DashboardUpdate{Type: "stats", Data: stats})
	}

	// Nodes
	if nodes, err := s.storage.GetNodeStats(ctx); err == nil {
		connectedNodes := s.GetConnectedClients()
		connectedMap := make(map[string]bool)
		for _, n := range connectedNodes {
			connectedMap[n] = true
		}
		for _, n := range nodes {
			n.IsConnected = connectedMap[n.NodeID]
		}
		updates = append(updates, DashboardUpdate{Type: "nodes", Data: nodes})
	}

	// Users (top 500 for dashboard)
	if users, err := s.storage.GetAllUsers(ctx, 500); err == nil {
		// Resolve numeric IDs to usernames via Remnawave API
		s.resolveUserDisplayNames(ctx, users)
		updates = append(updates, DashboardUpdate{Type: "users", Data: users})
	}

	// Blacklist analytics (with recent matches)
	since := time.Now().Add(-24 * time.Hour)
	if analytics, err := s.storage.GetBlacklistAnalytics(ctx, since); err == nil {
		// Resolve usernames for recent matches
		s.resolveBlacklistMatches(ctx, analytics.RecentMatches)
		updates = append(updates, DashboardUpdate{Type: "blacklist", Data: analytics})
	}

	// Threat intelligence
	if s.threatIntel != nil {
		tiStats := s.threatIntel.GetStats()
		tiMatches, err := s.storage.GetThreatMatches(ctx, 20)
		if err != nil {
			log.Printf("server: failed to get threat matches: %v", err)
			tiMatches = nil
		}
		tiRecentUsers, err := s.threatIntel.GetRecentUsersByAllCategories(ctx, 10)
		if err != nil {
			log.Printf("server: failed to get recent users by categories: %v", err)
			tiRecentUsers = nil
		}
		// Resolve usernames for matches and recent users
		if tiMatches != nil {
			s.resolveThreatMatches(ctx, tiMatches)
		}
		if tiRecentUsers != nil {
			s.resolveCategoryTopUsers(ctx, tiRecentUsers)
		}
		threatData := map[string]interface{}{
			"stats":    tiStats,
			"matches":  tiMatches,
			"topUsers": tiRecentUsers,
		}
		updates = append(updates, DashboardUpdate{Type: "threatintel", Data: threatData})
	}

	// Send to all clients
	for _, client := range clients {
		client.mu.Lock()
		for _, update := range updates {
			if err := client.Conn.WriteJSON(&update); err != nil {
				// Client will be removed on next read error
				break
			}
		}
		client.mu.Unlock()
	}
}

// getAnomalies returns current anomalies
func (s *Server) getAnomalies(ctx context.Context) []models.Anomaly {
	stats, err := s.storage.GetHourlyStats(ctx, 48)
	if err != nil || len(stats) < 6 {
		return nil
	}

	var sumRequests, sumBlacklist int64
	baseline := stats[:len(stats)-2]
	for _, st := range baseline {
		sumRequests += st.TotalRequests
		sumBlacklist += st.BlacklistHits
	}
	avgRequests := float64(sumRequests) / float64(len(baseline))
	avgBlacklist := float64(sumBlacklist) / float64(len(baseline))

	var anomalies []models.Anomaly
	recent := stats[len(stats)-2:]
	for _, st := range recent {
		if avgBlacklist > 0 && float64(st.BlacklistHits) > avgBlacklist*2 {
			anomalies = append(anomalies, models.Anomaly{
				Type:      "blacklist_spike",
				Hour:      st.Hour,
				Value:     st.BlacklistHits,
				Baseline:  int64(avgBlacklist),
				Deviation: float64(st.BlacklistHits) / avgBlacklist,
				Message:   "Blacklist hits spike detected",
			})
		}
		if avgRequests > 0 && float64(st.TotalRequests) > avgRequests*3 {
			anomalies = append(anomalies, models.Anomaly{
				Type:      "traffic_spike",
				Hour:      st.Hour,
				Value:     st.TotalRequests,
				Baseline:  int64(avgRequests),
				Deviation: float64(st.TotalRequests) / avgRequests,
				Message:   "Traffic spike detected",
			})
		}
	}

	userAnomalies, _ := s.storage.GetUserAnomalies(ctx, 5)
	anomalies = append(anomalies, userAnomalies...)

	// Sort by time (newest first)
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Hour.After(anomalies[j].Hour)
	})

	return anomalies
}

// sendThreatIntelUpdate sends threat intel data to a single client
func (s *Server) sendThreatIntelUpdate(client *DashboardClient) {
	if s.threatIntel == nil {
		return
	}

	ctx := context.Background()
	tiStats := s.threatIntel.GetStats()
	tiMatches, _ := s.storage.GetThreatMatches(ctx, 20) // Get all stored matches (max 20)
	tiRecentUsers, _ := s.threatIntel.GetRecentUsersByAllCategories(ctx, 10)

	// Resolve usernames for matches and recent users
	if tiMatches != nil {
		s.resolveThreatMatches(ctx, tiMatches)
	}
	if tiRecentUsers != nil {
		s.resolveCategoryTopUsers(ctx, tiRecentUsers)
	}

	threatData := map[string]interface{}{
		"stats":    tiStats,
		"matches":  tiMatches,
		"topUsers": tiRecentUsers,
	}

	client.mu.Lock()
	client.Conn.WriteJSON(&DashboardUpdate{Type: "threatintel", Data: threatData})
	client.mu.Unlock()
}
