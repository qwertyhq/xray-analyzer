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

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 64,
	WriteBufferSize: 1024 * 64,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// handleWebSocket handles WebSocket connections from agents
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

	// Handle messages
	s.handleClient(client)

	// Cleanup
	s.clientsMu.Lock()
	delete(s.clients, handshake.NodeID)
	s.clientsMu.Unlock()
}

// handleClient processes messages from a connected client
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

// Dashboard WebSocket upgrader
var dashboardUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024 * 64,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// handleDashboardWebSocket handles WebSocket connections from dashboard
func (s *Server) handleDashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := dashboardUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("server: dashboard upgrade error: %v", err)
		return
	}

	// Register client
	s.dashboardClientsMu.Lock()
	s.dashboardClients[conn] = true
	s.dashboardClientsMu.Unlock()

	log.Printf("server: dashboard client connected, total: %d", len(s.dashboardClients))

	// Send initial data
	s.sendFullDashboardData(conn)

	// Handle incoming messages (for ping/pong)
	defer func() {
		s.dashboardClientsMu.Lock()
		delete(s.dashboardClients, conn)
		s.dashboardClientsMu.Unlock()
		conn.Close()
		log.Printf("server: dashboard client disconnected, total: %d", len(s.dashboardClients))
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
func (s *Server) sendFullDashboardData(conn *websocket.Conn) {
	ctx := context.Background()

	// Stats
	if stats, err := s.storage.GetGlobalStats(ctx); err == nil {
		connectedNodes := s.GetConnectedClients()
		stats.NodesConnected = len(connectedNodes)
		conn.WriteJSON(&DashboardUpdate{Type: "stats", Data: stats})
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
		conn.WriteJSON(&DashboardUpdate{Type: "nodes", Data: nodes})
	}

	// Users (top 500 for dashboard)
	if users, err := s.storage.GetAllUsers(ctx, 500); err == nil {
		conn.WriteJSON(&DashboardUpdate{Type: "users", Data: users})
	}

	// Hourly stats (24h)
	if hourly, err := s.storage.GetHourlyStats(ctx, 24); err == nil {
		conn.WriteJSON(&DashboardUpdate{Type: "hourly", Data: hourly})
	}

	// Anomalies
	if anomalies := s.getAnomalies(ctx); anomalies != nil {
		conn.WriteJSON(&DashboardUpdate{Type: "anomalies", Data: anomalies})
	}

	// Blacklist analytics
	since := time.Now().Add(-24 * time.Hour)
	if analytics, err := s.storage.GetBlacklistAnalytics(ctx, since); err == nil {
		conn.WriteJSON(&DashboardUpdate{Type: "blacklist", Data: analytics})
	}

	// Threat intelligence
	s.sendThreatIntelUpdate(conn)
}

// BroadcastDashboardUpdate triggers a broadcast to all dashboard clients
func (s *Server) BroadcastDashboardUpdate() {
	select {
	case s.broadcastChan <- &DashboardUpdate{Type: "refresh"}:
	default:
		// Channel full, skip
	}
}

// startBroadcastLoop handles broadcasting updates to dashboard clients
func (s *Server) startBroadcastLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.broadcastChan:
			s.broadcastToDashboards()
		}
	}
}

// startPeriodicBroadcast sends updates every second
func (s *Server) startPeriodicBroadcast(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.broadcastToDashboards()
		}
	}
}

// broadcastToDashboards sends current data to all connected dashboard clients
func (s *Server) broadcastToDashboards() {
	s.dashboardClientsMu.RLock()
	clients := make([]*websocket.Conn, 0, len(s.dashboardClients))
	for conn := range s.dashboardClients {
		clients = append(clients, conn)
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
		updates = append(updates, DashboardUpdate{Type: "users", Data: users})
	}

	// Blacklist analytics (with recent matches)
	since := time.Now().Add(-24 * time.Hour)
	if analytics, err := s.storage.GetBlacklistAnalytics(ctx, since); err == nil {
		updates = append(updates, DashboardUpdate{Type: "blacklist", Data: analytics})
	}

	// Threat intelligence
	if s.threatIntel != nil {
		tiStats := s.threatIntel.GetStats()
		tiMatches, _ := s.storage.GetThreatMatches(ctx, time.Now().Add(-24*time.Hour), 10)
		threatData := map[string]interface{}{
			"stats":   tiStats,
			"matches": tiMatches,
		}
		updates = append(updates, DashboardUpdate{Type: "threatintel", Data: threatData})
	}

	// Send to all clients
	for _, conn := range clients {
		for _, update := range updates {
			if err := conn.WriteJSON(&update); err != nil {
				// Client will be removed on next read error
				continue
			}
		}
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
func (s *Server) sendThreatIntelUpdate(conn *websocket.Conn) {
	if s.threatIntel == nil {
		return
	}

	ctx := context.Background()
	tiStats := s.threatIntel.GetStats()
	tiMatches, _ := s.storage.GetThreatMatches(ctx, time.Now().Add(-24*time.Hour), 10)

	threatData := map[string]interface{}{
		"stats":   tiStats,
		"matches": tiMatches,
	}

	conn.WriteJSON(&DashboardUpdate{Type: "threatintel", Data: threatData})
}
