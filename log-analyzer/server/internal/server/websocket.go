package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
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
