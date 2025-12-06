package websocket

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xray-log-analyzer/agent/internal/models"
)

// Client manages WebSocket connection to the main server
type Client struct {
	serverURL      string
	nodeID         string
	batchCh        chan *models.LogBatch
	conn           *websocket.Conn
	mu             sync.Mutex
	reconnectDelay time.Duration
	maxRetries     int
}

// New creates a new WebSocket client
func New(serverURL, nodeID string, batchCh chan *models.LogBatch) *Client {
	return &Client{
		serverURL:      serverURL,
		nodeID:         nodeID,
		batchCh:        batchCh,
		reconnectDelay: 5 * time.Second,
		maxRetries:     0, // 0 = infinite retries
	}
}

// Start begins the WebSocket client loop
func (c *Client) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.close()
			log.Println("websocket: shutting down")
			return
		default:
			if err := c.connect(ctx); err != nil {
				log.Printf("websocket: connection error: %v", err)
				c.waitReconnect(ctx)
				continue
			}
			c.run(ctx)
		}
	}
}

// connect establishes a WebSocket connection
func (c *Client) connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, c.serverURL, nil)
	if err != nil {
		return err
	}

	c.conn = conn
	log.Printf("websocket: connected to %s", c.serverURL)

	// Send handshake with node ID
	handshake := map[string]string{
		"type":    "handshake",
		"node_id": c.nodeID,
	}
	if err := conn.WriteJSON(handshake); err != nil {
		conn.Close()
		c.conn = nil
		return err
	}

	return nil
}

// run handles sending batches and receiving server messages
func (c *Client) run(ctx context.Context) {
	// Start reader goroutine for server messages
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		c.readPump(ctx)
	}()

	// Main loop: send batches
	for {
		select {
		case <-ctx.Done():
			return
		case <-readerDone:
			log.Println("websocket: reader disconnected, reconnecting...")
			return
		case batch := <-c.batchCh:
			if err := c.sendBatch(batch); err != nil {
				log.Printf("websocket: send error: %v", err)
				return
			}
		}
	}
}

// sendBatch compresses and sends a batch to the server
func (c *Client) sendBatch(batch *models.LogBatch) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNotConnected
	}

	// Serialize to JSON
	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	// Compress with gzip
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	// Send as binary message
	err = c.conn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
	if err != nil {
		return err
	}

	log.Printf("websocket: sent batch with %d entries (compressed: %d -> %d bytes)",
		batch.Count, len(data), buf.Len())

	return nil
}

// readPump handles incoming messages from the server
func (c *Client) readPump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c.mu.Lock()
			conn := c.conn
			c.mu.Unlock()

			if conn == nil {
				return
			}

			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("websocket: read error: %v", err)
				}
				return
			}

			var serverMsg models.ServerMessage
			if err := json.Unmarshal(message, &serverMsg); err != nil {
				log.Printf("websocket: failed to parse server message: %v", err)
				continue
			}

			c.handleServerMessage(&serverMsg)
		}
	}
}

// handleServerMessage processes messages from the server
func (c *Client) handleServerMessage(msg *models.ServerMessage) {
	switch msg.Type {
	case "ack":
		log.Printf("websocket: server acknowledged batch, processed %d entries", msg.Processed)
	case "ping":
		c.sendPong()
	case "error":
		log.Printf("websocket: server error: %s", msg.Error)
	default:
		log.Printf("websocket: unknown message type: %s", msg.Type)
	}
}

// sendPong sends a pong response
func (c *Client) sendPong() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return
	}

	pong := map[string]string{"type": "pong"}
	c.conn.WriteJSON(pong)
}

// waitReconnect waits before reconnecting
func (c *Client) waitReconnect(ctx context.Context) {
	log.Printf("websocket: reconnecting in %v...", c.reconnectDelay)
	select {
	case <-ctx.Done():
	case <-time.After(c.reconnectDelay):
	}
}

// close closes the WebSocket connection
func (c *Client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// ErrNotConnected is returned when trying to send without connection
var ErrNotConnected = &NotConnectedError{}

// NotConnectedError indicates no active connection
type NotConnectedError struct{}

func (e *NotConnectedError) Error() string {
	return "websocket: not connected"
}
