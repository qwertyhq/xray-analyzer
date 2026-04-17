package websocket

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xray-log-analyzer/agent/internal/models"
)

// Defaults for liveness detection. Override per-instance for tests.
//
// Tuning rationale: NetBird/Caddy silently drop long-idle WS connections in
// prod; the previous 90s pongWait kept a "dead" node off the dashboard for
// up to ~95s per flap. 30s/10s detects a stall in under 30s, then reconnect
// takes ~5s — most flaps are invisible to the UI. Extra ping traffic is
// negligible (a control frame every 10s ≈ 6 bytes).
const (
	defaultPongWait     = 30 * time.Second
	defaultPingPeriod   = 10 * time.Second // < pongWait so a missed pong trips the deadline
	defaultWriteWait    = 5 * time.Second
	defaultTCPKeepAlive = 15 * time.Second
)

// Client manages WebSocket connection to the main server
type Client struct {
	serverURL      string
	nodeID         string
	authToken      string
	batchCh        chan *models.LogBatch
	conn           *websocket.Conn
	mu             sync.Mutex
	reconnectDelay time.Duration
	maxRetries     int

	// Liveness knobs (exported lowercase for in-package tests).
	pongWait     time.Duration
	pingPeriod   time.Duration
	writeWait    time.Duration
	tcpKeepAlive time.Duration
}

// New creates a new WebSocket client
func New(serverURL, nodeID, authToken string, batchCh chan *models.LogBatch) *Client {
	return &Client{
		serverURL:      serverURL,
		nodeID:         nodeID,
		authToken:      authToken,
		batchCh:        batchCh,
		reconnectDelay: 5 * time.Second,
		maxRetries:     0, // 0 = infinite retries
		pongWait:       defaultPongWait,
		pingPeriod:     defaultPingPeriod,
		writeWait:      defaultWriteWait,
		tcpKeepAlive:   defaultTCPKeepAlive,
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
			// run() always returns with the connection torn down — either
			// because the peer is dead, the writer failed, or ctx was
			// cancelled. Make sure the next connect() starts from a clean slate.
			c.close()
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

	headers := http.Header{}
	if c.authToken != "" {
		headers.Set("Authorization", "Bearer "+c.authToken)
	}

	conn, _, err := dialer.DialContext(ctx, c.serverURL, headers)
	if err != nil {
		return err
	}

	// Kernel-level keepalive: detects fully-dead TCP without app traffic.
	if tcpConn, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(c.tcpKeepAlive)
	}

	// Set initial read deadline; it gets extended on every received frame.
	_ = conn.SetReadDeadline(time.Now().Add(c.pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(c.pongWait))
	})

	c.conn = conn
	log.Printf("websocket: connected to %s", c.serverURL)

	// Send handshake with node ID.
	_ = conn.SetWriteDeadline(time.Now().Add(c.writeWait))
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
	// Reader goroutine: any read failure means the link is dead.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		c.readPump(ctx)
	}()

	// Periodic client-side ping. We use the WebSocket control frame so a
	// healthy peer responds at the protocol layer (handled by gorilla via
	// PongHandler), regardless of any application-level ping the server
	// may also send.
	pingTicker := time.NewTicker(c.pingPeriod)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-readerDone:
			log.Println("websocket: reader disconnected, reconnecting...")
			return
		case <-pingTicker.C:
			if err := c.writeControl(websocket.PingMessage, nil); err != nil {
				log.Printf("websocket: ping error: %v", err)
				return
			}
		case batch := <-c.batchCh:
			if err := c.sendBatch(batch); err != nil {
				log.Printf("websocket: send error: %v", err)
				return
			}
		}
	}
}

// writeControl sends a control frame (e.g. Ping) with a write deadline.
func (c *Client) writeControl(messageType int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return ErrNotConnected
	}
	deadline := time.Now().Add(c.writeWait)
	return c.conn.WriteControl(messageType, data, deadline)
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

	// Bound the write so a stalled peer trips immediately instead of blocking.
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeWait)); err != nil {
		return err
	}
	if err := c.conn.WriteMessage(websocket.BinaryMessage, buf.Bytes()); err != nil {
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
				} else {
					log.Printf("websocket: read terminated: %v", err)
				}
				return
			}

			// Any message from the server is proof of life — extend the deadline.
			_ = conn.SetReadDeadline(time.Now().Add(c.pongWait))

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

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeWait))
	pong := map[string]string{"type": "pong"}
	_ = c.conn.WriteJSON(pong)
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
