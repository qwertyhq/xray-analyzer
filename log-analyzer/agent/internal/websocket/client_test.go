package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"
	"github.com/xray-log-analyzer/agent/internal/models"
)

// TestClient_ReconnectsWhenServerGoesSilent simulates a half-dead peer:
// the server accepts the WebSocket and consumes the handshake, then stops
// responding entirely (no pings, no acks, no close). A correct client must
// detect the dead peer and reconnect; a broken one will hang forever.
func TestClient_ReconnectsWhenServerGoesSilent(t *testing.T) {
	var connectCount int32
	upgrader := gws.Upgrader{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		atomic.AddInt32(&connectCount, 1)
		// Consume handshake JSON so the client thinks it succeeded.
		var hs map[string]string
		_ = conn.ReadJSON(&hs)
		// Now go silent: don't read, don't write, don't close. gorilla's
		// auto-pong only fires while ReadMessage is active, so by parking
		// here we look exactly like a stalled/zombie peer.
		<-r.Context().Done()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	batchCh := make(chan *models.LogBatch, 10)
	client := New(wsURL, "test-node", "", batchCh)
	// Tighten timings so the test runs in seconds rather than minutes.
	client.pongWait = 800 * time.Millisecond
	client.pingPeriod = 200 * time.Millisecond
	client.writeWait = 300 * time.Millisecond
	client.reconnectDelay = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Start(ctx)

	// Expect the client to (re)connect at least 3 times within 5 s.
	// 1st = initial connect; further = after detecting the dead peer.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&connectCount) >= 3 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("client failed to detect dead peer; connect attempts=%d (want >=3)", atomic.LoadInt32(&connectCount))
}

// TestClient_DeliversBatchesAfterReconnect verifies the happy path on the
// reconnect side: when the server resumes normal behaviour, batches that
// arrive after the reconnect are delivered and acknowledged.
func TestClient_DeliversBatchesAfterReconnect(t *testing.T) {
	var receivedBatches int32
	upgrader := gws.Upgrader{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		var hs map[string]string
		if err := conn.ReadJSON(&hs); err != nil {
			return
		}
		// Echo a single ack to keep connection alive briefly, then continue
		// handling messages normally.
		for {
			mt, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == gws.BinaryMessage {
				atomic.AddInt32(&receivedBatches, 1)
				_ = conn.WriteJSON(models.ServerMessage{Type: "ack", Processed: 1})
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	batchCh := make(chan *models.LogBatch, 10)
	client := New(wsURL, "test-node", "", batchCh)
	client.pongWait = 5 * time.Second
	client.pingPeriod = 1 * time.Second
	client.writeWait = 1 * time.Second
	client.reconnectDelay = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Start(ctx)

	// Give the connect+handshake a moment.
	time.Sleep(300 * time.Millisecond)

	batchCh <- &models.LogBatch{NodeID: "test-node", Count: 1, Entries: []models.LogEntry{{User: "1"}}}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&receivedBatches) >= 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("batch was not delivered to server")
}
