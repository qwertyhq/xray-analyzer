package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/xray-log-analyzer/agent/internal/batcher"
	"github.com/xray-log-analyzer/agent/internal/config"
	"github.com/xray-log-analyzer/agent/internal/models"
	"github.com/xray-log-analyzer/agent/internal/tailer"
	"github.com/xray-log-analyzer/agent/internal/websocket"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("xray-log-agent starting...")

	// Load configuration
	cfg := config.LoadFromEnv()
	log.Printf("config: node_id=%s, log_file=%s, server=%s",
		cfg.NodeID, cfg.LogFilePath, cfg.ServerURL)
	log.Printf("config: batch_size=%d, batch_timeout=%v",
		cfg.BatchSize, cfg.BatchTimeout)

	// Create channels
	entryCh := make(chan *models.LogEntry, 10000) // Parsed entries
	batchCh := make(chan *models.LogBatch, 100)   // Batches for sending

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create components
	logTailer := tailer.New(cfg.LogFilePath, entryCh)
	logBatcher := batcher.New(cfg.NodeID, cfg.BatchSize, cfg.BatchTimeout, entryCh, batchCh)
	wsClient := websocket.New(cfg.ServerURL, cfg.NodeID, cfg.AuthToken, batchCh)

	// WaitGroup for proper shutdown
	var wg sync.WaitGroup

	// Start tailer
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := logTailer.Start(ctx); err != nil {
			log.Printf("tailer error: %v", err)
			cancel()
		}
	}()

	// Start batcher
	wg.Add(1)
	go func() {
		defer wg.Done()
		logBatcher.Start(ctx)
	}()

	// Start WebSocket client
	wg.Add(1)
	go func() {
		defer wg.Done()
		wsClient.Start(ctx)
	}()

	log.Println("agent started, press Ctrl+C to stop")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	cancel()

	// Wait for goroutines with timeout
	log.Println("waiting for cleanup...")
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("agent stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Println("agent stopped (timeout waiting for goroutines)")
	}
}
