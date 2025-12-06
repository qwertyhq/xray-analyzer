package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/xray-log-analyzer/agent/internal/batcher"
	"github.com/xray-log-analyzer/agent/internal/config"
	"github.com/xray-log-analyzer/agent/internal/models"
	"github.com/xray-log-analyzer/agent/internal/parser"
	"github.com/xray-log-analyzer/agent/internal/tailer"
	"github.com/xray-log-analyzer/agent/internal/websocket"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("xray-log-agent starting...")

	// Load configuration
	cfg := config.Load()
	log.Printf("config: node_id=%s, log_file=%s, server=%s",
		cfg.NodeID, cfg.LogFilePath, cfg.ServerURL)
	log.Printf("config: batch_size=%d, batch_timeout=%v",
		cfg.BatchSize, cfg.BatchTimeout)

	// Create channels
	lineCh := make(chan string, 10000)                // Raw log lines
	entryCh := make(chan *models.LogEntry, 10000)     // Parsed entries
	batchCh := make(chan *models.LogBatch, 100)       // Batches for sending

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create components
	logParser := parser.New()
	logTailer := tailer.New(cfg.LogFilePath, lineCh)
	logBatcher := batcher.New(cfg.NodeID, cfg.BatchSize, cfg.BatchTimeout, entryCh, batchCh)
	wsClient := websocket.New(cfg.ServerURL, cfg.NodeID, batchCh)

	// Start tailer
	go func() {
		if err := logTailer.Start(ctx); err != nil {
			log.Printf("tailer error: %v", err)
			cancel()
		}
	}()

	// Start parser goroutine (converts lines to entries)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case line := <-lineCh:
				entry, err := logParser.ParseLine(line)
				if err != nil {
					// Skip unparseable lines (warnings, errors, etc.)
					continue
				}
				select {
				case entryCh <- entry:
				default:
					log.Println("warning: entry channel full, dropping entry")
				}
			}
		}
	}()

	// Start batcher
	go logBatcher.Start(ctx)

	// Start WebSocket client
	go wsClient.Start(ctx)

	log.Println("agent started, press Ctrl+C to stop")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	cancel()

	// Give goroutines time to flush
	log.Println("waiting for cleanup...")
	// In production, use WaitGroup for proper cleanup
	log.Println("agent stopped")
}
