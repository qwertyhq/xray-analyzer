package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xray-log-analyzer/server/internal/analyzer"
	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/config"
	"github.com/xray-log-analyzer/server/internal/ipinfo"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/server"
	"github.com/xray-log-analyzer/server/internal/storage"
	"github.com/xray-log-analyzer/server/internal/telegram"
	"github.com/xray-log-analyzer/server/internal/threatintel"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("xray-log-analyzer server starting...")

	// Load configuration
	cfg := config.Load()
	log.Printf("config: listen=%s, db=%s, blacklist=%s",
		cfg.ListenAddr, cfg.DBPath, cfg.BlacklistPath)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize storage
	store, err := storage.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}
	defer store.Close()
	log.Println("storage: initialized")

	// Initialize blacklist
	bl := blacklist.New(cfg.BlacklistPath, cfg.BlacklistReload)
	if cfg.BlacklistRemoteURL != "" {
		bl.SetRemoteURL(cfg.BlacklistRemoteURL)
		log.Printf("blacklist: remote URL configured: %s", cfg.BlacklistRemoteURL)
	}
	if err := bl.Start(ctx); err != nil {
		log.Fatalf("failed to load blacklist: %v", err)
	}
	log.Printf("blacklist: loaded %d rules", bl.Count())

	// Create alert channel
	alertCh := make(chan *models.Alert, 100)

	// Initialize analyzer
	anal := analyzer.New(
		bl,
		store,
		alertCh,
		cfg.SuspiciousRequestCount,
		cfg.SuspiciousTimeWindow,
	)

	// Initialize IP info service for geo lookups
	ipInfoSvc := ipinfo.NewService()

	// Initialize threat intelligence service
	threatIntelSvc := threatintel.NewService(store, ipInfoSvc)
	if err := threatIntelSvc.Start(ctx); err != nil {
		log.Printf("threatintel: failed to start (continuing without): %v", err)
	} else {
		anal.SetThreatIntel(threatIntelSvc)
		log.Printf("threatintel: started with %d indicators", threatIntelSvc.GetIndicatorCount())
	}

	// Initialize Telegram bot if enabled
	if cfg.TelegramEnabled && cfg.TelegramToken != "" && cfg.TelegramChatID != "" {
		bot := telegram.New(cfg.TelegramToken, cfg.TelegramChatID, alertCh)
		go bot.Start(ctx)

		// Send test message
		if err := bot.SendTestMessage(); err != nil {
			log.Printf("telegram: failed to send test message: %v", err)
		}
	} else {
		log.Println("telegram: disabled (no token/chat_id)")
		// Drain alert channel if telegram is disabled
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case alert := <-alertCh:
					log.Printf("alert (not sent): %s", alert.Message)
				}
			}
		}()
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Cleanup old data (keep 30 days)
				if err := store.CleanupOldData(ctx, 30); err != nil {
					log.Printf("cleanup error: %v", err)
				}
				// Cleanup old threat matches (keep 30 days)
				if deleted, err := store.CleanupOldThreatMatches(ctx, 30*24*time.Hour); err != nil {
					log.Printf("cleanup threat matches error: %v", err)
				} else if deleted > 0 {
					log.Printf("cleanup: deleted %d old threat matches", deleted)
				}
				// Cleanup analyzer alert cache
				anal.CleanupAlertCache()
			}
		}
	}()

	// Initialize and start server
	srv := server.New(cfg.ListenAddr, anal, store, bl)
	srv.SetThreatIntel(threatIntelSvc)
	go func() {
		if err := srv.Start(ctx); err != nil {
			log.Printf("server error: %v", err)
			cancel()
		}
	}()

	log.Println("server started, press Ctrl+C to stop")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	cancel()

	// Stop threat intelligence service
	threatIntelSvc.Stop()

	// Give goroutines time to cleanup
	time.Sleep(2 * time.Second)
	log.Println("server stopped")
}
