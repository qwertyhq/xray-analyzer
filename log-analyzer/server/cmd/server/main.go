package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xray-log-analyzer/server/internal/aleria"
	"github.com/xray-log-analyzer/server/internal/analyzer"
	"github.com/xray-log-analyzer/server/internal/blacklist"
	"github.com/xray-log-analyzer/server/internal/config"
	"github.com/xray-log-analyzer/server/internal/correlation"
	"github.com/xray-log-analyzer/server/internal/ipinfo"
	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/rediscache"
	"github.com/xray-log-analyzer/server/internal/remnawave"
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

	// Initialize Redis (L2 persistent cache). Optional — if it fails or the
	// address is empty, everything still works with only the in-process L1.
	var redisClient *rediscache.Client
	if cfg.RedisAddr != "" {
		rc, err := rediscache.New(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisKeyPrefix)
		if err != nil {
			log.Printf("redis: disabled (connect %s failed: %v)", cfg.RedisAddr, err)
		} else {
			redisClient = rc
			log.Printf("redis: connected at %s (prefix=%q)", cfg.RedisAddr, cfg.RedisKeyPrefix)
			defer redisClient.Close()
		}
	} else {
		log.Println("redis: not configured (REDIS_ADDR empty)")
	}

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
	if err := anal.SetBridgeInboundPattern(cfg.BridgeInboundPattern); err != nil {
		log.Fatalf("invalid BRIDGE_INBOUND_PATTERN %q: %v", cfg.BridgeInboundPattern, err)
	}
	if cfg.BridgeInboundPattern != "" {
		log.Printf("analyzer: bridge inbound filter active: %q", cfg.BridgeInboundPattern)
	}
	if len(cfg.BridgeNodeIDs) > 0 {
		anal.SetBridgeCorrelation(cfg.BridgeNodeIDs, cfg.BridgeCorrelationWindow)
		log.Printf("analyzer: bridge correlation active: nodes=%v window=%s", cfg.BridgeNodeIDs, cfg.BridgeCorrelationWindow)
	}

	// Initialize IP info service for geo lookups
	ipInfoSvc := ipinfo.NewService()
	anal.SetIPInfo(ipInfoSvc)

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
		// Silently drain alert channel if telegram is disabled
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-alertCh:
					// Discard alerts silently
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
	srv := server.New(cfg.ListenAddr, cfg.AllowedOrigins, cfg.APIToken, cfg.AgentToken, anal, store, bl)
	srv.SetThreatIntel(threatIntelSvc)

	if cfg.APIToken != "" {
		log.Println("auth: API token authentication enabled")
	} else {
		log.Println("auth: WARNING - no API_TOKEN set, API is unprotected!")
	}
	if cfg.AgentToken != "" {
		log.Println("auth: agent token authentication enabled")
	} else {
		log.Println("auth: WARNING - no AGENT_TOKEN set, agent WebSocket is unprotected!")
	}

	// Initialize Remnawave client and sync service
	var remnaSvc *remnawave.SyncService
	var remnaClient *remnawave.Client
	if cfg.RemnawaveEnabled && cfg.RemnawaveURL != "" && cfg.RemnawaveAPIToken != "" {
		remnaClient = remnawave.NewClient(cfg.RemnawaveURL, cfg.RemnawaveAPIToken)
		remnaSvc = remnawave.NewSyncService(remnaClient, cfg.RemnawaveSyncInterval)
		remnaSvc.SetIDCacheRedis(redisClient)
		remnaSvc.SetStorage(store) // Persist data to SQLite
		// Warm cache after each sync for fast page loads
		remnaSvc.OnSyncComplete(func() {
			store.WarmCache(ctx)
		})
		srv.SetRemnawave(remnaSvc)
		go remnaSvc.Start(ctx)
		log.Printf("remnawave: enabled, sync interval: %v, storage: enabled", cfg.RemnawaveSyncInterval)
	} else {
		log.Println("remnawave: disabled (no URL/token configured)")
	}

	// Initial cache warm-up
	go store.WarmCache(ctx)

	// Initialize correlation service for user analysis
	correlationSvc := correlation.NewService(store, remnaSvc)
	anal.SetCorrelation(correlationSvc)
	srv.SetCorrelation(correlationSvc)
	log.Println("correlation: service initialized")

	// Initialize Aleria AI service
	if cfg.AleriaAPIKey != "" {
		aleriaSvc := aleria.NewService(cfg.AleriaAPIKey, store)
		// Give AI access to Remnawave API for real-time data
		if remnaClient != nil {
			aleriaSvc.SetRemnaClient(remnaClient)
		}
		srv.SetAleria(aleriaSvc)
		log.Println("aleria: AI service initialized")
	} else {
		log.Println("aleria: disabled (no API key configured)")
	}

	// Start periodic profile refresh (every 6 hours)
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				correlationSvc.RefreshAllProfiles(ctx)
			}
		}
	}()

	// Anomaly detection — runs every 10 minutes.
	// Detects activity spikes, night activity, threat bursts, multi-country access, etc.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		// Run once shortly after startup so dashboard isn't empty
		time.AfterFunc(60*time.Second, func() {
			if found, err := store.DetectAnomalies(ctx); err == nil && len(found) > 0 {
				log.Printf("anomaly: detected %d anomalies", len(found))
			}
		})
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if found, err := store.DetectAnomalies(ctx); err != nil {
					log.Printf("anomaly: detection error: %v", err)
				} else if len(found) > 0 {
					log.Printf("anomaly: detected %d anomalies", len(found))
				}
			}
		}
	}()

	// User risk profile recalculation — runs every 30 minutes.
	// Aggregates threat matches, anomalies, geo, and activity into a per-user risk score.
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		// Initial run after 2 minutes (let threat matches accumulate)
		time.AfterFunc(2*time.Minute, func() {
			if err := store.RecalculateAllUserRiskProfiles(ctx); err != nil {
				log.Printf("risk: recalculation error: %v", err)
			}
		})
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := store.RecalculateAllUserRiskProfiles(ctx); err != nil {
					log.Printf("risk: recalculation error: %v", err)
				}
			}
		}
	}()

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
