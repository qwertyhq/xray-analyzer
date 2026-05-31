package server

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"time"
)

// warmupPaths lists API paths the dashboard hits on first paint. Running
// them once at startup — and then periodically — primes the Redis HTTP
// cache so users never see a cold-cache spike.
//
// Order is roughly "lightest first" so if the process is killed mid-warmup
// the cheap endpoints are ready.
var warmupPaths = []string{
	"/api/stats",
	"/api/nodes",
	"/api/online-history?since=24h",
	"/api/remnawave/stats",
	"/api/hourly",
	"/api/users",
	"/api/alerts?limit=20",
	"/api/anomalies",
	"/api/threatintel/feeds",
	"/api/threatintel/stats",
	"/api/threatintel/time-stats",
	"/api/threatintel/anomalies?summary=true",
	"/api/threatintel/risk-profiles",
	"/api/threatintel/geo-stats?type=connections&limit=50",
	"/api/threatintel/geo-stats?type=cities&limit=200",
	"/api/threatintel/attacks?since=24h&limit=200",
	"/api/threatintel/reports",
	"/api/remnawave/users",
	"/api/correlation/stats",
	// Correlation tab content — query strings must match the dashboard's
	// defaults (see correlation/page.tsx) so the warmed cache key is the one
	// the UI actually reads.
	"/api/correlation/profiles?limit=100&min_risk=0",
	"/api/correlation/shared-ips?limit=50",
	"/api/correlation/shared-hwids?limit=50",
	"/api/blacklist/abuse",
	"/api/remnawave/abuse",
}

// startCacheWarmupJob preloads the HTTP cache for the hot dashboard paths.
// Runs once at boot (giving SQL time to quiet down) and then every warmupTTL/2
// so entries never expire while the dashboard is idle.
func (s *Server) startCacheWarmupJob(ctx context.Context) {
	if s.redis == nil {
		return
	}

	warmupInterval := s.cacheTTL
	if warmupInterval <= 0 {
		warmupInterval = 10 * time.Second
	}
	// Refresh well before TTL so hits stay warm.
	warmupInterval = warmupInterval / 2
	if warmupInterval < 5*time.Second {
		warmupInterval = 5 * time.Second
	}

	// Wait 3s after start — long enough for feeds loader, Remnawave sync,
	// and the first WS broadcast to fire so warm-up snapshots include real
	// numbers rather than empty initial state.
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}

	run := func() {
		start := time.Now()
		ok := 0
		for _, p := range warmupPaths {
			if s.hitWarmupPath(ctx, p) {
				ok++
			}
			if ctx.Err() != nil {
				return
			}
		}
		log.Printf("cache-warmup: primed %d/%d paths in %s", ok, len(warmupPaths), time.Since(start))
	}

	run()

	t := time.NewTicker(warmupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// hitWarmupPath drives one request through the normal handler stack so the
// cache middleware sees a real GET (includes the same Authorization-derived
// key the UI would produce, thanks to requireAPIToken bypass on localhost).
// Returns true on 2xx.
func (s *Server) hitWarmupPath(ctx context.Context, path string) bool {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = req.WithContext(ctx)
	// Loopback: requireAPIToken has a localhost bypass so we don't need a
	// real token here. Keeping RemoteAddr inside the bypass set is crucial.
	req.RemoteAddr = "127.0.0.1:0"
	rw := &warmupRecorder{header: make(http.Header), body: &bytes.Buffer{}, status: http.StatusOK}
	mux := s.warmupMux()
	mux.ServeHTTP(rw, req)
	return rw.status >= 200 && rw.status < 300
}

// warmupMux is a tiny mux that dispatches just the endpoints we warm up.
// Lives separately from the main Start() mux so warm-up doesn't depend on
// the server being already listening.
func (s *Server) warmupMux() *http.ServeMux {
	m := http.NewServeMux()
	wrap := func(pattern string, h http.HandlerFunc) {
		m.HandleFunc(pattern, s.cached(0, s.requireAPIToken(h)))
	}
	wrap("/api/stats", s.handleStats)
	wrap("/api/nodes", s.handleNodes)
	wrap("/api/online-history", s.handleOnlineHistory)
	wrap("/api/remnawave/stats", s.handleRemnawaveStats)
	wrap("/api/hourly", s.handleHourlyStats)
	wrap("/api/users", s.handleUsers)
	wrap("/api/alerts", s.handleAlerts)
	wrap("/api/anomalies", s.handleAnomalies)
	wrap("/api/threatintel/feeds", s.handleThreatIntelFeeds)
	wrap("/api/threatintel/stats", s.handleThreatIntelStats)
	wrap("/api/threatintel/time-stats", s.handleThreatIntelTimeStats)
	wrap("/api/threatintel/anomalies", s.handleThreatIntelAnomalies)
	wrap("/api/threatintel/risk-profiles", s.handleUserRiskProfiles)
	wrap("/api/threatintel/geo-stats", s.handleThreatIntelGeoStats)
	wrap("/api/threatintel/attacks", s.handleAttackAnomalies)
	wrap("/api/threatintel/reports", s.handleReports)
	wrap("/api/remnawave/users", s.handleRemnawaveUsers)
	wrap("/api/correlation/stats", s.handleCorrelationStats)
	wrap("/api/correlation/profiles", s.handleCorrelationProfiles)
	wrap("/api/correlation/shared-ips", s.handleCorrelationSharedIPs)
	wrap("/api/correlation/shared-hwids", s.handleCorrelationSharedHWIDs)
	wrap("/api/blacklist/abuse", s.handleSubscriptionAbuse)
	wrap("/api/remnawave/abuse", s.handleRemnawaveAbuse)
	return m
}

// warmupRecorder is a minimal ResponseWriter — we don't stream the body,
// we just need the middleware to run and populate Redis.
type warmupRecorder struct {
	header http.Header
	body   *bytes.Buffer
	status int
}

func (w *warmupRecorder) Header() http.Header          { return w.header }
func (w *warmupRecorder) WriteHeader(status int)       { w.status = status }
func (w *warmupRecorder) Write(b []byte) (int, error)  { return w.body.Write(b) }
