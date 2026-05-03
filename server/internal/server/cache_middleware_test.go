package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/xray-log-analyzer/server/internal/rediscache"
)

func newCacheTestServer(t *testing.T) (*Server, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc, err := rediscache.New(mr.Addr(), "", "")
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { rc.Close() })
	s := &Server{}
	s.SetRedis(rc, time.Minute)
	return s, mr
}

// TestCached_HitMiss: the second GET with the same URL+token must come
// from Redis without invoking the wrapped handler.
func TestCached_HitMiss(t *testing.T) {
	s, _ := newCacheTestServer(t)

	var calls int32
	wrapped := s.cached(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"hits":%d}`, atomic.LoadInt32(&calls))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer T")

	w1 := httptest.NewRecorder()
	wrapped(w1, req)
	if got := w1.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first call X-Cache=%q, want MISS", got)
	}
	if w1.Body.String() != `{"hits":1}` {
		t.Errorf("first body=%q", w1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req2.Header.Set("Authorization", "Bearer T")
	w2 := httptest.NewRecorder()
	wrapped(w2, req2)
	if got := w2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second call X-Cache=%q, want HIT", got)
	}
	if w2.Body.String() != `{"hits":1}` {
		t.Errorf("HIT body=%q, want exact replay of MISS body", w2.Body.String())
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("handler invoked %d times, want 1 (cache should have served)", got)
	}
}

// TestCached_DifferentTokensSeparate: two callers with different bearer
// tokens must NOT share a cache slot — otherwise user A could read user B's
// filtered view.
func TestCached_DifferentTokensSeparate(t *testing.T) {
	s, _ := newCacheTestServer(t)

	var calls int32
	wrapped := s.cached(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"who":%q}`, r.Header.Get("Authorization"))
	})

	req1 := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req1.Header.Set("Authorization", "Bearer A")
	req2 := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req2.Header.Set("Authorization", "Bearer B")

	w1 := httptest.NewRecorder()
	wrapped(w1, req1)
	w2 := httptest.NewRecorder()
	wrapped(w2, req2)

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected handler called twice (one per token), got %d", got)
	}
	if w1.Body.String() == w2.Body.String() {
		t.Errorf("token-scoped responses leaked: A=%q B=%q", w1.Body.String(), w2.Body.String())
	}
}

// TestCached_NonGETBypass: POST/DELETE must skip the cache so writes
// always run.
func TestCached_NonGETBypass(t *testing.T) {
	s, _ := newCacheTestServer(t)
	var calls int32
	wrapped := s.cached(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	})
	wrapped(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/x", nil))
	wrapped(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/x", nil))
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("POSTs collapsed into cache: handler ran %d times, want 2", got)
	}
}

// TestCached_NonOKNotCached: a 500 should not be persisted — otherwise a
// transient downstream error sticks around for TTL.
func TestCached_NonOKNotCached(t *testing.T) {
	s, _ := newCacheTestServer(t)
	var calls int32
	wrapped := s.cached(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	for i := 0; i < 3; i++ {
		wrapped(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/y", nil))
		time.Sleep(50 * time.Millisecond) // let any async write attempt resolve
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("5xx was cached (handler ran %d times, want 3)", got)
	}
}

// TestCached_InvalidateAfterMutation: after InvalidateHTTPCache, the next
// GET must miss again — proves the resolve/delete handlers can flush stale
// data on demand.
func TestCached_InvalidateAfterMutation(t *testing.T) {
	s, _ := newCacheTestServer(t)
	var calls int32
	wrapped := s.cached(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	})
	req := httptest.NewRequest(http.MethodGet, "/api/z", nil)
	wrapped(httptest.NewRecorder(), req)
	// wait for async write
	time.Sleep(150 * time.Millisecond)
	wrapped(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/z", nil))
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected hit after first call; calls=%d", got)
	}
	s.InvalidateHTTPCache(context.Background())
	wrapped(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/z", nil))
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("invalidation didn't force handler re-run; calls=%d", got)
	}
}
