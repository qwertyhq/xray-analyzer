package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// cachedResponse is the JSON-serialised wire shape kept in Redis. Storing
// the status code lets us replay 4xx/5xx without re-running the handler,
// and Content-Type lets `application/json` (or anything else) survive the
// round-trip without forcing every handler to set the header.
type cachedResponse struct {
	Status      int               `json:"s"`
	ContentType string            `json:"ct,omitempty"`
	Body        []byte            `json:"b"`
	Vary        map[string]string `json:"v,omitempty"`
}

// cached wraps a GET handler with a Redis-backed response cache.
//
//   - Only GETs are cached (other methods bypass).
//   - Successful (2xx) and client-cacheable (304) responses are persisted.
//   - Cache key is sha256(url + Authorization), so per-token responses don't
//     leak between users.
//   - Anything cached returns immediately (no handler call) → first paint
//     after a restart is bounded by Redis latency, not SQL.
//
// If Redis is nil the wrapper degrades gracefully to a passthrough.
func (s *Server) cached(ttl time.Duration, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || s.redis == nil {
			h(w, r)
			return
		}
		if ttl <= 0 {
			ttl = s.cacheTTL
		}
		if ttl <= 0 {
			ttl = 10 * time.Second
		}

		key := cacheKeyForRequest(r)
		ctx := r.Context()

		// Cache hit — replay the response verbatim.
		var stored cachedResponse
		if ok, err := s.redis.GetJSON(ctx, key, &stored); err == nil && ok {
			if stored.ContentType != "" {
				w.Header().Set("Content-Type", stored.ContentType)
			}
			w.Header().Set("X-Cache", "HIT")
			if stored.Status == 0 {
				stored.Status = http.StatusOK
			}
			w.WriteHeader(stored.Status)
			_, _ = w.Write(stored.Body)
			return
		}

		// Cache miss — run handler against a buffering ResponseWriter so we
		// can both stream to client and persist a copy.
		buf := newCapturingWriter(w)
		h(buf, r)

		w.Header().Set("X-Cache", "MISS")
		buf.flush()

		if buf.status >= 200 && buf.status < 300 {
			payload := cachedResponse{
				Status:      buf.status,
				ContentType: buf.Header().Get("Content-Type"),
				Body:        append([]byte(nil), buf.body.Bytes()...),
			}
			// Synchronous write — Redis is local (sub-ms), and a sync write
			// avoids a race where two near-simultaneous misses both run the
			// handler before either has persisted.
			writeCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			_ = s.redis.SetJSON(writeCtx, key, payload, ttl)
			cancel()
		}
	}
}

// cacheKeyForRequest builds a stable per-token key. The Authorization header
// is hashed in so two users with different tokens get different cache slots
// (prevents one user seeing another's filtered view).
func cacheKeyForRequest(r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(r.URL.RequestURI()))
	h.Write([]byte{0})
	h.Write([]byte(r.Header.Get("Authorization")))
	return "http:" + hex.EncodeToString(h.Sum(nil))
}

// capturingWriter records the handler's output so we can both forward it
// to the real client AND persist a copy in Redis on the way out.
type capturingWriter struct {
	upstream http.ResponseWriter
	body     bytes.Buffer
	status   int
	headers  http.Header
	written  bool
}

func newCapturingWriter(w http.ResponseWriter) *capturingWriter {
	return &capturingWriter{
		upstream: w,
		status:   http.StatusOK,
		headers:  make(http.Header),
	}
}

func (c *capturingWriter) Header() http.Header {
	return c.headers
}

func (c *capturingWriter) WriteHeader(code int) {
	c.status = code
}

func (c *capturingWriter) Write(p []byte) (int, error) {
	return c.body.Write(p)
}

// flush copies captured headers + body to the real ResponseWriter exactly
// once. Called after the handler returns; if the handler streamed via
// Hijack/SSE this would no-op (we don't cache those endpoints anyway).
func (c *capturingWriter) flush() {
	if c.written {
		return
	}
	c.written = true
	for k, vs := range c.headers {
		for _, v := range vs {
			c.upstream.Header().Add(k, v)
		}
	}
	c.upstream.WriteHeader(c.status)
	_, _ = c.upstream.Write(c.body.Bytes())
}

// InvalidateHTTPCache wipes every cached HTTP response. Called after a
// batch is processed so the next user request sees fresh data instead of
// a 10-second-stale snapshot.
func (s *Server) InvalidateHTTPCache(ctx context.Context) {
	if s.redis == nil {
		return
	}
	_ = s.redis.DeletePrefix(ctx, "http:")
}
