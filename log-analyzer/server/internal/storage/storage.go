package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/xray-log-analyzer/server/internal/cache"
)

const (
	CacheTTLShort  = 10 * time.Second
	CacheTTLMedium = 30 * time.Second
	CacheTTLLong   = 5 * time.Minute
)

//go:embed schema.sql
var schemaSQL string

type Storage struct {
	pool         *pgxpool.Pool
	db           *sql.DB // stdlib-compat handle so incremental porting works
	cache        *cache.Cache
	nodeRemnaMap map[string]string

	closeOnce sync.Once
}

// New opens a pgx pool at dsn, applies schema.sql, returns Storage.
func New(ctx context.Context, dsn string) (*Storage, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg ping: %w", err)
	}

	sqlDB := stdlib.OpenDBFromPool(pool)

	s := &Storage{
		pool:  pool,
		db:    sqlDB,
		cache: cache.New(),
	}
	if err := s.migrate(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database connection pool.
func (s *Storage) Close() error {
	s.closeOnce.Do(func() {
		if s.db != nil {
			s.db.Close()
		}
		if s.pool != nil {
			s.pool.Close()
		}
	})
	return nil
}

// DB returns the stdlib-compat sql.DB handle backed by the pgx pool.
func (s *Storage) DB() *sql.DB { return s.db }

// Pool returns the underlying pgx pool for callers that want native pgx features.
func (s *Storage) Pool() *pgxpool.Pool { return s.pool }

// migrate applies schema.sql. Idempotent — all CREATEs use IF NOT EXISTS.
func (s *Storage) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}

// InvalidateCache clears cache entries with the given prefix.
func (s *Storage) InvalidateCache(prefix string) {
	s.cache.DeletePrefix(prefix)
}

// CacheStats returns cache statistics.
func (s *Storage) CacheStats() map[string]int {
	return s.cache.Stats()
}

// SetNodeRemnaMap wires agent NODE_ID → Remnawave node name so online user
// counts can be sourced from the Remnawave sync (XTLS tracked sessions)
// instead of being inferred from access-log recency.
func (s *Storage) SetNodeRemnaMap(m map[string]string) {
	if m == nil {
		s.nodeRemnaMap = nil
		return
	}
	s.nodeRemnaMap = make(map[string]string, len(m))
	for k, v := range m {
		s.nodeRemnaMap[k] = v
	}
}

// WarmCache pre-populates the in-process L1 cache by firing all heavy read
// queries in parallel. Called once at startup and after each Remnawave sync.
func (s *Storage) WarmCache(ctx context.Context) {
	log.Println("[cache] warming cache in parallel...")
	start := time.Now()

	var wg sync.WaitGroup

	warmFuncs := []func(){
		func() { s.GetGlobalStats(ctx) },
		func() { s.GetNodeStats(ctx) },
		func() { s.GetRemnaStats(ctx) },
		func() { s.GetThreatStats(ctx) },
		func() { s.GetAllUsers(ctx, 100) },
		func() { s.GetCorrelationStats(ctx) },
		func() { s.GetHourlyStats(ctx, 24) },
		func() { s.GetRemnaUsers(ctx, 100, "", "") },
		func() { s.GetRemnaNodes(ctx) },
		func() { s.GetTopSharedHWIDs(ctx, 50) },
		func() { s.GetTopSharedIPs(ctx, 50) },
	}

	wg.Add(len(warmFuncs))
	for _, fn := range warmFuncs {
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}
	wg.Wait()

	log.Printf("[cache] cache warmed in %v, stats: %v", time.Since(start), s.cache.Stats())
}
