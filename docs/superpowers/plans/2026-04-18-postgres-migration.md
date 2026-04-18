# Postgres Migration Plan (xray-log-analyzer)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SQLite (modernc.org/sqlite) with PostgreSQL 17 as the analyzer's primary datastore, removing SQLITE_BUSY write-contention and enabling AI-friendly analytics.

**Architecture:**
- Separate `analyzer-postgres` container alongside `analyzer-redis` in the log-analyzer compose stack (isolation from Remnawave's postgres).
- Single Go `*pgxpool.Pool` driving all `*Storage` methods; ~259 SQL calls across 19 files get ported (`INSERT OR REPLACE` → `ON CONFLICT`, `datetime()`/`strftime()` → `NOW()`/`to_char()`, `GLOB` → regex, etc.).
- Tests switch from on-disk SQLite temp files to per-test Postgres schemas via `testcontainers-go`.
- Hybrid data migration: *live* tables (users, nodes, risk_profiles, bridged_flows, IP history) moved whole; *history* tables (hourly_stats, threat_matches, blacklist_matches, anomalies) keep only last 7 days + resolved=0.
- Cut-over plan: stop analyzer → run migration tool → swap DB_BACKEND env → start analyzer. ~2-minute downtime.

**Tech Stack:**
- PostgreSQL 17-alpine (Docker), `pgx/v5` + `pgxpool` driver.
- `github.com/jackc/pgx/v5/stdlib` for `database/sql` compatibility during incremental porting.
- `github.com/testcontainers/testcontainers-go/modules/postgres` for isolated tests.
- `github.com/jackc/tern/v2` CLI for schema migrations (or hand-rolled `migrate()` in storage.go, keeping existing pattern).

---

## File Structure

| Path | Purpose | New/Modified |
|------|---------|--------------|
| `log-analyzer/docker-compose.yml` | Add `analyzer-postgres` service + volume + env wiring | Modified |
| `log-analyzer/server/internal/storage/schema.sql` | Postgres DDL (all tables + indexes) | **New** (extracted from `storage.go:migrate()`) |
| `log-analyzer/server/internal/storage/storage.go` | pgx pool init, replace SQLite pragmas, keep `migrate()` driving schema.sql | Modified |
| `log-analyzer/server/internal/storage/*.go` (18 files) | Port SQL dialect (`INSERT OR REPLACE`, `datetime()`, `GLOB`, parameter placeholders `?` → `$1`) | Modified |
| `log-analyzer/server/cmd/migrate-from-sqlite/main.go` | One-shot migration tool: reads SQLite, writes Postgres (live full + history 7d) | **New** |
| `log-analyzer/server/internal/storage/testutil.go` | `testcontainers-go` helper spinning up per-test Postgres | **New** |
| `log-analyzer/server/internal/storage/*_test.go` | Retargeted to use testutil (replaces `t.TempDir()` SQLite files) | Modified |
| `log-analyzer/server/internal/config/config.go` | Add `PostgresURL` env + deprecate `DBPath` (kept for migrator tool) | Modified |
| `log-analyzer/server/cmd/server/main.go` | Open pgx pool, pass to `storage.New(ctx, pool)` | Modified |
| `log-analyzer/server/go.mod`, `go.sum` | Add pgx + testcontainers | Modified |
| `docs/superpowers/plans/2026-04-18-postgres-migration.md` | This plan | **New** |

---

## Task 1: Add Postgres container + pgx dependency (no code wiring yet)

Get infra and deps ready without touching Go code. Everything keeps working on SQLite.

**Files:**
- Modify: `log-analyzer/docker-compose.yml`
- Modify: `log-analyzer/server/go.mod`
- Modify: `log-analyzer/server/go.sum`

- [ ] **Step 1: Add analyzer-postgres service**

Append to `log-analyzer/docker-compose.yml` (before `volumes:` block):

```yaml
  analyzer-postgres:
    image: postgres:17-alpine
    container_name: analyzer-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: xray_analyzer
      POSTGRES_USER: xray_analyzer
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme_in_env}
    volumes:
      - analyzer-postgres-data:/var/lib/postgresql/data
    command: >-
      postgres
      -c shared_buffers=256MB
      -c work_mem=4MB
      -c maintenance_work_mem=64MB
      -c effective_cache_size=1GB
      -c wal_buffers=16MB
      -c max_connections=40
      -c random_page_cost=1.1
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "xray_analyzer"]
      interval: 10s
      timeout: 3s
      retries: 5
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "3"
    networks:
      - analyzer-net
```

Add to `volumes:` block:
```yaml
  analyzer-postgres-data:
```

- [ ] **Step 2: Add pgx + testcontainers to go.mod**

```bash
cd log-analyzer/server
go get github.com/jackc/pgx/v5 github.com/jackc/pgx/v5/pgxpool github.com/jackc/pgx/v5/stdlib
go get github.com/testcontainers/testcontainers-go github.com/testcontainers/testcontainers-go/modules/postgres
```

- [ ] **Step 3: Stand the container up locally and sanity-check**

Run:
```bash
cd log-analyzer && docker compose up -d analyzer-postgres
docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer -c "SELECT version();"
```
Expected: PostgreSQL 17.x version line.

- [ ] **Step 4: Commit**

```bash
git add log-analyzer/docker-compose.yml log-analyzer/server/go.mod log-analyzer/server/go.sum
git commit -m "chore(postgres): add analyzer-postgres container + pgx deps"
```

---

## Task 2: Postgres schema draft + smoke test

Create the full schema as a standalone SQL file, applied on startup. Not yet wired to Go storage code — just proves DDL is valid under Postgres.

**Files:**
- Create: `log-analyzer/server/internal/storage/schema.sql`
- Create: `log-analyzer/server/internal/storage/schema_test.go`

- [ ] **Step 1: Write the failing test**

Create `log-analyzer/server/internal/storage/schema_test.go`:

```go
package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestSchemaAppliesCleanly loads schema.sql into a fresh Postgres and asserts
// every expected table exists. It guards against dialect-specific DDL bugs
// (SQLite AUTOINCREMENT vs Postgres IDENTITY, strftime-indexed generated
// columns, etc.) before we port any query code.
func TestSchemaAppliesCleanly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	pg, err := tcpg.Run(ctx, "postgres:17-alpine",
		tcpg.WithDatabase("test"),
		tcpg.WithUsername("test"),
		tcpg.WithPassword("test"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	defer pg.Terminate(ctx)

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	schema, err := os.ReadFile(filepath.Join("schema.sql"))
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	if _, err := pool.Exec(ctx, string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	wantTables := []string{
		"node_stats", "user_stats", "blacklist_matches", "alerts", "hourly_stats",
		"user_destinations", "threat_matches", "anomalies", "user_ip_history",
		"user_risk_profiles", "remna_users", "remna_hwid_devices", "remna_nodes",
		"bridged_flows", "online_snapshots", "ip_user_map", "hwid_user_map",
		"user_fingerprints",
	}
	for _, tbl := range wantTables {
		var ok bool
		err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, tbl).Scan(&ok)
		if err != nil || !ok {
			t.Errorf("table %q not found (err=%v)", tbl, err)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd log-analyzer/server
go test ./internal/storage/ -run TestSchemaAppliesCleanly -timeout 180s
```
Expected: FAIL with "read schema.sql: no such file".

- [ ] **Step 3: Create schema.sql**

Create `log-analyzer/server/internal/storage/schema.sql`. Port the full DDL from `storage.go:migrate()` with these translation rules (pick the table you're working on, apply them, move on — don't try to hold all 20 tables in your head at once):

- `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY`
- `TEXT PRIMARY KEY` → `TEXT PRIMARY KEY` (unchanged)
- `DATETIME DEFAULT CURRENT_TIMESTAMP` → `TIMESTAMPTZ DEFAULT NOW()`
- `DATETIME` (nullable) → `TIMESTAMPTZ`
- `INTEGER` → `BIGINT` (row counts, sizes) OR `INTEGER` (confidence / severity integers 0-100)
- `REAL` → `DOUBLE PRECISION`
- `CHECK (id = 1)` singleton pattern → keep, works in Postgres
- Remove SQLite-only `INSERT OR IGNORE ... VALUES (1, 0)` — do it separately with `ON CONFLICT DO NOTHING`
- `CREATE INDEX IF NOT EXISTS` → unchanged (Postgres 9.5+)
- Tables without a natural PK that used `ROWID` in SQLite: add `id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY`
- Composite unique constraints like `UNIQUE(user_email, ip_address)` → unchanged

Reference list (read from existing `storage.go`, don't invent columns):
```
node_stats, user_stats, blacklist_matches, alerts, hourly_stats,
user_destinations, threat_matches, threat_stats_agg, threat_type_stats,
user_threat_stats, user_threat_domains, threat_hourly_stats,
threat_hourly_users, threat_daily_stats, threat_daily_users,
threat_geo_stats, user_locations, user_ip_history, anomalies,
user_activity_baseline, user_risk_profiles, dns_domain_stats,
dns_hourly_stats, dns_daily_stats, user_dns_stats, reports,
ip_user_map, hwid_user_map, user_fingerprints, user_clusters,
user_ai_profile, user_sessions, remna_users, remna_hwid_devices,
remna_nodes, ai_chat_sessions, ai_chat_messages, online_snapshots,
bridged_flows
```

Append the singleton seed at the bottom:
```sql
INSERT INTO threat_stats_agg (id, total_matches) VALUES (1, 0) ON CONFLICT DO NOTHING;
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test ./internal/storage/ -run TestSchemaAppliesCleanly -timeout 180s
```
Expected: PASS (first run downloads the postgres:17-alpine image, ~30s; later runs ~15s).

- [ ] **Step 5: Commit**

```bash
git add log-analyzer/server/internal/storage/schema.sql log-analyzer/server/internal/storage/schema_test.go
git commit -m "feat(postgres): schema.sql + schema-apply smoke test"
```

---

## Task 3: Storage test harness on Postgres

Before porting any query code, build the shared test helper that spins up a clean Postgres per test. Every subsequent storage test will call this instead of `t.TempDir()`.

**Files:**
- Create: `log-analyzer/server/internal/storage/testutil_test.go`
- Modify: `log-analyzer/server/internal/storage/anomaly_test.go` — switch `newTestStorage` to the new helper.

- [ ] **Step 1: Write failing test**

Create `log-analyzer/server/internal/storage/testutil_test.go`:

```go
package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	sharedPGOnce sync.Once
	sharedPGDSN  string
	sharedPGErr  error
)

// sharedPostgres spins up a single Postgres container for the whole test
// binary — each test gets its own schema inside it, which is ~100× faster
// than spawning a container per test.
func sharedPostgres(t *testing.T) string {
	t.Helper()
	sharedPGOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		pg, err := tcpg.Run(ctx, "postgres:17-alpine",
			tcpg.WithDatabase("shared"),
			tcpg.WithUsername("shared"),
			tcpg.WithPassword("shared"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
		)
		if err != nil {
			sharedPGErr = err
			return
		}
		sharedPGDSN, sharedPGErr = pg.ConnectionString(ctx, "sslmode=disable")
	})
	if sharedPGErr != nil {
		t.Fatalf("shared postgres: %v", sharedPGErr)
	}
	return sharedPGDSN
}

// newTestStorage returns a Storage backed by a dedicated schema inside the
// shared container. Schema is dropped on cleanup.
func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	dsn := sharedPostgres(t)
	ctx := context.Background()

	schema := "test_" + randomSuffix()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	admin.Close()

	scopedDSN := dsn + "&search_path=" + schema
	s, err := New(ctx, scopedDSN)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		cleanupPool, _ := pgxpool.New(ctx, dsn)
		if cleanupPool != nil {
			cleanupPool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			cleanupPool.Close()
		}
	})
	return s
}

func randomSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
go test ./internal/storage/ -run NothingMatchesThis -timeout 60s
```
Expected: compilation error — `storage.New` still has old SQLite signature `func New(dbPath string) (*Storage, error)`.

This failure is intentional — it pins down the API we're about to introduce in Task 4.

- [ ] **Step 3: Leave the file in place and commit as work-in-progress**

We're intentionally committing a broken test so Task 4 can make it pass:

```bash
git add log-analyzer/server/internal/storage/testutil_test.go
git commit -m "test(postgres): shared container + per-test schema harness (WIP, compiles in Task 4)"
```

---

## Task 4: Swap storage backend to pgx (schema only)

Replace the SQLite driver in `storage.go` with pgx. Only the init path changes; the query methods keep their current SQLite syntax and will be ported one file at a time in Task 5+. To keep the build green during that gradual port, this task **stops linking to** existing query files that haven't been ported yet — we move them behind a temporary build tag.

**Files:**
- Modify: `log-analyzer/server/internal/storage/storage.go`
- Create: `log-analyzer/server/internal/storage/_stash/README.md`
- Modify: every other `log-analyzer/server/internal/storage/*.go` — add `//go:build sqlite_legacy` build tag at the top so they stop compiling in the normal build.

- [ ] **Step 1: Write failing test**

Add to `testutil_test.go`:

```go
func TestStorageNew_Postgres(t *testing.T) {
	s := newTestStorage(t)
	if s == nil {
		t.Fatal("storage is nil")
	}
	// Smoke: a trivial ping-through-pool query works.
	ctx := context.Background()
	var got int
	if err := s.DB().QueryRowContext(ctx, "SELECT 1").Scan(&got); err != nil {
		t.Fatalf("SELECT 1: %v", err)
	}
	if got != 1 {
		t.Fatalf("got %d want 1", got)
	}
}
```

Run:
```bash
go test ./internal/storage/ -run TestStorageNew_Postgres -timeout 180s
```
Expected: FAIL — build errors (New has wrong signature, or query files missing).

- [ ] **Step 2: Rewrite storage.go init path**

Replace the top of `log-analyzer/server/internal/storage/storage.go` (everything above `migrate()`) with:

```go
package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
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

func (s *Storage) DB() *sql.DB          { return s.db }
func (s *Storage) Pool() *pgxpool.Pool  { return s.pool }

// migrate applies schema.sql. Idempotent — all CREATEs use IF NOT EXISTS.
func (s *Storage) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}
```

Remove the giant embedded schema string from `storage.go` (it now lives in `schema.sql`, embedded via `//go:embed`). Keep `InvalidateCache`, `CacheStats`, `WarmCache`, `SetNodeRemnaMap` methods as-is at the bottom of storage.go — they don't touch SQL.

- [ ] **Step 3: Build-tag-fence every other storage file**

For each of the 18 files in `internal/storage/` **except** `storage.go`, `testutil_test.go`, `schema.sql`, `schema_test.go`, add the line `//go:build sqlite_legacy` as the very first line (before `package storage`):

```bash
for f in log-analyzer/server/internal/storage/*.go; do
  base=$(basename "$f")
  case "$base" in
    storage.go|testutil_test.go|schema_test.go) continue;;
  esac
  awk 'NR==1 && $0=="package storage" {print "//go:build sqlite_legacy"; print ""} {print}' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done
```

This keeps them compilable under the `sqlite_legacy` build tag (useful for the migration tool in Task 7) while removing them from the default build.

- [ ] **Step 4: Build to confirm storage compiles alone**

```bash
go build ./internal/storage/
```
Expected: succeeds. Some symbols used by `server/`/`analyzer/` packages are now missing — expected; they'll be restored one file at a time in Task 5.

- [ ] **Step 5: Run the new test**

```bash
go test ./internal/storage/ -run TestStorageNew_Postgres -timeout 180s
```
Expected: PASS — migrate runs, pool pings, SELECT 1 works.

- [ ] **Step 6: Commit**

```bash
git add log-analyzer/server/internal/storage/
git commit -m "feat(postgres): pgx pool init, schema.sql wired, legacy files gated"
```

---

## Task 5: Port query files incrementally

**Repeat for each of the 18 query files, easiest → hardest:** `online_snapshots.go`, `destinations.go`, `alerts.go`, `bridged_flows.go`, `hourly.go`, `chat.go`, `nodes.go`, `blacklist.go`, `geo_stats.go`, `user_risk.go`, `anomaly.go`, `reports.go`, `dns_stats.go`, `threat_stats.go`, `correlation.go`, `threat_matches.go`, `remnawave.go`, `users.go`.

For each file: port, bring back the existing `*_test.go` if any, run tests, commit.

**File template — apply to every query file:**

- [ ] **Step 1: Remove the legacy build tag**

Delete the `//go:build sqlite_legacy` line from the top of the file.

- [ ] **Step 2: Port SQL dialect**

Mechanical substitutions (do them in this order to avoid collisions):

1. `INSERT OR REPLACE INTO foo (...)` → `INSERT INTO foo (...) ... ON CONFLICT (<pk>) DO UPDATE SET col = EXCLUDED.col ...`
2. `INSERT OR IGNORE INTO foo (...)` → `INSERT INTO foo (...) ON CONFLICT DO NOTHING`
3. `ON CONFLICT(col) DO UPDATE SET x = excluded.x` → `ON CONFLICT (col) DO UPDATE SET x = EXCLUDED.x` (note spacing + uppercase `EXCLUDED`)
4. Numbered placeholders: count `?` in the query and replace with `$1`, `$2`, ... **in order**. The easiest approach is a small helper at package scope:

```go
// pgArgs rewrites the SQLite-style "?" placeholders in q to "$1", "$2", ...
func pgArgs(q string) string {
	var out []byte
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, '$')
			out = append(out, []byte(fmt.Sprintf("%d", n))...)
			continue
		}
		out = append(out, q[i])
	}
	return string(out)
}
```

Call it on every query string. (Dropping a dev-time `strings.Contains(q, "?")` assertion is fine while porting — avoids missing a placeholder.)

5. Date functions:
   - `datetime('now')` → `NOW()`
   - `datetime('now', '-5 minutes')` → `NOW() - INTERVAL '5 minutes'`
   - `datetime('now', ?)` where the param is a string like `"-5 minutes"` → stop computing the string; pass `time.Duration` via `$N::interval` *or* pass a `time.Time` and compare directly: `last_seen >= $1` with `time.Now().Add(-5 * time.Minute)` from Go.
   - `strftime('%Y-%m-%d %H', ts)` → `to_char(ts, 'YYYY-MM-DD HH24')`
   - `strftime('%H', ts) AS h` → `to_char(ts, 'HH24')` (result is TEXT — same as SQLite)
   - `strftime('%Y-%m-%dT%H:00:00Z', ts)` → `to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:00:00"Z"')`

6. Boolean columns: SQLite stored 0/1 in `INTEGER`. Postgres uses `BOOLEAN`. Where tests did `resolved int; ... resolved == 1` — switch to `resolved bool` and compare to `resolved`. Update schema.sql to declare those columns `BOOLEAN DEFAULT FALSE`.

7. `GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*:[0-9]*'` → `~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$'` (regex; `.` is a metachar and needs escaping).

8. `SUBSTR / INSTR` string ops: `INSTR(destination, ':')` → `POSITION(':' IN destination)` (same semantics, 1-based).

9. `strings.Join(placeholders, ",")` for a slice: rewrite to `= ANY($1)` and pass the slice directly. `stdlib.OpenDBFromPool` marshals `[]string` / `[]int` to Postgres arrays automatically, no `pq.Array` wrapper needed:

```go
// Before (SQLite): "node_id IN (%s)" with len(ids) "?" placeholders
// After  (PG):     "node_id = ANY($1)" with ids as a single arg
rows, err := s.db.QueryContext(ctx, "SELECT ... WHERE node_id = ANY($1)", ids)
```

10. `sql.ErrNoRows`: still works with `pgx/v5/stdlib`. No change.

- [ ] **Step 3: Port the test file if it exists**

Tests previously opened SQLite through `storage.New("tempfile.db")`. Switch them to `newTestStorage(t)` (the helper from Task 3). Table inserts that used raw date strings (`"2026-04-17T14:07:24.724077Z"`) keep working — Postgres TIMESTAMPTZ accepts ISO-8601.

- [ ] **Step 4: Run the tests**

```bash
go test ./internal/storage/ -run TestThisFileOnly -v -timeout 120s
```

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(postgres): port <filename>.go queries + tests"
```

**Track progress with TodoWrite — one todo per file. Don't batch more than 2-3 files per commit; a single SQL-dialect bug is cheaper to find in a 100-line diff than a 1000-line one.**

---

## Task 6: Re-enable callers (server/, analyzer/)

Once every storage file is ported (no more `//go:build sqlite_legacy` tags left), re-enable the rest of the binary.

- [ ] **Step 1: Update `storage.New` callers**

`cmd/server/main.go`: change
```go
store, err := storage.New(cfg.DBPath)
```
to
```go
store, err := storage.New(ctx, cfg.PostgresURL)
```

`internal/config/config.go`: add
```go
PostgresURL: getEnv("POSTGRES_URL", "postgres://xray_analyzer:changeme@analyzer-postgres:5432/xray_analyzer?sslmode=disable"),
```

- [ ] **Step 2: Update docker-compose.yml env**

Add to `analyzer-server.environment`:
```yaml
      - POSTGRES_URL=postgres://xray_analyzer:${POSTGRES_PASSWORD}@analyzer-postgres:5432/xray_analyzer?sslmode=disable
```

And `depends_on`:
```yaml
    depends_on:
      analyzer-redis:
        condition: service_started
      analyzer-postgres:
        condition: service_healthy
```

- [ ] **Step 3: Full build + test**

```bash
go build ./...
go test ./... -timeout 180s
```
Expected: all green. If something in `server/` or `analyzer/` references a removed helper, fix the caller (usually signature-compatible).

- [ ] **Step 4: Commit**

```bash
git commit -am "feat(postgres): wire server main + config to postgres DSN"
```

---

## Task 7: Migration tool (cmd/migrate-from-sqlite)

One-shot program that reads the existing SQLite database and writes into fresh Postgres. Hybrid policy: live tables full copy, history tables last 7 days + active anomalies.

**Files:**
- Create: `log-analyzer/server/cmd/migrate-from-sqlite/main.go`

- [ ] **Step 1: Scaffold the command**

```go
// migrate-from-sqlite copies analyzer data from the old SQLite file to the
// new Postgres instance. Invoked once during the cut-over. Not part of the
// hot path; stays tagged sqlite_legacy so modernc.org/sqlite isn't pulled
// into the main binary.
//go:build sqlite_legacy

package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"
)

func main() {
	sqlitePath := flag.String("sqlite", "/app/data/analyzer.db", "path to existing SQLite database")
	pgURL := flag.String("postgres", "", "Postgres DSN (required)")
	retentionDays := flag.Int("history-days", 7, "how many days of history to migrate")
	flag.Parse()

	if *pgURL == "" {
		log.Fatal("-postgres required")
	}

	sqliteDB, err := sql.Open("sqlite", "file:"+*sqlitePath+"?mode=ro")
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer sqliteDB.Close()

	ctx := context.Background()
	pg, err := pgxpool.New(ctx, *pgURL)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer pg.Close()

	cutoff := time.Now().UTC().Add(-time.Duration(*retentionDays) * 24 * time.Hour)

	migrateFull(ctx, sqliteDB, pg, "remna_users")
	migrateFull(ctx, sqliteDB, pg, "remna_hwid_devices")
	migrateFull(ctx, sqliteDB, pg, "remna_nodes")
	migrateFull(ctx, sqliteDB, pg, "node_stats")
	migrateFull(ctx, sqliteDB, pg, "user_stats")
	migrateFull(ctx, sqliteDB, pg, "user_risk_profiles")
	migrateFull(ctx, sqliteDB, pg, "user_ip_history")
	migrateFull(ctx, sqliteDB, pg, "ip_user_map")
	migrateFull(ctx, sqliteDB, pg, "hwid_user_map")
	migrateFull(ctx, sqliteDB, pg, "user_fingerprints")
	migrateFull(ctx, sqliteDB, pg, "user_locations")
	migrateFull(ctx, sqliteDB, pg, "bridged_flows")
	migrateFull(ctx, sqliteDB, pg, "online_snapshots")

	migrateWithCutoff(ctx, sqliteDB, pg, "hourly_stats", "hour", cutoff)
	migrateWithCutoff(ctx, sqliteDB, pg, "threat_matches", "matched_at", cutoff)
	migrateWithCutoff(ctx, sqliteDB, pg, "blacklist_matches", "timestamp", cutoff)
	migrateAnomalies(ctx, sqliteDB, pg) // resolved=false OR detected_at>=cutoff

	log.Println("migration complete")
}

// migrateFull copies every row.
func migrateFull(ctx context.Context, src *sql.DB, dst *pgxpool.Pool, table string) {
	// Implemented in Step 2.
	panic("TODO: implement in Step 2")
}

// migrateWithCutoff copies rows where <timeCol> >= cutoff.
func migrateWithCutoff(ctx context.Context, src *sql.DB, dst *pgxpool.Pool, table, timeCol string, cutoff time.Time) {
	panic("TODO: implement in Step 2")
}

// migrateAnomalies copies unresolved anomalies plus anything fresh.
func migrateAnomalies(ctx context.Context, src *sql.DB, dst *pgxpool.Pool) {
	panic("TODO: implement in Step 2")
}

// Silence unused-import warnings during scaffolding.
var _ = fmt.Sprint
```

- [ ] **Step 2: Implement the three migrators**

Body for `migrateFull`:

```go
func migrateFull(ctx context.Context, src *sql.DB, dst *pgxpool.Pool, table string) {
	rows, err := src.QueryContext(ctx, "SELECT * FROM "+table)
	if err != nil {
		log.Printf("%s: source query: %v", table, err)
		return
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		log.Printf("%s: columns: %v", table, err)
		return
	}

	// Stream via COPY FROM for performance. 500MB SQLite → Postgres in
	// a few minutes; row-by-row INSERT would take hours.
	copyRows := &sqlRowSource{rows: rows, cols: cols, err: nil}
	tag, err := dst.CopyFrom(ctx, pgx.Identifier{table}, cols, copyRows)
	if err != nil {
		log.Printf("%s: COPY: %v (rows so far=%d)", table, err, tag)
		return
	}
	log.Printf("%s: copied %d rows", table, tag)
}

type sqlRowSource struct {
	rows *sql.Rows
	cols []string
	vals []any
	err  error
}

func (s *sqlRowSource) Next() bool {
	if !s.rows.Next() {
		return false
	}
	s.vals = make([]any, len(s.cols))
	ptrs := make([]any, len(s.cols))
	for i := range s.vals {
		ptrs[i] = &s.vals[i]
	}
	if err := s.rows.Scan(ptrs...); err != nil {
		s.err = err
		return false
	}
	return true
}
func (s *sqlRowSource) Values() ([]any, error) { return s.vals, s.err }
func (s *sqlRowSource) Err() error             { return s.err }
```

Body for `migrateWithCutoff`:

```go
func migrateWithCutoff(ctx context.Context, src *sql.DB, dst *pgxpool.Pool, table, timeCol string, cutoff time.Time) {
	rows, err := src.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s WHERE %s >= ?", table, timeCol), cutoff.Format(time.RFC3339))
	if err != nil {
		log.Printf("%s: %v", table, err)
		return
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	copyRows := &sqlRowSource{rows: rows, cols: cols}
	tag, err := dst.CopyFrom(ctx, pgx.Identifier{table}, cols, copyRows)
	if err != nil {
		log.Printf("%s: %v", table, err)
		return
	}
	log.Printf("%s (>=%s): %d rows", table, cutoff.Format("2006-01-02"), tag)
}
```

Body for `migrateAnomalies`:

```go
func migrateAnomalies(ctx context.Context, src *sql.DB, dst *pgxpool.Pool) {
	rows, err := src.QueryContext(ctx, `SELECT * FROM anomalies WHERE resolved = 0 OR detected_at >= datetime('now','-7 days')`)
	if err != nil {
		log.Printf("anomalies: %v", err)
		return
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	copyRows := &sqlRowSource{rows: rows, cols: cols}
	tag, err := dst.CopyFrom(ctx, pgx.Identifier{"anomalies"}, cols, copyRows)
	if err != nil {
		log.Printf("anomalies COPY: %v", err)
		return
	}
	log.Printf("anomalies (active+7d): %d rows", tag)
}
```

- [ ] **Step 3: Build with the legacy tag**

```bash
cd log-analyzer/server
go build -tags sqlite_legacy -o /tmp/migrate-from-sqlite ./cmd/migrate-from-sqlite
```
Expected: a binary at `/tmp/migrate-from-sqlite`.

- [ ] **Step 4: Commit**

```bash
git add log-analyzer/server/cmd/migrate-from-sqlite/main.go
git commit -m "feat(postgres): one-shot migration tool from sqlite (hybrid retention)"
```

---

## Task 8: Dry-run migration against a Postgres copy on VM 101

Do this on the actual production data but into a **separate** database so we can compare and iterate without downtime.

- [ ] **Step 1: Push code + build migrator on VM 101**

```bash
ssh dedik "ssh root@10.10.10.20 'cd /opt/xray/log-analyzer && git fetch origin && git reset --hard origin/postgres-migration && find . -name \"._*\" -delete'"
ssh dedik "ssh root@10.10.10.20 'cd /opt/xray/log-analyzer/server && docker run --rm -v \$PWD:/src -w /src golang:1.21-alpine sh -c \"apk add --no-cache git && go build -tags sqlite_legacy -o /src/migrate-from-sqlite ./cmd/migrate-from-sqlite\"'"
```

- [ ] **Step 2: Create a parallel `xray_analyzer_dryrun` database**

```bash
ssh dedik "ssh root@10.10.10.20 'docker exec analyzer-postgres psql -U xray_analyzer -d postgres -c \"CREATE DATABASE xray_analyzer_dryrun OWNER xray_analyzer;\"'"
```

- [ ] **Step 3: Apply schema**

```bash
ssh dedik "ssh root@10.10.10.20 'docker exec -i analyzer-postgres psql -U xray_analyzer -d xray_analyzer_dryrun < /opt/xray/log-analyzer/server/internal/storage/schema.sql'"
```

- [ ] **Step 4: Run migrator against prod SQLite + dryrun DB**

```bash
ssh dedik "ssh root@10.10.10.20 '/opt/xray/log-analyzer/server/migrate-from-sqlite -sqlite /var/lib/docker/volumes/log-analyzer_analyzer-data/_data/analyzer.db -postgres \"postgres://xray_analyzer:\${POSTGRES_PASSWORD}@localhost:5432/xray_analyzer_dryrun?sslmode=disable\" 2>&1 | tee /tmp/migrate.log'"
```

- [ ] **Step 5: Spot-check**

```bash
ssh dedik "ssh root@10.10.10.20 'docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer_dryrun -c \"
  SELECT '\''remna_users'\'' AS t, COUNT(*) FROM remna_users UNION ALL
  SELECT '\''anomalies'\'', COUNT(*) FROM anomalies UNION ALL
  SELECT '\''user_stats'\'', COUNT(*) FROM user_stats UNION ALL
  SELECT '\''hourly_stats'\'', COUNT(*) FROM hourly_stats;
\"'"
```

Cross-check against the SQLite counts the user captured in the previous debug session. Expect `remna_users`/`user_stats` to match exactly; `hourly_stats` to be smaller (7d only).

If any count is wildly off — revisit Task 7's migrator for that table before cut-over.

- [ ] **Step 6: Commit nothing (this is ops)**

No code change; this task is a dry-run gate.

---

## Task 9: Production cut-over

~2-minute downtime. Everything already deployed and tested on dry-run; this just swaps DSNs.

- [ ] **Step 1: Snapshot SQLite**

```bash
ssh dedik "ssh root@10.10.10.20 'cp /var/lib/docker/volumes/log-analyzer_analyzer-data/_data/analyzer.db /var/lib/docker/volumes/log-analyzer_analyzer-data/_data/analyzer.db.precutover.\$(date +%Y%m%d-%H%M%S)'"
```

- [ ] **Step 2: Stop analyzer**

```bash
ssh dedik "ssh root@10.10.10.20 'docker compose -f /opt/xray/log-analyzer/docker-compose.yml stop analyzer-server'"
```

- [ ] **Step 3: Drop dry-run DB, create clean production DB, apply schema**

```bash
ssh dedik "ssh root@10.10.10.20 'docker exec analyzer-postgres psql -U xray_analyzer -d postgres -c \"DROP DATABASE xray_analyzer;\"'"
ssh dedik "ssh root@10.10.10.20 'docker exec analyzer-postgres psql -U xray_analyzer -d postgres -c \"CREATE DATABASE xray_analyzer OWNER xray_analyzer;\"'"
ssh dedik "ssh root@10.10.10.20 'docker exec -i analyzer-postgres psql -U xray_analyzer -d xray_analyzer < /opt/xray/log-analyzer/server/internal/storage/schema.sql'"
```

- [ ] **Step 4: Run final migration**

```bash
ssh dedik "ssh root@10.10.10.20 '/opt/xray/log-analyzer/server/migrate-from-sqlite -sqlite /var/lib/docker/volumes/log-analyzer_analyzer-data/_data/analyzer.db -postgres \"postgres://xray_analyzer:\${POSTGRES_PASSWORD}@localhost:5432/xray_analyzer?sslmode=disable\"'"
```

- [ ] **Step 5: Start analyzer (now on Postgres)**

```bash
ssh dedik "ssh root@10.10.10.20 'cd /opt/xray/log-analyzer && docker compose up -d analyzer-server'"
```

- [ ] **Step 6: Verify**

```bash
ssh dedik "ssh root@10.10.10.20 'docker logs xray-log-analyzer --since 1m 2>&1 | head -30; curl -s -H \"Authorization: Bearer \${API_TOKEN}\" http://localhost:8237/api/stats'"
```
Expected: logs say `storage: initialized`, no SQLITE_* errors, `/api/stats` returns real numbers. Agents reconnect within 30s (anti-hang v2).

- [ ] **Step 7: Commit**

No code changes. Leave a memory note in `/Users/qwertyhq/.claude/projects/.../memory/project_xray_analyzer.md` with the cut-over date and the path to the preserved `.precutover.*` SQLite snapshot.

---

## Task 10: Cleanup (after 72h of stable Postgres)

Run 3 days after cut-over, once it's clear there's no regression.

- [ ] **Step 1: Delete SQLite volume from compose**

Remove `analyzer-data:/app/data` volume + `DB_PATH` env from `analyzer-server` in `docker-compose.yml`. Keep the `analyzer-data` volume declaration for one more week (backup safety net).

- [ ] **Step 2: Remove `sqlite_legacy` build tag support**

Delete `cmd/migrate-from-sqlite/` entirely. Drop `modernc.org/sqlite` from `go.mod` (`go mod tidy`).

- [ ] **Step 3: Drop the legacy DB_PATH config field**

`config.go`: remove `DBPath string` field.

- [ ] **Step 4: Final commit + push**

```bash
git commit -am "chore(postgres): remove sqlite legacy code after stable cut-over"
```

- [ ] **Step 5: Delete the preserved SQLite snapshot from VM 101** (optional, after 2 weeks):

```bash
ssh dedik "ssh root@10.10.10.20 'rm -f /var/lib/docker/volumes/log-analyzer_analyzer-data/_data/analyzer.db.precutover.*'"
```

---

## Rollback plan

If any production Postgres query returns wrong numbers or breaks the UI:

1. `docker compose stop analyzer-server` on VM 101.
2. `git revert` the cut-over commit on `main`, push.
3. `git pull` on VM 101, `docker compose up -d --build analyzer-server`.
4. SQLite file is still at its original path — analyzer boots back on it with last-known-good data.
5. File a follow-up issue describing which query misbehaved; fix with a test in the normal flow, then redo Task 9.
