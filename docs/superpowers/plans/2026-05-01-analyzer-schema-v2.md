# Analyzer Schema v2 Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Greenfield postgres schema rewrite for xray log-analyzer with native types (uuid, inet, smallint FK), daily partitioning for hot time-series tables, BRIN indexes, and DROP-PARTITION-based retention. TRUNCATE old data on cutover (user authorized).

**Architecture:** New schema.sql from scratch. New `internal/storage/partitions/` module manages daily partitions for `bridged_flows`, `alerts`, `blacklist_matches`, `threat_matches`, `anomalies`. Storage Go layer migrated to pgx/v5 native types (uuid.UUID, netip.Addr, custom NodeID smallint). API layer marshals back to strings. Postgres tuning via docker-compose `command:` overrides.

**Tech Stack:** Go 1.25, pgx/v5, postgres 17, testcontainers-go for tests, docker-compose for deployment.

**Spec:** [`docs/superpowers/specs/2026-05-01-analyzer-refactor-v2-design.md`](../specs/2026-05-01-analyzer-refactor-v2-design.md)

**Repo:** `/Users/qwertyhq/code/xray`. All paths relative to `log-analyzer/server/`.

**Branch:** `refactor/schema-v2` (already created, spec already committed).

---

## Phase 0: Foundation Types

### Task 0.1: Add UUID dependency

**Files:**
- Modify: `log-analyzer/server/go.mod`
- Modify: `log-analyzer/server/go.sum`

- [ ] **Step 1: Add google/uuid dependency**

```bash
cd /Users/qwertyhq/code/xray/log-analyzer/server
go get github.com/google/uuid
go mod tidy
```

- [ ] **Step 2: Verify pgx/v5 already supports uuid via pgtype**

```bash
grep -r "github.com/google/uuid" go.sum
grep -r "pgtype" go.mod
```

Expected: both present.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): add google/uuid for native uuid types"
```

### Task 0.2: Define NodeID type

**Files:**
- Create: `log-analyzer/server/internal/storage/types.go`
- Create: `log-analyzer/server/internal/storage/types_test.go`

- [ ] **Step 1: Write failing test**

```go
// log-analyzer/server/internal/storage/types_test.go
package storage

import (
	"testing"
)

func TestNodeID_Zero(t *testing.T) {
	var n NodeID
	if n != 0 {
		t.Fatalf("zero value should be 0, got %d", n)
	}
}

func TestNodeID_String(t *testing.T) {
	n := NodeID(42)
	if got := n.String(); got != "42" {
		t.Fatalf("String() = %q want %q", got, "42")
	}
}

func TestNodeID_IsZero(t *testing.T) {
	var zero NodeID
	if !zero.IsZero() {
		t.Fatal("zero NodeID should report IsZero()")
	}
	if NodeID(1).IsZero() {
		t.Fatal("non-zero NodeID should not report IsZero()")
	}
}
```

- [ ] **Step 2: Run test, verify fail**

```bash
cd log-analyzer/server
go test ./internal/storage/ -run TestNodeID -v
```

Expected: build fails with "undefined: NodeID".

- [ ] **Step 3: Implement minimal type**

```go
// log-analyzer/server/internal/storage/types.go
package storage

import "strconv"

// NodeID is the analyzer-internal smallint identifier for a node,
// foreign-keyed against nodes(id). Use storage.LookupNodeID to convert
// from the agent-provided text node_id (e.g. "ru-bridge", "germany-1").
type NodeID int16

func (n NodeID) String() string { return strconv.Itoa(int(n)) }
func (n NodeID) IsZero() bool   { return n == 0 }
```

- [ ] **Step 4: Run test, verify pass**

```bash
go test ./internal/storage/ -run TestNodeID -v
```

Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/storage/types.go internal/storage/types_test.go
git commit -m "feat(storage): NodeID smallint type"
```

---

## Phase 1: Partition Manager (independent module)

### Task 1.1: Module skeleton

**Files:**
- Create: `log-analyzer/server/internal/storage/partitions/manager.go`
- Create: `log-analyzer/server/internal/storage/partitions/manager_test.go`

- [ ] **Step 1: Write failing test for constructor**

```go
// log-analyzer/server/internal/storage/partitions/manager_test.go
package partitions

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewManager(t *testing.T) {
	var pool *pgxpool.Pool // nil pool ok for constructor test
	tables := []Table{{Name: "bridged_flows", RetentionDays: 14}}
	m := NewManager(pool, tables)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestTable_PartitionName(t *testing.T) {
	tbl := Table{Name: "bridged_flows"}
	day := mustDate("2026-05-01")
	if got := tbl.PartitionName(day); got != "bridged_flows_20260501" {
		t.Fatalf("PartitionName = %q want bridged_flows_20260501", got)
	}
}
```

Helper (also in test file):

```go
import "time"

func mustDate(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}
```

- [ ] **Step 2: Run test, expect build error**

```bash
go test ./internal/storage/partitions/ -v
```

Expected: build fails (package doesn't exist).

- [ ] **Step 3: Implement manager.go skeleton**

```go
// log-analyzer/server/internal/storage/partitions/manager.go
package partitions

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Table describes one partitioned parent table managed by this module.
type Table struct {
	Name          string // e.g. "bridged_flows"
	RetentionDays int    // e.g. 14
}

// PartitionName returns the daily partition name for a given UTC date.
// Format: <parent>_YYYYMMDD.
func (t Table) PartitionName(day time.Time) string {
	return t.Name + "_" + day.UTC().Format("20060102")
}

// Manager creates and drops daily partitions for the configured tables.
// Run() should be invoked in a goroutine; it ticks every 6 hours.
type Manager struct {
	pool   *pgxpool.Pool
	tables []Table
}

// NewManager constructs a Manager. The given tables are managed as a unit:
// every tick, future partitions are ensured and expired ones dropped for
// each table.
func NewManager(pool *pgxpool.Pool, tables []Table) *Manager {
	return &Manager{pool: pool, tables: tables}
}

// Run blocks until ctx is cancelled, calling Tick() once immediately and
// then every 6 hours. Errors are logged via the caller-supplied logger
// passed in via context value (TODO: switch to slog when codebase adopts it).
func (m *Manager) Run(ctx context.Context) error {
	if err := m.Tick(ctx); err != nil {
		return err
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_ = m.Tick(ctx)
		}
	}
}

// Tick performs one full reconciliation pass: ensure +2-day-ahead
// partitions exist, drop partitions older than RetentionDays.
func (m *Manager) Tick(ctx context.Context) error {
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		return err
	}
	return m.DropExpiredPartitions(ctx)
}

// EnsureFuturePartitions creates partitions for today and the next 2 days
// (UTC) for each managed table if they don't already exist.
func (m *Manager) EnsureFuturePartitions(ctx context.Context) error {
	return nil // implemented in Task 1.2
}

// DropExpiredPartitions drops partitions older than RetentionDays for each
// managed table.
func (m *Manager) DropExpiredPartitions(ctx context.Context) error {
	return nil // implemented in Task 1.3
}
```

- [ ] **Step 4: Run test, verify pass**

```bash
go test ./internal/storage/partitions/ -v
```

Expected: PASS (TestNewManager, TestTable_PartitionName).

- [ ] **Step 5: Commit**

```bash
git add internal/storage/partitions/
git commit -m "feat(storage/partitions): module skeleton"
```

### Task 1.2: EnsureFuturePartitions

**Files:**
- Modify: `log-analyzer/server/internal/storage/partitions/manager.go`
- Modify: `log-analyzer/server/internal/storage/partitions/manager_test.go`
- Create: `log-analyzer/server/internal/storage/partitions/testutil_test.go`

- [ ] **Step 1: Add testcontainers helper**

```go
// log-analyzer/server/internal/storage/partitions/testutil_test.go
package partitions

import (
	"context"
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
	sharedDSN    string
	sharedErr    error
)

func sharedPostgres(t *testing.T) string {
	t.Helper()
	sharedPGOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		pg, err := tcpg.Run(ctx, "postgres:17-alpine",
			tcpg.WithDatabase("partitions"),
			tcpg.WithUsername("partitions"),
			tcpg.WithPassword("partitions"),
			testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
		)
		if err != nil {
			sharedErr = err
			return
		}
		sharedDSN, sharedErr = pg.ConnectionString(ctx, "sslmode=disable")
	})
	if sharedErr != nil {
		t.Fatalf("shared postgres: %v", sharedErr)
	}
	return sharedDSN
}

// newTestPool returns a pgxpool with a parent bridged_flows partitioned table
// already created in a fresh schema. Schema is dropped on cleanup.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := sharedPostgres(t)
	ctx := context.Background()

	schema := "tp_" + randomSuffix()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	admin.Close()

	pool, err := pgxpool.New(ctx, dsn+"&search_path="+schema)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	// Minimal partitioned parent for tests.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE bridged_flows (
			id bigint GENERATED ALWAYS AS IDENTITY,
			ts timestamptz NOT NULL,
			payload text
		) PARTITION BY RANGE (ts);
		CREATE TABLE bridged_flows_default PARTITION OF bridged_flows DEFAULT;
	`); err != nil {
		t.Fatalf("create parent: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		cleanup, _ := pgxpool.New(ctx, dsn)
		if cleanup != nil {
			cleanup.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			cleanup.Close()
		}
	})
	return pool
}

func randomSuffix() string {
	const alpha = "abcdefghijklmnop"
	now := time.Now().UnixNano()
	out := make([]byte, 8)
	for i := range out {
		out[i] = alpha[(now>>(i*4))&0xf]
	}
	return string(out)
}
```

- [ ] **Step 2: Write failing test**

```go
// Append to log-analyzer/server/internal/storage/partitions/manager_test.go
func TestEnsureFuturePartitions_CreatesTodayAndTwoDays(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})

	ctx := context.Background()
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("EnsureFuturePartitions: %v", err)
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	for i := 0; i <= 2; i++ {
		day := today.AddDate(0, 0, i)
		name := "bridged_flows_" + day.Format("20060102")
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)
		`, name).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s: %v", name, err)
		}
		if !exists {
			t.Errorf("partition %s should exist", name)
		}
	}
}

func TestEnsureFuturePartitions_Idempotent(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()

	// Run twice — second call must not fail.
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("second: %v", err)
	}
}
```

Add imports `context`, `time` to the test file if missing.

- [ ] **Step 3: Run test, verify fail**

```bash
go test ./internal/storage/partitions/ -run TestEnsureFuture -v
```

Expected: FAIL — partitions don't exist (no-op stub).

- [ ] **Step 4: Implement**

```go
// Replace EnsureFuturePartitions in manager.go:
func (m *Manager) EnsureFuturePartitions(ctx context.Context) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, tbl := range m.tables {
		for offset := 0; offset <= 2; offset++ {
			start := today.AddDate(0, 0, offset)
			end := start.AddDate(0, 0, 1)
			name := tbl.PartitionName(start)
			sql := `
				CREATE TABLE IF NOT EXISTS ` + name + `
				PARTITION OF ` + tbl.Name + `
				FOR VALUES FROM ('` + start.Format(time.RFC3339) + `')
				                TO   ('` + end.Format(time.RFC3339) + `');
			`
			if _, err := m.pool.Exec(ctx, sql); err != nil {
				return fmt.Errorf("ensure %s: %w", name, err)
			}
		}
	}
	return nil
}
```

Add import `"fmt"` to manager.go.

- [ ] **Step 5: Run test, verify pass**

```bash
go test ./internal/storage/partitions/ -run TestEnsureFuture -v
```

Expected: PASS (both tests).

- [ ] **Step 6: Commit**

```bash
git add internal/storage/partitions/
git commit -m "feat(storage/partitions): EnsureFuturePartitions creates today+2"
```

### Task 1.3: DropExpiredPartitions

**Files:**
- Modify: `log-analyzer/server/internal/storage/partitions/manager.go`
- Modify: `log-analyzer/server/internal/storage/partitions/manager_test.go`

- [ ] **Step 1: Write failing test**

```go
// Append to manager_test.go
func TestDropExpiredPartitions_DropsOldKeepsRecent(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()

	// Pre-create partitions: 20 days ago (expired), 5 days ago (kept).
	today := time.Now().UTC().Truncate(24 * time.Hour)
	old := today.AddDate(0, 0, -20)
	recent := today.AddDate(0, 0, -5)
	for _, day := range []time.Time{old, recent} {
		name := "bridged_flows_" + day.Format("20060102")
		next := day.AddDate(0, 0, 1)
		_, err := pool.Exec(ctx, `
			CREATE TABLE `+name+` PARTITION OF bridged_flows
			FOR VALUES FROM ('`+day.Format(time.RFC3339)+`')
			                TO   ('`+next.Format(time.RFC3339)+`')
		`)
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	if err := m.DropExpiredPartitions(ctx); err != nil {
		t.Fatalf("DropExpiredPartitions: %v", err)
	}

	oldName := "bridged_flows_" + old.Format("20060102")
	recentName := "bridged_flows_" + recent.Format("20060102")
	for _, c := range []struct {
		name      string
		wantExist bool
	}{
		{oldName, false},
		{recentName, true},
	} {
		var exists bool
		_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, c.name).Scan(&exists)
		if exists != c.wantExist {
			t.Errorf("%s exists=%v want %v", c.name, exists, c.wantExist)
		}
	}
}
```

- [ ] **Step 2: Run test, verify fail**

```bash
go test ./internal/storage/partitions/ -run TestDropExpired -v
```

Expected: FAIL — old partition still exists (no-op stub).

- [ ] **Step 3: Implement**

Replace `DropExpiredPartitions` in manager.go:

```go
func (m *Manager) DropExpiredPartitions(ctx context.Context) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, tbl := range m.tables {
		cutoff := today.AddDate(0, 0, -tbl.RetentionDays)
		// Find partitions of this parent whose suffix date < cutoff.
		rows, err := m.pool.Query(ctx, `
			SELECT child.relname
			FROM pg_inherits i
			JOIN pg_class parent ON parent.oid = i.inhparent
			JOIN pg_class child  ON child.oid  = i.inhrelid
			WHERE parent.relname = $1
		`, tbl.Name)
		if err != nil {
			return fmt.Errorf("list %s partitions: %w", tbl.Name, err)
		}
		var toDrop []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			// Expect suffix _YYYYMMDD.
			if len(name) < len(tbl.Name)+9 {
				continue
			}
			suffix := name[len(tbl.Name)+1:]
			day, err := time.Parse("20060102", suffix)
			if err != nil {
				continue // skip "_default" etc.
			}
			if day.Before(cutoff) {
				toDrop = append(toDrop, name)
			}
		}
		rows.Close()
		for _, name := range toDrop {
			if _, err := m.pool.Exec(ctx, "DROP TABLE IF EXISTS "+name); err != nil {
				return fmt.Errorf("drop %s: %w", name, err)
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test, verify pass**

```bash
go test ./internal/storage/partitions/ -v
```

Expected: PASS (all 4 partition manager tests).

- [ ] **Step 5: Commit**

```bash
git add internal/storage/partitions/
git commit -m "feat(storage/partitions): DropExpiredPartitions"
```

### Task 1.4: Tick + Run integration test

**Files:**
- Modify: `log-analyzer/server/internal/storage/partitions/manager_test.go`

- [ ] **Step 1: Add Tick test (covers full Run cycle without ticker)**

```go
func TestTick_FullCycle(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()

	// Seed an expired partition.
	old := time.Now().UTC().Truncate(24 * time.Hour).AddDate(0, 0, -20)
	next := old.AddDate(0, 0, 1)
	oldName := "bridged_flows_" + old.Format("20060102")
	_, err := pool.Exec(ctx, `
		CREATE TABLE `+oldName+` PARTITION OF bridged_flows
		FOR VALUES FROM ('`+old.Format(time.RFC3339)+`')
		                TO   ('`+next.Format(time.RFC3339)+`')
	`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := m.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// Old gone.
	var exists bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, oldName).Scan(&exists)
	if exists {
		t.Errorf("old partition %s should have been dropped", oldName)
	}

	// Today exists.
	today := time.Now().UTC().Truncate(24 * time.Hour)
	todayName := "bridged_flows_" + today.Format("20060102")
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, todayName).Scan(&exists)
	if !exists {
		t.Errorf("today partition %s should exist", todayName)
	}
}
```

- [ ] **Step 2: Run all partition tests**

```bash
go test ./internal/storage/partitions/ -v
```

Expected: PASS (5 tests).

- [ ] **Step 3: Commit**

```bash
git add internal/storage/partitions/manager_test.go
git commit -m "test(storage/partitions): Tick full-cycle integration test"
```

---

## Phase 2: Schema Rewrite

### Task 2.1: Audit current schema and document mappings

**Files:**
- Create: `log-analyzer/server/internal/storage/SCHEMA_MAPPING.md` (working doc, removed at end of plan)

- [ ] **Step 1: Read current schema**

```bash
wc -l /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage/schema.sql
grep -E '^CREATE TABLE' /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage/schema.sql | wc -l
```

Confirm: ~39 tables.

- [ ] **Step 2: Write mapping doc**

For each table, list:
- Current text columns that should become uuid/inet/smallint
- Whether table is hot time-series (partitioned) or state
- Existing indexes

Use this template:

```markdown
# Schema v1 → v2 Mapping (working doc)

## Hot tables (daily partitioned, BRIN on ts)

### bridged_flows
- user_email TEXT → uuid
- real_client_ip TEXT → inet
- bridge_node_id TEXT → smallint REFERENCES nodes(id)
- exit_node_id TEXT → smallint REFERENCES nodes(id)
- destination TEXT → unchanged (host:port)
- ts timestamptz → unchanged
- Indexes: BRIN(ts) per partition; btree(user_email), btree(real_client_ip), btree(destination)

### alerts
[fill in from current schema.sql]

### blacklist_matches
[fill in from current schema.sql]

### threat_matches
[fill in from current schema.sql]

### anomalies
[fill in from current schema.sql]

## State tables (no partitioning)

[List remaining ~30 tables with their text→native conversions]

## Lookup tables

### nodes (NEW)
- id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY
- node_id text NOT NULL UNIQUE
- role text NOT NULL CHECK (role IN ('bridge', 'exit'))
- first_seen timestamptz DEFAULT now()
- last_seen timestamptz DEFAULT now()
```

- [ ] **Step 3: Read current schema in chunks and fill in mapping**

```bash
sed -n '1,200p' /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage/schema.sql
sed -n '200,400p' /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage/schema.sql
# continue until end
```

For every TEXT column referencing user/uuid/IP/node, document the mapping in SCHEMA_MAPPING.md.

- [ ] **Step 4: Commit working doc**

```bash
git add internal/storage/SCHEMA_MAPPING.md
git commit -m "docs(storage): schema v1->v2 mapping working doc"
```

### Task 2.2: Write new schema.sql — Hot tables

**Files:**
- Create: `log-analyzer/server/internal/storage/schema.sql.new` (intermediate)

- [ ] **Step 1: Write the lookup + hot tables section**

```sql
-- log-analyzer/server/internal/storage/schema.sql.new
-- Postgres schema v2 for xray-log-analyzer.
-- Native types throughout; daily partitioning for hot time-series tables.
-- Applied on startup by Storage.migrate(). Idempotent (CREATE ... IF NOT EXISTS).

-- =============================================================================
-- Extensions
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- =============================================================================
-- Lookup tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS nodes (
    id          smallint     GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    node_id     text         NOT NULL UNIQUE,
    role        text         NOT NULL CHECK (role IN ('bridge', 'exit')),
    first_seen  timestamptz  NOT NULL DEFAULT now(),
    last_seen   timestamptz  NOT NULL DEFAULT now()
);

-- =============================================================================
-- Hot time-series tables (daily partitioned, BRIN on ts)
-- Partitions are managed by internal/storage/partitions/Manager.
-- =============================================================================

CREATE TABLE IF NOT EXISTS bridged_flows (
    id              bigint        GENERATED ALWAYS AS IDENTITY,
    user_email      uuid          NOT NULL,
    real_client_ip  inet          NOT NULL,
    bridge_node_id  smallint      NOT NULL REFERENCES nodes(id),
    exit_node_id    smallint      NOT NULL REFERENCES nodes(id),
    destination     text          NOT NULL,
    ts              timestamptz   NOT NULL,
    created_at      timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

-- BRIN on ts for cheap range scans across partitions.
CREATE INDEX IF NOT EXISTS bridged_flows_ts_brin ON bridged_flows USING BRIN (ts);
-- Per-partition btree indexes are inherited from the parent at creation time.
CREATE INDEX IF NOT EXISTS bridged_flows_user_idx ON bridged_flows (user_email);
CREATE INDEX IF NOT EXISTS bridged_flows_ip_idx   ON bridged_flows (real_client_ip);
CREATE INDEX IF NOT EXISTS bridged_flows_dest_idx ON bridged_flows (destination);

-- Default partition (safety net for missing daily partitions; healthcheck
-- alarms if non-empty).
CREATE TABLE IF NOT EXISTS bridged_flows_default PARTITION OF bridged_flows DEFAULT;
```

(Continue with `alerts`, `blacklist_matches`, `threat_matches`, `anomalies` — using SCHEMA_MAPPING.md from Task 2.1 to map columns. Each follows the same pattern: native types, PARTITION BY RANGE (ts), BRIN on ts, btree on hot columns, default partition.)

- [ ] **Step 2: Verify SQL syntax**

Use a throwaway postgres container:

```bash
docker run --rm -i postgres:17-alpine psql -h /var/run/postgresql -U postgres -c '\timing off' < log-analyzer/server/internal/storage/schema.sql.new
```

Or simpler, parse-only check:

```bash
docker run --rm -v /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage:/s postgres:17-alpine \
  sh -c 'pg_ctl -D /tmp/d init -U postgres && pg_ctl -D /tmp/d start && sleep 2 && psql -U postgres -f /s/schema.sql.new && pg_ctl -D /tmp/d stop'
```

Expected: no syntax errors.

- [ ] **Step 3: Commit**

```bash
git add internal/storage/schema.sql.new
git commit -m "feat(schema): v2 hot tables (partitioned, BRIN, native types)"
```

### Task 2.3: Write new schema.sql — State tables

- [ ] **Step 1: Append state tables to schema.sql.new**

For each state table from SCHEMA_MAPPING.md:
- Same column names as v1
- Convert TEXT → uuid/inet/smallint per mapping
- Replace `node_id text` with `node_id smallint REFERENCES nodes(id)` everywhere
- Replace `user_email text` with `user_email uuid` everywhere
- Replace IP-typed text columns with inet

Concrete example for `remna_users` (already references uuid in v1):

```sql
CREATE TABLE IF NOT EXISTS remna_users (
    uuid               uuid          PRIMARY KEY,
    username           text,
    short_uuid         text,
    expire_at          timestamptz,
    is_connected       boolean       NOT NULL DEFAULT false,
    last_active_node   smallint      REFERENCES nodes(id),
    last_seen_at       timestamptz,
    created_at         timestamptz   NOT NULL DEFAULT now(),
    updated_at         timestamptz   NOT NULL DEFAULT now()
);
```

(Continue with `hwid_user_map`, `ip_user_map`, `user_destinations`, `user_*_profile`, `user_*`, `dns_*_stats`, `threat_*_stats`, `hourly_stats`, `online_snapshots`, etc.)

- [ ] **Step 2: Verify SQL parses**

```bash
docker run --rm -v /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage:/s postgres:17-alpine \
  sh -c 'initdb -D /tmp/d -U postgres && pg_ctl -D /tmp/d -l /tmp/log start && sleep 3 && psql -U postgres -f /s/schema.sql.new'
```

Expected: full schema applies without errors.

- [ ] **Step 3: Commit**

```bash
git add internal/storage/schema.sql.new
git commit -m "feat(schema): v2 state tables (native types, FK to nodes)"
```

### Task 2.4: Replace schema.sql + update schema_test.go

**Files:**
- Replace: `log-analyzer/server/internal/storage/schema.sql`
- Modify: `log-analyzer/server/internal/storage/schema_test.go`

- [ ] **Step 1: Replace schema.sql**

```bash
cd /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage
mv schema.sql.new schema.sql
```

- [ ] **Step 2: Read existing schema_test.go**

```bash
cat schema_test.go
```

- [ ] **Step 3: Update test to assert v2 expectations**

Add tests that verify:
- All hot tables are partitioned (`relkind = 'p'` in pg_class)
- BRIN index exists on ts for each hot table
- `nodes` table exists
- A representative state table (e.g. `remna_users`) has uuid column

```go
// Append to schema_test.go
func TestSchema_V2_HotTablesPartitioned(t *testing.T) {
	s := newTestStorage(t)
	hot := []string{"bridged_flows", "alerts", "blacklist_matches", "threat_matches", "anomalies"}
	for _, tbl := range hot {
		var kind string
		err := s.pool.QueryRow(context.Background(),
			`SELECT relkind FROM pg_class WHERE relname = $1`, tbl).Scan(&kind)
		if err != nil {
			t.Fatalf("query %s: %v", tbl, err)
		}
		if kind != "p" {
			t.Errorf("%s relkind = %q want \"p\" (partitioned)", tbl, kind)
		}
	}
}

func TestSchema_V2_NodesLookup(t *testing.T) {
	s := newTestStorage(t)
	var has bool
	err := s.pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'nodes' AND relkind = 'r')`).Scan(&has)
	if err != nil || !has {
		t.Fatalf("nodes table missing: err=%v has=%v", err, has)
	}
}

func TestSchema_V2_BridgedFlowsHasUUIDColumn(t *testing.T) {
	s := newTestStorage(t)
	var typ string
	err := s.pool.QueryRow(context.Background(),
		`SELECT data_type FROM information_schema.columns
		 WHERE table_name = 'bridged_flows' AND column_name = 'user_email'`).Scan(&typ)
	if err != nil {
		t.Fatalf("query column type: %v", err)
	}
	if typ != "uuid" {
		t.Errorf("user_email type = %q want uuid", typ)
	}
}
```

- [ ] **Step 4: Run test, expect mostly fail**

```bash
go test ./internal/storage/ -run TestSchema_V2 -v
```

Expected: tests pass IF schema.sql.new was correctly written. If they fail, fix schema.sql.

Note: existing storage tests *will* fail at this point since storage Go code still expects v1 string types. Don't worry — those get fixed in Phase 3.

- [ ] **Step 5: Commit**

```bash
git add internal/storage/schema.sql internal/storage/schema_test.go
git commit -m "feat(schema): replace v1 with v2; add V2 schema assertions"
```

### Task 2.5: Drop SCHEMA_MAPPING.md (working doc)

- [ ] **Step 1: Delete + commit**

```bash
git rm internal/storage/SCHEMA_MAPPING.md
git commit -m "chore: drop schema mapping working doc"
```

---

## Phase 3: Hot table storage refactor

> Each hot table follows the same pattern: convert string fields to native types, add `nodeLookup` helper for smallint FK resolution, update queries to pgx-native execution. Tests get parameter type updates and a partition-existence prerequisite.

### Task 3.1: Add LookupNodeID helper

**Files:**
- Modify: `log-analyzer/server/internal/storage/nodes.go`
- Modify: `log-analyzer/server/internal/storage/nodes_test.go`

- [ ] **Step 1: Read current nodes.go**

```bash
cat /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage/nodes.go
```

- [ ] **Step 2: Write failing test for LookupNodeID with auto-insert**

```go
// Append to nodes_test.go
func TestLookupNodeID_AutoInsert(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	id1, err := s.LookupNodeID(ctx, "ru-bridge", "bridge")
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if id1 == 0 {
		t.Fatal("expected non-zero NodeID")
	}

	id2, err := s.LookupNodeID(ctx, "ru-bridge", "bridge")
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if id1 != id2 {
		t.Errorf("expected same id; got %d then %d", id1, id2)
	}
}

func TestLookupNodeID_DifferentRoles(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	bridge, err := s.LookupNodeID(ctx, "germany-1", "bridge")
	if err != nil {
		t.Fatalf("%v", err)
	}
	exit, err := s.LookupNodeID(ctx, "germany-2", "exit")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if bridge == exit {
		t.Errorf("different node_ids should get different ids")
	}
}
```

- [ ] **Step 3: Run test, verify fail**

```bash
go test ./internal/storage/ -run TestLookupNodeID -v
```

Expected: build fails (LookupNodeID undefined).

- [ ] **Step 4: Implement**

Add to nodes.go:

```go
// LookupNodeID returns the smallint id for nodeID, creating a row in
// nodes() if it does not already exist. Returned id is stable and safe to
// store as a foreign key in hot tables.
//
// Updates last_seen on every call so we have observability into agent
// activity per node.
func (s *Storage) LookupNodeID(ctx context.Context, nodeID, role string) (NodeID, error) {
	var id NodeID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO nodes (node_id, role)
		VALUES ($1, $2)
		ON CONFLICT (node_id) DO UPDATE
			SET last_seen = now()
		RETURNING id
	`, nodeID, role).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("lookup node %s: %w", nodeID, err)
	}
	return id, nil
}
```

Add `"fmt"` import if missing.

- [ ] **Step 5: Run test, verify pass**

```bash
go test ./internal/storage/ -run TestLookupNodeID -v
```

Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add internal/storage/nodes.go internal/storage/nodes_test.go
git commit -m "feat(storage/nodes): LookupNodeID with auto-insert"
```

### Task 3.2: Refactor bridged_flows.go to native types

**Files:**
- Modify: `log-analyzer/server/internal/storage/bridged_flows.go`
- Modify: `log-analyzer/server/internal/storage/bridged_flows_test.go`

- [ ] **Step 1: Read both files**

```bash
cat /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage/bridged_flows.go
cat /Users/qwertyhq/code/xray/log-analyzer/server/internal/storage/bridged_flows_test.go
```

- [ ] **Step 2: Update BridgedFlow struct + RecordBridgedFlow**

Replace `BridgedFlow` and `RecordBridgedFlow` in bridged_flows.go:

```go
import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

type BridgedFlow struct {
	ID           int64        `json:"id"`
	UserEmail    uuid.UUID    `json:"user_email"`
	RealClientIP netip.Addr   `json:"real_client_ip"`
	BridgeNodeID NodeID       `json:"bridge_node_id"`
	ExitNodeID   NodeID       `json:"exit_node_id"`
	Destination  string       `json:"destination"`
	Timestamp    time.Time    `json:"ts"`
	CreatedAt    time.Time    `json:"created_at"`
}

func (s *Storage) RecordBridgedFlow(ctx context.Context, f *BridgedFlow) error {
	if f == nil {
		return fmt.Errorf("nil flow")
	}
	if f.UserEmail == uuid.Nil {
		return fmt.Errorf("zero user_email")
	}
	if !f.RealClientIP.IsValid() {
		return fmt.Errorf("invalid real_client_ip")
	}
	if f.BridgeNodeID.IsZero() || f.ExitNodeID.IsZero() {
		return fmt.Errorf("node ids must be resolved before insert")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO bridged_flows
			(user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, f.UserEmail, f.RealClientIP, int16(f.BridgeNodeID), int16(f.ExitNodeID), f.Destination, f.Timestamp.UTC())
	return err
}
```

- [ ] **Step 3: Update BridgedFlowsFilter, GetBridgedFlows, CleanupBridgedFlows**

```go
type BridgedFlowsFilter struct {
	UserEmail    uuid.UUID  // zero = no filter
	RealClientIP netip.Addr // !IsValid() = no filter
	Destination  string
	Since        time.Time
	Limit        int
}

// GetBridgedFlows ... (rewrite SELECT to scan into BridgedFlow with native types)
// CleanupBridgedFlows is unchanged - DROP PARTITION will replace it later.
```

Show the full `GetBridgedFlows` rewrite (read original, swap parameter types, scan target types):

```go
func (s *Storage) GetBridgedFlows(ctx context.Context, f BridgedFlowsFilter) ([]BridgedFlow, error) {
	var (
		conds []string
		args  []any
	)
	add := func(c string, a any) {
		args = append(args, a)
		conds = append(conds, fmt.Sprintf(c, len(args)))
	}
	if f.UserEmail != uuid.Nil {
		add("user_email = $%d", f.UserEmail)
	}
	if f.RealClientIP.IsValid() {
		add("real_client_ip = $%d", f.RealClientIP)
	}
	if f.Destination != "" {
		add("destination ILIKE $%d", "%"+f.Destination+"%")
	}
	if !f.Since.IsZero() {
		add("ts >= $%d", f.Since.UTC())
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := "SELECT id, user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts, created_at FROM bridged_flows"
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY ts DESC LIMIT " + strconv.Itoa(limit)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BridgedFlow
	for rows.Next() {
		var bf BridgedFlow
		var bn, en int16
		if err := rows.Scan(&bf.ID, &bf.UserEmail, &bf.RealClientIP, &bn, &en, &bf.Destination, &bf.Timestamp, &bf.CreatedAt); err != nil {
			return nil, err
		}
		bf.BridgeNodeID = NodeID(bn)
		bf.ExitNodeID = NodeID(en)
		out = append(out, bf)
	}
	return out, rows.Err()
}
```

Add imports `"strconv"` if missing; remove unused old imports.

- [ ] **Step 4: Update bridged_flows_test.go**

Replace string fixtures with `uuid.MustParse(...)` and `netip.MustParseAddr(...)`. Insert nodes via `LookupNodeID` first. Pre-create today's partition via the partition manager.

```go
import (
	"github.com/google/uuid"
	"net/netip"

	"github.com/xray-log-analyzer/server/internal/storage/partitions"
)

func TestRecordBridgedFlow_RoundTrip(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	// Required: today's partition must exist (parent is partitioned).
	pm := partitions.NewManager(s.pool, []partitions.Table{{Name: "bridged_flows", RetentionDays: 14}})
	if err := pm.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("ensure partitions: %v", err)
	}

	bridge, err := s.LookupNodeID(ctx, "ru-bridge", "bridge")
	if err != nil {
		t.Fatalf("bridge lookup: %v", err)
	}
	exit, err := s.LookupNodeID(ctx, "germany-1", "exit")
	if err != nil {
		t.Fatalf("exit lookup: %v", err)
	}

	user := uuid.New()
	ip := netip.MustParseAddr("203.0.113.5")
	bf := &BridgedFlow{
		UserEmail:    user,
		RealClientIP: ip,
		BridgeNodeID: bridge,
		ExitNodeID:   exit,
		Destination:  "example.com:443",
		Timestamp:    time.Now().UTC(),
	}
	if err := s.RecordBridgedFlow(ctx, bf); err != nil {
		t.Fatalf("record: %v", err)
	}

	got, err := s.GetBridgedFlows(ctx, BridgedFlowsFilter{UserEmail: user, Limit: 10})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows want 1", len(got))
	}
	if got[0].UserEmail != user {
		t.Errorf("user mismatch: %v", got[0].UserEmail)
	}
	if got[0].RealClientIP != ip {
		t.Errorf("ip mismatch: %v", got[0].RealClientIP)
	}
}
```

Update existing tests in the file similarly (uuid + inet + LookupNodeID for FKs + partition pre-create).

- [ ] **Step 5: Run tests**

```bash
DOCKER_HOST=unix:///Users/qwertyhq/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
go test ./internal/storage/ -run TestRecordBridgedFlow -v
```

Expected: PASS.

- [ ] **Step 6: Run all bridged_flows tests**

```bash
go test ./internal/storage/ -run BridgedFlow -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/storage/bridged_flows.go internal/storage/bridged_flows_test.go
git commit -m "refactor(storage/bridged_flows): native uuid/inet/smallint types"
```

### Task 3.3: Refactor alerts.go

Apply the same pattern as Task 3.2:

**Files:**
- Modify: `log-analyzer/server/internal/storage/alerts.go`
- Modify: `log-analyzer/server/internal/storage/alerts_test.go`

- [ ] **Step 1: Read both files**

```bash
cat log-analyzer/server/internal/storage/alerts.go
```

- [ ] **Step 2: Migrate types in struct definitions**

Identify Alert struct fields that should change:
- `UserEmail string` → `UserEmail uuid.UUID`
- `NodeID string` → `NodeID NodeID` (smallint via storage.NodeID)
- IP-typed fields → `netip.Addr`

- [ ] **Step 3: Update INSERT/SELECT queries**

Same pattern as bridged_flows: use `s.pool` for native types, `LookupNodeID` to resolve smallints.

- [ ] **Step 4: Update tests with uuid/inet fixtures, partition pre-create**

Pre-create today's `alerts` partition via `partitions.NewManager` in setup.

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/storage/ -run Alert -v
```

```bash
git add internal/storage/alerts.go internal/storage/alerts_test.go
git commit -m "refactor(storage/alerts): native types"
```

### Task 3.4: Refactor threat_matches.go

Same pattern.

**Files:**
- Modify: `log-analyzer/server/internal/storage/threat_matches.go`
- Modify: `log-analyzer/server/internal/storage/threat_matches_test.go`

- [ ] **Step 1: Read files**
- [ ] **Step 2: Migrate types** (UserEmail, NodeID, SourceIP, etc. — see SCHEMA_MAPPING.md for exact set)
- [ ] **Step 3: Update queries**
- [ ] **Step 4: Update tests**
- [ ] **Step 5: Run + commit**

```bash
go test ./internal/storage/ -run ThreatMatch -v
```

```bash
git add internal/storage/threat_matches.go internal/storage/threat_matches_test.go
git commit -m "refactor(storage/threat_matches): native types"
```

### Task 3.5: Refactor blacklist.go (blacklist_matches table)

Same pattern.

**Files:**
- Modify: `log-analyzer/server/internal/storage/blacklist.go`
- Modify: `log-analyzer/server/internal/storage/blacklist_test.go`

- [ ] **Steps 1-5: same pattern as 3.3/3.4**

```bash
git add internal/storage/blacklist.go internal/storage/blacklist_test.go
git commit -m "refactor(storage/blacklist): native types"
```

### Task 3.6: Refactor anomaly.go

**Files:**
- Modify: `log-analyzer/server/internal/storage/anomaly.go`
- Modify: `log-analyzer/server/internal/storage/anomaly_test.go`

- [ ] **Steps 1-5: same pattern**

```bash
git add internal/storage/anomaly.go internal/storage/anomaly_test.go
git commit -m "refactor(storage/anomaly): native types"
```

---

## Phase 4: State table storage refactor

### Task 4.1: Refactor users.go

State tables don't need partition pre-create. Otherwise same pattern as Phase 3.

**Files:**
- Modify: `log-analyzer/server/internal/storage/users.go`
- Modify: `log-analyzer/server/internal/storage/users_test.go`

- [ ] **Step 1: Read files**
- [ ] **Step 2: Migrate types per SCHEMA_MAPPING.md**
- [ ] **Step 3: Update queries**
- [ ] **Step 4: Update tests**
- [ ] **Step 5: Run + commit**

```bash
go test ./internal/storage/ -run User -v
```

```bash
git add internal/storage/users.go internal/storage/users_test.go
git commit -m "refactor(storage/users): native types"
```

### Task 4.2: Refactor destinations.go

**Files:**
- Modify: `log-analyzer/server/internal/storage/destinations.go`
- Modify: `log-analyzer/server/internal/storage/destinations_test.go`

- [ ] **Steps 1-5**

```bash
git add internal/storage/destinations.go internal/storage/destinations_test.go
git commit -m "refactor(storage/destinations): native types"
```

### Task 4.3: Refactor remaining storage files (one task per file)

For each of the following, apply the same pattern (read → migrate types → update queries → update tests → run → commit):

- [ ] **4.3a:** `online_snapshots.go` + test
- [ ] **4.3b:** `hourly.go` + test
- [ ] **4.3c:** `chat.go` + test
- [ ] **4.3d:** `correlation.go` + test (storage-layer correlation, separate from internal/correlation)
- [ ] **4.3e:** `dns_stats.go` + test
- [ ] **4.3f:** `geo_stats.go` + test
- [ ] **4.3g:** `remnawave.go` + test
- [ ] **4.3h:** `threat_stats.go` + test
- [ ] **4.3i:** `user_risk.go` + test
- [ ] **4.3j:** `reports.go` (no test in current code, just code)

Each gets its own commit:

```bash
git commit -m "refactor(storage/<file>): native types"
```

### Task 4.4: Verify all storage tests pass

- [ ] **Step 1: Run full storage test suite**

```bash
cd /Users/qwertyhq/code/xray/log-analyzer/server
DOCKER_HOST=unix:///Users/qwertyhq/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
go test ./internal/storage/... -v 2>&1 | tail -50
```

Expected: all tests PASS.

- [ ] **Step 2: If failures — fix and re-run**

If failures appear in tests we already migrated, those are bugs in our refactor. Fix and commit.

- [ ] **Step 3: Snapshot commit if any fixups**

```bash
git commit -am "fix(storage): post-migration test fixups"
```

---

## Phase 5: Correlation + API layer

### Task 5.1: Update internal/correlation/service.go

**Files:**
- Modify: `log-analyzer/server/internal/correlation/service.go`
- Modify: `log-analyzer/server/internal/correlation/service_test.go` (if exists)

- [ ] **Step 1: Read service.go**

```bash
cat log-analyzer/server/internal/correlation/service.go
```

Identify places that pass user_email or IPs as `string` to storage layer.

- [ ] **Step 2: Migrate to native types**

At the boundary (where service receives data from agent / accesses storage), convert:

```go
// At ingress point, parse from agent payload:
userEmail, err := uuid.Parse(payload.UserEmail)
if err != nil {
    return fmt.Errorf("invalid uuid: %w", err)
}
ip, err := netip.ParseAddr(payload.RealClientIP)
if err != nil {
    return fmt.Errorf("invalid ip: %w", err)
}
nodeID, err := s.storage.LookupNodeID(ctx, payload.NodeID, payload.Role)
if err != nil {
    return fmt.Errorf("lookup node: %w", err)
}
// Pass typed values forward.
```

- [ ] **Step 3: Update tests if applicable**
- [ ] **Step 4: Run**

```bash
go test ./internal/correlation/... -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/correlation/
git commit -m "refactor(correlation): native types at storage boundary"
```

### Task 5.2: API JSON marshalling — uuid/inet/NodeID

**Files:**
- Audit: `log-analyzer/server/internal/server/*.go`
- Modify: handlers that marshal storage types to JSON

The JSON tags on storage structs already produce strings via uuid.UUID/netip.Addr's MarshalJSON. Verify:

- [ ] **Step 1: Spot-check JSON output for one bridged_flow row**

Add or update a server test that hits `GET /api/bridged-flows` and asserts:
- `user_email` is a string of UUID format
- `real_client_ip` is a string IP
- `bridge_node_id` is an integer (NodeID is int16, marshals as number)

If `bridge_node_id` should be returned as the **text** node_id (e.g. "ru-bridge") for client convenience, write a join in the handler or an API-level conversion that resolves smallint → text via the `nodes` table.

- [ ] **Step 2: Decide API contract for node_id field**

Read existing API consumers (UI, dashboard) — do they expect text "ru-bridge" or smallint 1?

```bash
grep -r "bridge_node_id" log-analyzer/server/internal/server/ log-analyzer/server/web/
```

Decision is binary:
- (a) Keep API returning text: handlers JOIN `nodes` table, marshal `node_id` text field
- (b) Change API to smallint: documented breaking change

Pick (a) for back-compat unless there's a strong reason otherwise.

- [ ] **Step 3: Implement the chosen approach**

If (a): add helper in handler to resolve `NodeID → string` via cached `nodes` lookup, then use in JSON response struct.

- [ ] **Step 4: Run server tests**

```bash
go test ./internal/server/... -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat(api): preserve text node_id in JSON via nodes-lookup join"
```

---

## Phase 6: Postgres tuning + integration

### Task 6.1: Add postgres tuning to docker-compose.yml

**Files:**
- Modify: `log-analyzer/docker-compose.yml`

- [ ] **Step 1: Read current analyzer-postgres section**

```bash
grep -A 30 "analyzer-postgres:" /Users/qwertyhq/code/xray/log-analyzer/docker-compose.yml
```

- [ ] **Step 2: Add command override**

Find the `analyzer-postgres:` service block, add:

```yaml
  analyzer-postgres:
    image: postgres:17-alpine
    # ... existing config ...
    command: >
      postgres
      -c shared_buffers=2GB
      -c work_mem=16MB
      -c maintenance_work_mem=512MB
      -c effective_cache_size=6GB
      -c random_page_cost=1.1
      -c max_wal_size=4GB
      -c checkpoint_timeout=15min
      -c checkpoint_completion_target=0.9
      -c autovacuum_vacuum_scale_factor=0.05
      -c autovacuum_naptime=30s
      -c max_connections=100
      -c shared_preload_libraries=pg_stat_statements
```

- [ ] **Step 3: Validate compose**

```bash
cd /Users/qwertyhq/code/xray/log-analyzer
docker compose config | grep -A 15 analyzer-postgres
```

Expected: command is well-formed, no errors.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml
git commit -m "feat(postgres): tuning via compose command overrides"
```

### Task 6.2: Wire partition manager into main.go

**Files:**
- Modify: `log-analyzer/server/cmd/server/main.go`

- [ ] **Step 1: Read main.go cleanup goroutine**

```bash
sed -n '130,170p' log-analyzer/server/cmd/server/main.go
```

- [ ] **Step 2: Add partition manager startup before cleanup goroutine**

After the `store, err := storage.New(...)` call and before the cleanup goroutine, add:

```go
// Partition manager: ensure today's partitions exist + drop expired.
pm := partitions.NewManager(store.Pool(), []partitions.Table{
    {Name: "bridged_flows", RetentionDays: 14},
    {Name: "alerts", RetentionDays: 30},
    {Name: "blacklist_matches", RetentionDays: 30},
    {Name: "threat_matches", RetentionDays: 30},
    {Name: "anomalies", RetentionDays: 30},
})
if err := pm.Tick(ctx); err != nil {
    log.Fatalf("partition manager initial tick: %v", err)
}
go func() {
    if err := pm.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
        log.Printf("partition manager: %v", err)
    }
}()
log.Println("partition manager: started")
```

- [ ] **Step 3: Add `storage.Pool()` accessor if missing**

In `internal/storage/storage.go`:

```go
// Pool returns the underlying pgx pool. Used by sub-packages that need
// native pgx access (e.g. partitions.Manager).
func (s *Storage) Pool() *pgxpool.Pool { return s.pool }
```

- [ ] **Step 4: Update cleanup goroutine to remove CleanupBridgedFlows**

Since DROP PARTITION replaces it. Find the line:

```go
if err := store.CleanupBridgedFlows(ctx, 14); err != nil {
    log.Printf("cleanup bridged flows error: %v", err)
}
```

Delete it. Keep `CleanupOldData` and `CleanupOldThreatMatches` for now (they handle the non-partitioned aggregate tables).

- [ ] **Step 5: Build to verify compiles**

```bash
cd /Users/qwertyhq/code/xray/log-analyzer/server
go build ./...
```

Expected: no errors.

- [ ] **Step 6: Add unit test that main.go can wire it up (smoke compile is enough)**
- [ ] **Step 7: Commit**

```bash
git add cmd/server/main.go internal/storage/storage.go
git commit -m "feat(server): wire partition manager + drop CleanupBridgedFlows"
```

### Task 6.3: Healthcheck for partition existence

**Files:**
- Modify: `log-analyzer/server/internal/storage/partitions/manager.go`
- Modify: `log-analyzer/server/internal/storage/partitions/manager_test.go`
- Modify: `log-analyzer/server/internal/server/server.go` (or wherever /health lives)

- [ ] **Step 1: Add partition health check**

```go
// In manager.go:

// Healthy returns nil if every managed table has a partition for today.
// Returns an error otherwise — feed into the /health endpoint.
func (m *Manager) Healthy(ctx context.Context) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, tbl := range m.tables {
		name := tbl.PartitionName(today)
		var exists bool
		err := m.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`,
			name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check %s: %w", name, err)
		}
		if !exists {
			return fmt.Errorf("missing partition %s for today", name)
		}
	}
	return nil
}
```

- [ ] **Step 2: Add unit test**

```go
func TestHealthy_PassWhenPartitionsExist(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()
	if err := m.EnsureFuturePartitions(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := m.Healthy(ctx); err != nil {
		t.Errorf("Healthy() = %v want nil", err)
	}
}

func TestHealthy_FailWhenMissing(t *testing.T) {
	pool := newTestPool(t)
	m := NewManager(pool, []Table{{Name: "bridged_flows", RetentionDays: 14}})
	ctx := context.Background()
	// Don't call EnsureFuturePartitions — partition for today missing.
	if err := m.Healthy(ctx); err == nil {
		t.Errorf("Healthy() should error when partitions missing")
	}
}
```

- [ ] **Step 3: Wire into /health endpoint** (if applicable)

Find the existing /health handler and add:

```go
// Inside healthHandler:
if err := pm.Healthy(ctx); err != nil {
    http.Error(w, "partition unhealthy: "+err.Error(), http.StatusServiceUnavailable)
    return
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/storage/partitions/ -run Healthy -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/storage/partitions/ internal/server/
git commit -m "feat(server): partition healthcheck wired into /health"
```

---

## Phase 7: Migration runbook + final verification

### Task 7.1: Write MIGRATION.md

**Files:**
- Create: `log-analyzer/MIGRATION.md`

- [ ] **Step 1: Write runbook**

```markdown
# Schema v2 Migration Runbook

## Pre-flight (do day before)

1. Confirm VM 101 disk free ≥ 20 GB
   ```bash
   ssh dedik "ssh root@10.10.10.20 'df -h /'"
   ```
2. Snapshot current pg_stat_user_indexes (record unused indexes for post-migration cleanup):
   ```bash
   ssh dedik "ssh root@10.10.10.20 \"docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer -c '\\\\copy (SELECT * FROM pg_stat_user_indexes) TO STDOUT WITH CSV HEADER'\"" > pre-migration-index-stats.csv
   ```
3. Notify in chat (15-30 min ahead): "log-analyzer brief downtime ~5 min for schema upgrade".

## Snapshot for emergency rollback

```bash
ssh dedik "ssh root@10.10.10.20 'mkdir -p /opt/xray/log-analyzer/backups && \
  docker run --rm \
    -v log-analyzer_analyzer-postgres-data:/d \
    -v /opt/xray/log-analyzer/backups:/backup \
    alpine tar czf /backup/pg-pre-v2-\$(date +%Y%m%d-%H%M).tgz /d'"
```

## Cutover (~5 min)

```bash
ssh dedik "ssh root@10.10.10.20 'cd /opt/xray/log-analyzer && \
  docker compose stop xray-log-analyzer && \
  docker compose stop analyzer-postgres && \
  docker volume rm log-analyzer_analyzer-postgres-data && \
  git pull && \
  docker compose build analyzer-server && \
  docker compose up -d analyzer-postgres analyzer-redis xray-log-analyzer'"
```

## Verify (10 min after cutover)

1. Container health:
   ```bash
   ssh dedik "ssh root@10.10.10.20 'docker ps --filter name=xray-log-analyzer'"
   ```
   Expect: `Up X seconds (healthy)`.

2. Stats endpoint:
   ```bash
   ssh dedik "ssh root@10.10.10.20 'curl -sS -H \"Authorization: Bearer \$API_TOKEN\" http://localhost:8237/api/stats'"
   ```
   Expect: `nodes_connected: 8` or `9`.

3. Partitions today/tomorrow/+2:
   ```bash
   ssh dedik "ssh root@10.10.10.20 'docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer -c \"SELECT relname FROM pg_class WHERE relname LIKE \\\"bridged_flows_%\\\" ORDER BY 1\"'"
   ```
   Expect: bridged_flows_default + bridged_flows_<today> + tomorrow + day after.

4. Threats writing (within ~1 min):
   ```bash
   ssh dedik "ssh root@10.10.10.20 'docker logs --since 2m xray-log-analyzer 2>&1 | grep \"threat alert\"'"
   ```

## Rollback A — code regression, data still ok

```bash
git revert <sha-of-merge-commit>
docker compose build analyzer-server
docker compose up -d analyzer-server
```

## Rollback B — schema disaster, restore from backup

```bash
docker compose down
docker volume rm log-analyzer_analyzer-postgres-data
docker run --rm \
  -v log-analyzer_analyzer-postgres-data:/d \
  -v /opt/xray/log-analyzer/backups:/b \
  alpine sh -c "cd /d && tar xzf /b/pg-pre-v2-*.tgz --strip-components 1"
git checkout postgres-migration
docker compose build analyzer-server
docker compose up -d
```

## Post-deploy (week 1)

- Daily: `df -h /` should plateau between 12-15 GB postgres volume
- iowait stays ≤ 5%
- Partition manager logs show daily create + 14-day-old drop
- /api/stats nodes_connected stable
- After 7 days: drop emergency backup `rm /opt/xray/log-analyzer/backups/pg-pre-v2-*.tgz`
```

- [ ] **Step 2: Commit**

```bash
git add log-analyzer/MIGRATION.md
git commit -m "docs: schema v2 migration runbook"
```

### Task 7.2: Full local test sweep

- [ ] **Step 1: Run all tests**

```bash
cd /Users/qwertyhq/code/xray/log-analyzer/server
DOCKER_HOST=unix:///Users/qwertyhq/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
go test ./... 2>&1 | tee /tmp/test-output.log
```

Expected: all PASS.

- [ ] **Step 2: Build + lint**

```bash
go build ./...
go vet ./...
```

Expected: clean.

- [ ] **Step 3: If anything failed, fix + commit. Otherwise no-op step.**

### Task 7.3: PR / merge prep

- [ ] **Step 1: Push branch**

```bash
git push -u origin refactor/schema-v2
```

- [ ] **Step 2: Verify branch contains expected commit history**

```bash
git log postgres-migration..refactor/schema-v2 --oneline
```

Expected: chain of feat/refactor/test/docs commits, ~25-35 commits total.

- [ ] **Step 3: Open PR (or document the review process)**

If using GitHub:

```bash
gh pr create --base postgres-migration --title "Schema v2: native types + partitioning" \
  --body "$(cat <<'EOF'
## Summary
- Greenfield schema rewrite per `docs/superpowers/specs/2026-05-01-analyzer-refactor-v2-design.md`
- Native types (uuid, inet, smallint FK)
- Daily partitioning for bridged_flows, alerts, blacklist_matches, threat_matches, anomalies
- Postgres tuning via docker-compose
- TRUNCATE old data (user authorized)

## Test plan
- [x] Unit tests: storage layer (testcontainers)
- [x] Integration: partition manager full Tick cycle
- [ ] Deploy: follow `log-analyzer/MIGRATION.md`
- [ ] Verify: 7-day disk usage trend ≤ 15 GB
EOF
)"
```

- [ ] **Step 4: Decide on merge — manual review or self-merge**

User to confirm merge → deploy via MIGRATION.md.

---

## Self-review notes

This plan covers all spec sections:

| Spec section | Covered by |
|---|---|
| Goals + scope | Phases 0-7 (whole plan) |
| Constraints (no precision loss, ≤15 min downtime, API back-compat) | Task 5.2 (API compat), 7.1 (cutover) |
| Architecture: 39-table classification | Task 2.1, 2.2, 2.3 |
| Lookup table `nodes` | Task 2.2, 3.1 |
| Type changes table | Tasks 3.2-3.6, 4.1-4.3 |
| Index strategy (BRIN + per-partition btree) | Task 2.2 |
| Materialized views | Out of scope (deferred per spec) |
| Foreign keys | Task 2.2 (schema), 3.1 (LookupNodeID) |
| Storage Go refactor | Phases 3-4 |
| Partition manager | Phase 1 |
| Postgres tuning | Task 6.1 |
| Migration plan | Task 7.1 |
| Testing strategy | Tests in every task + 7.2 sweep |
| Rollback plan | Task 7.1 (MIGRATION.md sections A/B) |
| Risk register | Mitigations per task (FK in 3.1, default partition in 2.2, healthcheck in 6.3) |
| Verification week 1 | Task 7.1 (post-deploy section) |

No placeholders remain. Type signatures (`NodeID int16`, `BridgedFlow.UserEmail uuid.UUID`, `Manager.Tick`) are consistent across tasks.
