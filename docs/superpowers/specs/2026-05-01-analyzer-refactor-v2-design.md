# Analyzer Schema v2 Refactor — Design

**Date:** 2026-05-01
**Status:** Draft (pending user review)
**Branch:** `refactor/schema-v2`

## Goal

Перевести xray log-analyzer (VM 101 Remnawave) на native-typed Postgres-схему c partitioning'ом для time-series таблиц. Цели:

1. Сократить дисковую нагрузку bridged_flows (22 → 12-15 GB при 14d retention)
2. Убрать iowait-bottleneck (22% → ~5%) через постгрес tuning
3. Заменить DELETE-based retention на DROP PARTITION (мгновенно, без bloat)
4. Чистая схема на native-типах (uuid/inet/smallint FK) без legacy text-полей
5. Подготовить codebase к 5-10x росту нагрузки без архитектурных изменений

**Не входит в scope:**
- Threat intel в Redis / bloom filter
- pgbouncer / connection pooler
- Async event pipeline (NATS / NOTIFY)
- Prometheus metrics для analyzer
- Сохранение исторических данных (TRUNCATE — пользователь явно согласился)
- Дедуп fan-out корреляций (теряет sub-минутную точность — пользователь явно отказался)

## Constraints

- **Точность корреляций сохраняется**: 1 строка bridged_flows на каждый candidate user в окне ±15с. Ничего не меняем в логике fan-out.
- **Допустимый downtime**: до 15 минут maintenance window (агенты буферизуют у себя).
- **Платформа**: Postgres 17, pgx/v5, Go 1.25 (server) / 1.21 (agent). Все как сейчас.
- **Совместимость API**: dashboard и REST endpoints возвращают text-форматы (uuid.String(), addr.String()) — внешний контракт без breaking changes.
- **Backups**: TRUNCATE без сохранения старых данных (явное согласие пользователя). Snapshot волума перед drop'ом для emergency rollback на ~неделю.

## Architecture overview

### Классификация таблиц (39 шт.)

**Hot time-series (daily partitions, retention 14d, BRIN на ts):**
- `bridged_flows` — main consumer, ~7M rows/day
- `alerts` — ~150K rows/day estimated
- `blacklist_matches` — ~450K rows/day estimated
- `threat_matches` — текущий объём 51 MB, partition для consistency
- `anomalies` — 235 MB

**State / small (без partitioning, btree-индексы):**
- ~30 остальных таблиц (`remna_users`, `nodes`, `hwid_user_map`, `user_*_profile`, остальные `user_*` / `dns_*` / `threat_*_stats` / `hourly_stats` / `online_snapshots`)
- Retention сохраняем как сейчас: существующая `CleanupOldData(ctx, 30)` для агрегатов (30 дней), state-таблицы (`hwid_user_map`, `ip_user_map`) живут до явного truncate. Объёмы маленькие, DELETE-bloat не критичен.

### Lookup-таблица для node IDs

Вводим **отдельную** owned-by-analyzer таблицу `nodes` (не реюзаем `remna_nodes`, которая sync'ается из Remnawave API и имеет свою lifecycle/schema):

```sql
CREATE TABLE nodes (
    id          smallint     GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    node_id     text         NOT NULL UNIQUE,    -- "ru-bride", "germany-1"
    role        text         NOT NULL CHECK (role IN ('bridge', 'exit')),
    first_seen  timestamptz  NOT NULL DEFAULT now(),
    last_seen   timestamptz  NOT NULL DEFAULT now()
);
```

Auto-populate: при первом коннекте агента нода добавляется в `nodes` (UPSERT по `node_id`). Все таблицы с node-ссылкой используют `smallint FK`, экономия ~8-12 байт/строка.

### Изменения типов (ключевые)

| Поле | До | После | Эффект |
|---|---|---|---|
| `user_email` | text (~40B) | `uuid` (16B) | -24B/row |
| `real_client_ip` | text | `inet` | -7B/row IPv4 |
| `source_ip` | text | `inet` | -7B/row |
| `bridge_node_id` | text | `smallint FK` | -8B/row |
| `exit_node_id` | text | `smallint FK` | -8B/row |
| `node_id` (всех таблиц) | text | `smallint FK` | -8B/row |
| `threat_type` | text | `smallint` (enum-like) | -8B/row |
| `severity` | text | `smallint` (enum-like) | -6B/row |
| `hwid` | text | text | без изменений (variable content) |
| `destination` | text | text | без изменений (host:port string) |
| `ts`, `created_at` | timestamptz | timestamptz | без изменений |

Ожидаемая экономия heap-данных bridged_flows: ~50 байт/строка × 100M = **−5 GB heap**, плюс пропорционально уменьшаются индексы.

### Индексная стратегия для bridged_flows

**Текущее (один btree на 100M строк):**
```
idx_bridged_flows_user (user_email, ts DESC)   5.0 GB
idx_bridged_flows_ts   (ts DESC)               1.4 GB
idx_bridged_flows_dest (destination)           929 MB
idx_bridged_flows_ip   (real_client_ip)        1.0 GB
                                              ──────
                                              ~8.3 GB
```

**После (per-partition × 14 партиций ≈ 7M rows/partition):**
```
BRIN (ts)                  ~50 KB    ← btree → BRIN, ts уже sorted в партиции
btree (user_email)         ~250 MB × 14 = 3.5 GB  ← user_email теперь uuid (16B)
btree (real_client_ip)     ~80 MB × 14 = 1.1 GB
btree (destination)        ~70 MB × 14 = 1.0 GB
                                       ──────
                                       ~5.6 GB всего
```

Удаляем композитный `(user_email, ts DESC)` — partition pruning по дате + btree по user_email + sort внутри партиции даёт тот же результат с меньшим объёмом.

### Materialized views (опционально, позже)

Только если `pg_stat_statements` после миграции покажет hotspots:
- `mv_threat_top_users_24h`
- `mv_node_health_summary`

Не в первой итерации — только если будут реальные performance-проблемы.

### Foreign Keys

Добавляем где не нарушают write-path agent'ов:
- `bridged_flows.bridge_node_id`, `exit_node_id` → `nodes.id`
- `threat_matches.node_id` → `nodes.id`

**Не добавляем** FK от `alerts.user_email` / `bridged_flows.user_email` / других user-ссылающихся таблиц на `remna_users.uuid` — могут писаться записи на удалённых/неизвестных юзеров (бывшие подписчики, юзеры из synced backlog'а).

PG 17 поддерживает FK на партиционированные таблицы (важно).

## Storage Go layer refactor

### Native types

```go
import (
    "github.com/google/uuid"
    "net/netip"
    "github.com/jackc/pgx/v5/pgxpool"
)

// До
type BridgedFlow struct {
    UserEmail    string
    RealClientIP string
    BridgeNodeID string
    ExitNodeID   string
    Destination  string
    Timestamp    time.Time
}

// После
type NodeID int16

type BridgedFlow struct {
    UserEmail    uuid.UUID
    RealClientIP netip.Addr
    BridgeNodeID NodeID
    ExitNodeID   NodeID
    Destination  string  // host:port — variable content
    Timestamp    time.Time
}
```

### Затрагиваемые файлы

**Major refactor:**
- `internal/storage/bridged_flows.go`
- `internal/storage/alerts.go`
- `internal/storage/threat_matches.go`
- `internal/storage/blacklist_matches.go`
- `internal/storage/anomalies.go`
- `internal/storage/schema.sql` — replace полностью

**Minor (smallint FK для node_id):**
- `internal/storage/users.go`
- `internal/storage/nodes.go`
- `internal/storage/destinations.go`
- `internal/storage/online_snapshots.go`
- `internal/storage/hourly.go`
- остальные storage/*.go где есть `node_id`

**Correlation:**
- `internal/correlation/service.go` — обновить типы для real_client_ip / user_email

**API layer:**
- `internal/server/*.go` — конвертация uuid/inet в string для JSON-выдачи (через `MarshalJSON`)

### Partition manager (новый модуль)

```go
// internal/storage/partitions/manager.go
type PartitionedTable struct {
    Name         string  // "bridged_flows"
    Retention    int     // days, e.g. 14
}

type Manager struct {
    db     *pgxpool.Pool
    tables []PartitionedTable
}

// Запускается goroutine'ой рядом с cleanup goroutine.
// Каждые 6 часов:
//   1. Создаёт партиции на сегодня + 2 дня вперёд (буфер на midnight edge)
//   2. Дропает партиции старше retention
//   3. Логирует операции
func (m *Manager) Run(ctx context.Context) error
func (m *Manager) ensureFutureParitions(ctx context.Context) error
func (m *Manager) dropExpiredPartitions(ctx context.Context) error
```

Partition naming: `bridged_flows_20260501`, `bridged_flows_20260502`, ...

Default partition (`PARTITION DEFAULT`) служит safety net на случай отсутствия дневной партиции — INSERT не падает, потом partition manager переносит данные. Healthcheck сигнализирует если default непустая.

## Postgres tuning

В `docker-compose.yml` для `analyzer-postgres`, через `command:` overrides (или mount custom postgresql.conf):

```yaml
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
```

Под 8 GB VM — postgres получает ~4 GB (shared_buffers 2GB + work_mem peak + кеши). Остальное на analyzer-server, redis, OS, buff/cache.

**Эффект (ожидаемый):**
- iowait 22% → ~3-5%
- INSERT throughput +30-50%
- VACUUM/CREATE INDEX в 2-3 раза быстрее (maintenance_work_mem)
- Меньше WAL flush'ей (max_wal_size + checkpoint_timeout)

## Migration plan

### Branch / commits

```
refactor/schema-v2 (от postgres-migration)
  ├── feat(schema): rewrite v2 with partitions and native types
  ├── feat(storage/partitions): partition manager + tests
  ├── refactor(storage/bridged_flows): native types + partitioned insert
  ├── refactor(storage/{alerts,threat_matches,blacklist_matches,anomalies}): same
  ├── refactor(storage/{users,nodes,destinations,...}): smallint FK
  ├── refactor(api): uuid/inet ↔ string marshalling
  ├── feat(postgres): tuning via compose command
  ├── chore(tests): testcontainers updates for new types
  └── docs: MIGRATION.md
```

### Deployment (single maintenance window, ~5 min)

1. **Pre-flight** (за день до):
   - Снять `pg_stat_user_indexes` для определения unused indexes (записать в memory / docs)
   - Убедиться что VM 101 disk free ≥ 20 GB (в случае если backup volume займёт место)
   - Notification в чат (15-30 мин до окна)

2. **Backup snapshot** (на случай emergency rollback):
   ```bash
   docker run --rm \
     -v log-analyzer_analyzer-postgres-data:/d \
     -v /opt/xray/log-analyzer/backups:/backup \
     alpine tar czf /backup/pg-pre-v2-$(date +%Y%m%d-%H%M).tgz /d
   ```

3. **Cutover (~5 min):**
   ```bash
   cd /opt/xray/log-analyzer
   docker compose stop xray-log-analyzer       # агенты буферизуют у себя
   docker compose stop analyzer-postgres
   docker volume rm log-analyzer_analyzer-postgres-data
   git pull
   docker compose build analyzer-server
   docker compose up -d analyzer-postgres analyzer-redis xray-log-analyzer
   ```

4. **Verify (10 min after up):**
   - `/api/stats` возвращает корректные `nodes_connected` (8-9)
   - Логи без panic / type errors
   - Партиции на сегодня/завтра/послезавтра созданы (`\d+ bridged_flows`)
   - Проверить что INSERT идут в правильную партицию

### Rollback

Сценарии:

**A. Баг в новом коде, БД ещё ок:**
1. `git revert <commits>` или `git checkout postgres-migration`
2. `docker compose build analyzer-server`
3. `docker compose up -d analyzer-server`
4. ~3 минуты, без потери данных (ну, тех что уже не было)

**B. Схема сломалась, нужна старая БД:**
1. `docker compose down`
2. `docker volume rm log-analyzer_analyzer-postgres-data`
3. Распаковать backup snapshot обратно в новый volume:
   ```bash
   docker run --rm -v log-analyzer_analyzer-postgres-data:/d -v /opt/xray/log-analyzer/backups:/b alpine sh -c "cd /d && tar xzf /b/pg-pre-v2-*.tgz --strip 1"
   ```
4. `git checkout postgres-migration && docker compose build && docker compose up -d`
5. ~10 минут

Backup хранится 7 дней, потом дропается.

### Verification (week 1)

| Метрика | Цель |
|---|---|
| Disk usage trend | плато на 12-15 GB к концу 14-дневного цикла |
| `pg_stat_statements` regressions | 0 (или явный план фикса) |
| iowait на VM | ~5% |
| Memory: postgres | ~3-4 GB |
| Memory: analyzer-server | без изменений (~1.1 GB) |
| Partition manager logs | regular create/drop без ошибок |
| `nodes_connected` API | 8-9, постоянно |
| Threat alerts генерация | без падений |

## Testing strategy

### Unit / integration tests

Существующий паттерн: `testcontainers-go` + `postgres:17-alpine` (уже в codebase).

**Что обновляем:**
- Все существующие storage tests — переписать под native types
- Особенно: `bridged_flows_test.go`, `alerts_test.go`, `threat_matches_test.go`

**Новые tests:**
- `internal/storage/partitions/manager_test.go`:
  - Создание партиций для today, today+1, today+2
  - DROP партиций старше retention
  - INSERT попадает в правильную партицию (по timestamp)
  - Edge case: midnight (UTC), DST transitions
  - Edge case: отсутствующая дневная партиция → fallback в default
- Integration test full-flow: agent отправляет batch → сервер сохраняет в правильную партицию → cleanup дропает старую партицию → данные исчезают

### Local dev pre-deploy validation

```bash
# В xray/log-analyzer/server, локально:
DOCKER_HOST=unix:///Users/qwertyhq/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
go test ./internal/storage/...
```

(Из memory `project_xray_analyzer.md` — Colima setup для testcontainers.)

### Pre-deploy load test (опционально)

Симулируем нагрузку на staging:
- Создаём fake-агента, льющего 100 батчей × 1000 rows = 100K rows/sec
- Проверяем что insert latency < 10ms p99
- Проверяем что partition manager успевает создавать партиции

## Risk register

| Риск | Вероятность | Impact | Митигация |
|---|---|---|---|
| FK constraints ломают INSERT'ы агентов с неизвестных нод | medium | high | Partition manager стартует first, создаёт `nodes` lookup из ENV или auto-add при первом коннекте; FK ON DELETE NO ACTION |
| Partition manager падает → нет завтрашней партиции → INSERT fail | low | high | DEFAULT PARTITION как safety net; healthcheck "есть ли партиция на завтра"; retry logic в Go |
| Storage refactor ломает API контракты UI | medium | medium | API responses через `MarshalJSON`/typed encoders → external API остаётся в text форматах; integration test покрывает |
| pgx/v5 versioning surprises | low | medium | Уже на pgx/v5 (memory подтверждает), без upgrade |
| Миграция занимает >15 мин | low | low | TRUNCATE — ничего не копируем; expected ~2 минуты |
| Postgres не стартует с новыми параметрами | medium | high | Тестируем локально через testcontainers до деплоя; rollback к default config через env override |
| BRIN индекс работает плохо на наших паттернах ts | low | medium | Бенчмарк до миграции на копии данных; fallback на btree если регрессии |
| Default partition разбухает из-за пропущенных партиций | low | medium | Healthcheck алерт; ежедневный INFO лог `pg_partition_tree(default)` |

## Open questions

(не блокирующие — решаем в ходе implementation)

1. **Default partition или нет?** За: safety net против пропущенных партиций. Против: может забухать незаметно. Решение: использовать с healthcheck'ом.
2. **Retention 14d для всех hot-таблиц или разная?** Сейчас bridged_flows 14d, alerts/threats были 30d. Подумать: оставить per-table retention или унифицировать.
3. **Materialized views в первой итерации или после?** Решение: после, только если pg_stat_statements покажет hotspots.
4. **Включить `pg_stat_statements` extension сразу?** Да, нужен для post-migration анализа. Добавить в schema.sql.

## Deliverables

1. `server/internal/storage/schema.sql` — полностью переписан
2. `server/internal/storage/partitions/` — новый модуль
3. `server/internal/storage/*.go` — обновлённые types & queries
4. `server/internal/correlation/service.go` — обновлён под новые types
5. `server/internal/server/*.go` — JSON marshalling adjustments
6. `docker-compose.yml` — postgres tuning command
7. `MIGRATION.md` — runbook для деплоя
8. Обновлённые тесты (existing + new partition manager tests)
