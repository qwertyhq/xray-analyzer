# Xray Log Analyzer

Real-time analytics для Xray-core access logs c интеграцией с Remnawave panel. Собирает access logs со всех VPN-нод через WebSocket-агентов, агрегирует в Postgres, детектит abuse/threat-traffic, рисует дашборд.

> 📦 **Установка по шагам:** [INSTALL.md](./INSTALL.md) — production-ready гайд для server + agents + reverse-proxy.

## Содержание

- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Tech stack](#tech-stack)
- [Quick install — server](#quick-install--server)
- [Quick install — agent](#quick-install--agent-на-каждой-xray-ноде)
- [Configuration reference](#configuration-reference)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Возможности

- **Real-time ingest** — агенты на каждой ноде читают access.log через `inotify` и стримят батчи (gzip, WebSocket) на сервер
- **Postgres storage** с partitioning по дням для hot tables (`bridged_flows`, `alerts`, `threat_matches`...). Daily DROP PARTITION → ноль bloat
- **Threat intel** — 1.5M+ indicators (ads, malware, casino, social, tor, blocklist-fraud), алерты при превышении порогов
- **Bridge correlation** — time-based fan-out для bridge-фронтированных exit-нод (RU bridge → German exit), резолвит синтетические email-IDs обратно к настоящим Remnawave UUID через `remna_users` lookup
- **Remnawave sync** — каждые 1-5 мин подтягивает users / nodes / hwid devices / online stats из panel API, держит дашборд в sync с panel
- **Web UI** на Next.js (RU + EN, dark theme, language switcher) — dashboard, threat intel breakdown, per-user details, abuse analytics, geo map
- **Telegram alerts** — threat alerts с категориями + контекстом
- **AI assistant** — встроенный chat для запросов вроде "найди abusers за последний час"

## Архитектура

```
                    ┌──────────────────────────────────────────┐
                    │  Каждая Xray нода (Remnawave node)       │
                    │  ┌─────────────────────────────────┐     │
                    │  │  xray-log-agent (docker)        │     │
                    │  │  - reads /var/log/remnanode/    │     │
                    │  │    access.log via inotify       │     │
                    │  │  - batches 1000/5s, gzip        │     │
                    │  │  - WebSocket → server           │     │
                    │  └─────────────────────────────────┘     │
                    └──────────────────────┬───────────────────┘
                                           │
                                           │ WSS
                                           ▼
                    ┌──────────────────────────────────────────┐
                    │  Main analyzer server                    │
                    │  ┌────────────────────────────────────┐  │
                    │  │ analyzer-server (Go + Next.js)     │  │
                    │  │ :8237 (WS+API)  :3925 (UI)         │  │
                    │  └─────────────┬──────────────────────┘  │
                    │                │                          │
                    │   ┌────────────┴────────────┐             │
                    │   ▼                         ▼             │
                    │  postgres:17           redis:7            │
                    │  (analytics DB)        (L2 cache)         │
                    └──────────────────────────────────────────┘
                                           │
                                           │ HTTP API sync
                                           ▼
                    ┌──────────────────────────────────────────┐
                    │  Remnawave panel (отдельный сервер)      │
                    │  - users, nodes, subscriptions           │
                    │  - XTLS-tracked online counts            │
                    └──────────────────────────────────────────┘
```

**Ключевые порты сервера:**
- `8237/tcp` — WebSocket для агентов + REST API (внутренний)
- `3925/tcp` — Next.js UI (внутренний)
- Реверс-прокси (Caddy/nginx) терминирует TLS и роутит:
  - `analyzer.example.com/ws*` → `:8237/ws*` (агенты)
  - `analyzer.example.com/api/*` → `:8237/api/*` (UI → API)
  - `analyzer.example.com/health` → `:8237/health`
  - `analyzer.example.com/*` → `:3925` (UI)

## Tech stack

- **Server**: Go 1.25, Postgres 17, Redis 7, Next.js 16 (React 19, TypeScript, Tailwind 4)
- **Agent**: Go 1.21, gorilla/websocket, fsnotify
- **Storage**: Postgres с партиционированием по дням, BRIN индексы по `ts`
- **Auth**: Bearer tokens (отдельные для UI/API и для agent WebSocket)
- **i18n**: next-intl с RU/EN bundles, cookie-based persistence

---

## Quick install — server

Один скрипт устанавливает Postgres + Redis + analyzer-server из исходников. Поддерживает Ubuntu 22.04+/Debian 12+. Подходит для bare-metal, VM, или контейнера с Docker access.

```bash
git clone https://github.com/qwertyhq/xray-analyzer.git /opt/xray-analyzer
cd /opt/xray-analyzer/log-analyzer
sudo bash scripts/install-server.sh
```

После установки скрипт:
1. Установит Docker + docker-compose-plugin (если нет)
2. Сгенерирует случайные `API_TOKEN`, `AGENT_TOKEN`, `POSTGRES_PASSWORD` в `.env`
3. Соберёт images (analyzer-server из локальных Go + Next.js sources)
4. Поднимет стек через `docker compose up -d`
5. Подождёт healthcheck'ов и распечатает endpoints + tokens

**Что нужно настроить вручную после установки:**

Отредактируй `/opt/xray-analyzer/.env`:

| Переменная | Назначение |
|---|---|
| `REMNAWAVE_URL` | URL твоей Remnawave panel (`https://panel.example.com`) |
| `REMNAWAVE_API_TOKEN` | Bearer token из panel → Settings → API |
| `TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID` | бот для алертов |
| `BRIDGE_NODE_IDS` | список node_id мостов через запятую (если используешь bridge architecture) |
| `NODE_REMNA_MAP` | mapping `agent_node_id=remnawave_name`, например `est-1=Estonia,germany-1=Germany 2` |

После правок:
```bash
cd /opt/xray-analyzer/log-analyzer
docker compose up -d
```

**Reverse-proxy.** Скрипт НЕ конфигурит Caddy/nginx — это специфично для твоей инфры. Минимальный пример Caddyfile:

```caddy
analyzer.example.com {
    @ws path /ws*
    reverse_proxy @ws localhost:8237

    @api path /api/* /health
    reverse_proxy @api localhost:8237

    reverse_proxy localhost:3925
}
```

---

## Quick install — agent (на каждой Xray-ноде)

Запусти на каждой ноде где работает Xray (Remnawave node, отдельный VPN endpoint, и т.д.):

```bash
curl -fsSL https://raw.githubusercontent.com/qwertyhq/xray-analyzer/main/scripts/install-agent.sh | \
  sudo SERVER_URL="wss://analyzer.example.com/ws" \
       AUTH_TOKEN="<AGENT_TOKEN из server .env>" \
       NODE_ID="germany-1" \
       bash
```

Параметры (через env-переменные перед `bash`):

| Переменная | Required | Default | Описание |
|---|---|---|---|
| `SERVER_URL` | yes | — | WSS endpoint analyzer-сервера |
| `AUTH_TOKEN` | yes | — | `AGENT_TOKEN` из server `.env` |
| `NODE_ID` | yes | hostname | уникальный ID ноды (используется в дашборде) |
| `LOG_PATH` | no | `/var/log/remnanode` | путь к директории с access.log |
| `BATCH_SIZE` | no | 1000 | сколько записей в одном WS-кадре |
| `BATCH_TIMEOUT` | no | 5s | максимальное время до отправки batch'а |

**Важно для Remnawave-нод:** `Xray` config на ноде должен писать access.log в `/var/log/remnanode/access.log`. Это настраивается в Config Profile в Remnawave panel:

```json
"log": {
  "access": "/var/log/remnanode/access.log",
  "error": "/var/log/remnanode/error.log",
  "loglevel": "warning"
}
```

И в `docker-compose.yml` для `remnanode` контейнера должен быть volume:
```yaml
volumes:
  - /var/log/remnanode:/var/log/remnanode
```

Скрипт сам проверит, что директория существует и не пустая.

---

## Configuration reference

### Server (.env)

```bash
# Authentication (REQUIRED, generate strong tokens)
API_TOKEN=                     # для UI и /api/* endpoints
AGENT_TOKEN=                   # для агентов на нодах через WS
POSTGRES_PASSWORD=             # postgres user password

# Remnawave integration (highly recommended)
REMNAWAVE_ENABLED=true
REMNAWAVE_URL=https://panel.example.com
REMNAWAVE_API_TOKEN=<bearer>
REMNAWAVE_SYNC_INTERVAL=1m

# Bridge architecture (если используешь moscow→germany туннель)
BRIDGE_NODE_IDS=ru-white,ru-bride       # node_id мостов
BRIDGE_CORRELATION_WINDOW=15s            # окно для time-based fan-out
BRIDGE_INBOUND_PATTERN=^BRIDGE_.*_IN(_\d+)?$

# Node mapping (sync agent NODE_ID с Remnawave node names)
NODE_REMNA_MAP=est-1=Estonia,germany-1=Germany 2,poland-1=Poland

# Telegram alerts
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=<bot_token>
TELEGRAM_CHAT_ID=<chat_id>

# Threat detection thresholds
SUSPICIOUS_REQUEST_COUNT=5
SUSPICIOUS_TIME_WINDOW=1h

# Threat-intel feeds (defaults are fine, can override)
BLACKLIST_REMOTE_URL=https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst
BLACKLIST_RELOAD=5m

# AI assistant (опционально, любой OpenAI-compatible /v1 endpoint)
# Примеры: OpenAI, Together AI, OpenRouter, Aleria, локальный llama.cpp/vLLM.
OPENAI_API_KEY=<key>
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini

# Web UI Mapbox token для geo map (опционально)
NEXT_PUBLIC_MAPBOX_TOKEN=<token>
```

### Agent (.env)

```bash
NODE_ID=germany-1                                 # required, unique per node
SERVER_URL=wss://analyzer.example.com/ws          # required
AUTH_TOKEN=<AGENT_TOKEN из server>                 # required

LOG_FILE_PATH=/var/log/remnanode/access.log       # default
BATCH_SIZE=1000                                    # records per batch
BATCH_TIMEOUT=5s                                   # max wait before send
ENABLE_COMPRESSION=true                            # gzip-сжимать batches
```

---

## Operations

### Логи

```bash
# Server
cd /opt/xray-analyzer/log-analyzer
docker compose logs -f analyzer-server      # API + UI
docker compose logs -f analyzer-postgres    # DB
docker compose logs -f analyzer-redis       # Cache

# Agent (на ноде)
cd /opt/xray-analyzer/log-analyzer
docker compose -f docker-compose.agent.yml logs -f xray-log-agent
```

### Healthchecks

```bash
# Server health (включает проверку партиций)
curl -fsS http://localhost:8237/health

# Stats endpoint (нужен API_TOKEN)
curl -sS -H "Authorization: Bearer $API_TOKEN" http://localhost:8237/api/stats | jq
```

### Backup Postgres

```bash
docker exec analyzer-postgres pg_dump -U xray_analyzer -Fc xray_analyzer \
  > backup-$(date +%Y%m%d-%H%M).dump
```

Или snapshot всего volume (faster, но требует stop'а):
```bash
docker compose stop analyzer-postgres
docker run --rm -v log-analyzer_analyzer-postgres-data:/d -v $PWD:/b alpine \
  tar czf /b/pg-backup-$(date +%Y%m%d).tgz /d
docker compose start analyzer-postgres
```

### Обновление

Для сервера:
```bash
cd /opt/xray-analyzer
git pull origin main
cd log-analyzer
docker compose build analyzer-server
docker compose up -d analyzer-server
```

Для агента (на каждой ноде):
```bash
cd /opt/xray-analyzer
git pull origin main
cd log-analyzer
docker compose -f docker-compose.agent.yml build
docker compose -f docker-compose.agent.yml up -d --force-recreate
```

Раскатывай агенты по одной ноде с проверкой `nodes_connected` в `/api/stats` после каждой.

### Retention

Hot tables (`bridged_flows`, `alerts`, `blacklist_matches`, `threat_matches`, `anomalies`) партиционированы по дням. Partition manager в analyzer-server:
- Каждые 6 часов создаёт партиции на сегодня + 2 дня вперёд
- Дропает партиции старше retention (`bridged_flows: 14d, остальное: 30d`)

`/health` сигнализирует если today's партиция отсутствует ИЛИ default partition не пустая (обе ситуации = partition manager пропустил окно).

### Scale

При >100 нод / >50M flows/day:
- Bump postgres `shared_buffers=4GB`, `effective_cache_size=12GB` (нужно ~16GB RAM на VM)
- Поднять `BATCH_SIZE=5000` на агентах для меньше WS round-trips
- Рассмотреть pgbouncer перед postgres
- Disk: ~150 байт/строка × 7M строк/день = ~1 GB/день, 14 GB steady state

---

## Troubleshooting

### Агент не подключается

```bash
# На агентной ноде
docker compose -f docker-compose.agent.yml logs --tail 30 xray-log-agent | grep -E "error|connect"
```

Типичные причины:
- `403 forbidden` → `AUTH_TOKEN` на агенте не совпадает с `AGENT_TOKEN` на сервере
- `connection refused` / `tls: ...` → reverse-proxy не пропускает WebSocket (Upgrade header)
- `no such file or directory: /var/log/remnanode/access.log` → xray не пишет access log в эту директорию (см. Remnawave config profile setup выше)

### Дашборд показывает голые UUID вместо username

`remna_users` ещё не синканулся — подожди 1-5 минут после первого старта analyzer-server. Если sync не работает:
```bash
docker compose logs analyzer-server | grep -i remnawave
```
Проверь `REMNAWAVE_URL` (должен быть полный URL с `https://`) и `REMNAWAVE_API_TOKEN` (выдаётся в Settings → API в panel).

### `/api/stats` total_users не совпадает с Remnawave

Sync прогоняется раз в `REMNAWAVE_SYNC_INTERVAL` (default 1m). Подожди следующий цикл — числа сойдутся. Stale entries (юзеры удалённые из panel) удаляются автоматически после первого успешного sync'а.

### Disk fills up

```bash
# Посмотреть что занимает место
docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer \
  -c "\dt+" | sort -k7 -h -r | head -15
```

Если bridged_flows >25 GB — partition manager не работает. Проверь `/health`:
```bash
curl http://localhost:8237/health
```
Должен вернуть `200`. Если `503 partition unhealthy` — посмотри логи на наличие SQL errors в partition creation/drop.

---

## Development

### Local dev

```bash
# Server
cd server
go run ./cmd/server

# Web UI
cd server/web
npm install
npm run dev
```

### Tests

```bash
cd server
DOCKER_HOST=unix:///var/run/docker.sock go test ./...
```

Тесты используют testcontainers-go с `postgres:17-alpine` — поднимают одноразовый контейнер postgres на запуск.

---

## Лицензия и контрибьютинг

Внутренний проект. PRs welcome — фокус на:
- Новые threat-intel feeds
- UI components (vanilla shadcn/Radix)
- Performance improvements

Issue tracker: https://github.com/qwertyhq/xray-analyzer/issues
