# Установка Xray Log Analyzer — пошагово

Полный гайд для production-деплоя. Сервер + агенты + reverse-proxy + интеграции.

## Что мы строим

```
                           Internet
                              │
                              ▼
                    ┌──────────────────┐
                    │  Caddy / nginx   │  TLS termination
                    │  :443            │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
            /ws*          /api/*           /*
              │              │              │
              ▼              ▼              ▼
        analyzer-server :8237   analyzer-server :3925 (UI)
              │
       ┌──────┴──────┐
       ▼             ▼
    postgres:17   redis:7
```

И на каждой Xray-ноде:

```
xray-log-agent (docker)  →  WSS /ws  →  analyzer-server
       │
       ▼
/var/log/remnanode/access.log (read-only mount)
```

---

## Часть 1 — Сервер

### Требования

- **OS**: Ubuntu 22.04+ или Debian 12+
- **CPU**: 2 cores (4 рекомендуется)
- **RAM**: 4 GB минимум, 8 GB рекомендуется
- **Disk**: 20 GB free (15 GB для system + Postgres growth)
- **Сеть**: открыты порты 80/443 (или reverse-proxy уже настроен)
- **Domain**: один для analyzer (например, `analyzer.example.com`)

### Шаг 1. Подготовка сервера

```bash
# Обнови систему
sudo apt update && sudo apt upgrade -y

# Установи минимальный toolset (если нет)
sudo apt install -y curl git ca-certificates openssl
```

### Шаг 2. Установка через скрипт (рекомендуется)

```bash
git clone https://github.com/qwertyhq/xray-analyzer.git /opt/xray-analyzer
sudo bash /opt/xray-analyzer/scripts/install-server.sh
```

Скрипт:
- Установит Docker + docker-compose-plugin
- Сгенерирует `.env` со случайными tokens (`API_TOKEN`, `AGENT_TOKEN`, `POSTGRES_PASSWORD`)
- Соберёт image сервера (Go + Next.js, ~3-5 минут)
- Поднимет стек, дождётся healthcheck'ов
- **Распечатает endpoints + tokens** — сохрани их

После завершения у тебя:
- `analyzer-server` слушает на `:8237` (API+WS) и `:3925` (UI)
- Postgres + Redis запущены в Docker
- `/opt/xray-analyzer/.env` с tokens

### Шаг 3. Заполни Remnawave + Telegram настройки

```bash
sudo nano /opt/xray-analyzer/.env
```

Минимум что нужно поправить:

```bash
# Remnawave (получи API token в panel → Settings → API)
REMNAWAVE_ENABLED=true
REMNAWAVE_URL=https://panel.example.com
REMNAWAVE_API_TOKEN=eyJhbGc...

# Telegram alerts (создай бота через @BotFather, узнай chat_id)
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=1234567890:AAA...
TELEGRAM_CHAT_ID=-100...

# Опционально — связь agent NODE_ID ↔ Remnawave node names
NODE_REMNA_MAP=germany-1=Germany 2,est-1=Estonia,poland-1=Poland
```

После правок применяем:

```bash
cd /opt/xray-analyzer/log-analyzer
docker compose up -d
```

### Шаг 4. Reverse-proxy

Скрипт **не настраивает** Caddy/nginx — это специфично. Минимальный Caddyfile:

```caddy
analyzer.example.com {
    @ws path /ws*
    reverse_proxy @ws localhost:8237

    @api path /api/* /health
    reverse_proxy @api localhost:8237

    reverse_proxy localhost:3925
}
```

Сохрани в `/etc/caddy/Caddyfile`, перезагрузи: `sudo systemctl reload caddy`.

Для nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name analyzer.example.com;

    # ssl_certificate ... (через certbot или ручной cert)

    # WebSocket — ОБЯЗАТЕЛЬНО Upgrade headers
    location /ws {
        proxy_pass http://localhost:8237;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }

    location ~ ^/(api|health) {
        proxy_pass http://localhost:8237;
        proxy_set_header Host $host;
    }

    location / {
        proxy_pass http://localhost:3925;
        proxy_set_header Host $host;
    }
}
```

### Шаг 5. Проверка

```bash
# Health endpoint (должен вернуть 200 OK)
curl -fsS https://analyzer.example.com/health

# Stats endpoint (нужен API_TOKEN из .env)
source /opt/xray-analyzer/.env
curl -sS -H "Authorization: Bearer $API_TOKEN" \
  https://analyzer.example.com/api/stats | jq
```

Открой `https://analyzer.example.com` в браузере — должен загрузиться dashboard. Логин с `API_TOKEN`.

### Шаг 6. Backup (рекомендуется настроить cron)

```bash
sudo mkdir -p /opt/xray-analyzer/backups
sudo crontab -e
```

Добавь:

```cron
# Ежедневный pg_dump в 2:00 ночи, retention 7 дней
0 2 * * * docker exec analyzer-postgres pg_dump -U xray_analyzer -Fc xray_analyzer > /opt/xray-analyzer/backups/pg-$(date +\%Y\%m\%d).dump 2>&1 ; find /opt/xray-analyzer/backups -name "pg-*.dump" -mtime +7 -delete
```

---

## Часть 2 — Агенты на VPN-нодах

Запускается на **каждой** Xray-ноде, которая должна слать access logs в analyzer.

### Требования

- Docker уже работает (на Remnawave-нодах он есть)
- Xray пишет access log в `/var/log/remnanode/access.log`

### Шаг 1. Настрой Xray на запись access log

В Remnawave panel → Config Profiles → выбери профиль ноды → добавь в JSON:

```json
"log": {
  "access":   "/var/log/remnanode/access.log",
  "error":    "/var/log/remnanode/error.log",
  "loglevel": "warning"
}
```

И на ноде проверь docker-compose `remnanode`:

```yaml
volumes:
  - /var/log/remnanode:/var/log/remnanode
```

Перезапусти `remnanode` контейнер на ноде, подожди минуту, проверь:

```bash
ls -la /var/log/remnanode/access.log
tail -3 /var/log/remnanode/access.log
```

Должен быть не-пустой и обновляться. Если пустой — xray не пишет.

### Шаг 2. Установка агента

На ноде:

```bash
curl -fsSL https://raw.githubusercontent.com/qwertyhq/xray-analyzer/main/scripts/install-agent.sh \
  | sudo SERVER_URL="wss://analyzer.example.com/ws" \
         AUTH_TOKEN="<AGENT_TOKEN из server .env>" \
         NODE_ID="germany-1" \
         bash
```

`NODE_ID` должен быть **уникальным** на каждой ноде (`germany-1`, `est-1`, `poland-1`, ...). Скрипт:
- Проверит ОС, поставит Docker если нет
- Клонирует репо в `/opt/xray-analyzer`
- Создаст `.env` для агента
- Настроит logrotate для `/var/log/remnanode/*.log`
- Соберёт image, поднимет контейнер
- Через 8 секунд проверит что подключение к серверу работает

### Шаг 3. Проверка на сервере

```bash
# На сервере, не на ноде
source /opt/xray-analyzer/.env
curl -sS -H "Authorization: Bearer $API_TOKEN" \
  https://analyzer.example.com/api/nodes | \
  jq '.[] | {node_id, is_connected, total_requests}'
```

Твоя нода должна появиться с `is_connected: true`.

### Шаг 4. Повторить для всех нод

Раскатывай по одной с проверкой `nodes_connected` после каждой:

```bash
curl -sS -H "Authorization: Bearer $API_TOKEN" https://analyzer.example.com/api/stats | \
  jq '.nodes_connected'
```

Должно расти после каждого подключённого агента.

---

## Часть 3 — Опциональные интеграции

### AI assistant (OpenAI-compatible)

Включает встроенный AI-чат на дашборде для запросов вроде "найди abusers за час".

В `.env` сервера:

```bash
# OpenAI
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini

# или Together AI
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://api.together.xyz/v1
OPENAI_MODEL=meta-llama/Llama-3.3-70B-Instruct-Turbo

# или OpenRouter
OPENAI_API_KEY=sk-or-...
OPENAI_BASE_URL=https://openrouter.ai/api/v1
OPENAI_MODEL=anthropic/claude-3.5-sonnet

# или локальный llama.cpp/vLLM
OPENAI_API_KEY=local
OPENAI_BASE_URL=http://localhost:8080/v1
OPENAI_MODEL=qwen2.5-72b
```

Перезапуск:

```bash
cd /opt/xray-analyzer/log-analyzer
docker compose up -d analyzer-server
```

### Mapbox (geo map в дашборде)

Получи бесплатный токен: https://account.mapbox.com/access-tokens/

```bash
# В .env
NEXT_PUBLIC_MAPBOX_TOKEN=pk.eyJ1...
```

⚠️ Этот токен билдится в JS bundle, **обязательно нужно пересобрать UI**:

```bash
docker compose build analyzer-server
docker compose up -d analyzer-server
```

### Bridge architecture

Если у тебя моста-схема (RU-bridge → Germany-exit), укажи node_id мостов:

```bash
BRIDGE_NODE_IDS=ru-white,ru-bride
BRIDGE_CORRELATION_WINDOW=15s
```

Это включит time-based fan-out: для каждого bridged exit-flow analyzer резолвит реальный client IP через `user_ip_history` на bridge-нодах.

---

## Часть 4 — Обновление

### Сервер

```bash
cd /opt/xray-analyzer
sudo git pull origin main

cd log-analyzer
sudo docker compose build analyzer-server
sudo docker compose up -d analyzer-server
```

Postgres / Redis обычно не нужно перезапускать. Если есть schema миграции (новые таблицы) — analyzer-server применит их сам на старте.

### Агенты

На каждой ноде:

```bash
cd /opt/xray-analyzer
sudo git pull origin main

cd log-analyzer
sudo docker compose -f docker-compose.agent.yml build
sudo docker compose -f docker-compose.agent.yml up -d --force-recreate
```

Раскатывай по одной с проверкой `nodes_connected`.

---

## Часть 5 — Что-то сломалось

### Агент не подключается

```bash
# На ноде
docker compose -f /opt/xray-analyzer/docker-compose.agent.yml logs --tail 30 xray-log-agent
```

| Ошибка в логах | Причина | Фикс |
|---|---|---|
| `403 forbidden` | wrong AUTH_TOKEN | Проверь что `AUTH_TOKEN` агента совпадает с `AGENT_TOKEN` сервера |
| `tls: failed to verify` | invalid cert | Проверь что `SERVER_URL` использует правильный domain, не self-signed cert |
| `connection refused` | reverse-proxy не пропускает WS | nginx нужен `Upgrade $http_upgrade` (см. шаг 4 выше) |
| `no such file: /var/log/remnanode/access.log` | xray не пишет туда | См. Часть 2 шаг 1 |

### Дашборд показывает 0 пользователей

`remna_users` ещё не синканулся. Жди 1-5 минут после старта, потом проверь:

```bash
docker logs analyzer-server 2>&1 | grep -i remnawave | tail -5
```

Если есть `remnawave: failed to sync` — проверь `REMNAWAVE_URL` (полный URL с https://) и `REMNAWAVE_API_TOKEN`.

### Postgres ошибка `nodes_id_seq overflow` (smallint)

Маловероятно после refactor v2 — нода кэшируется в памяти. Если всё-таки случилось:

```bash
docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer \
  -c "SELECT setval('nodes_id_seq', (SELECT MAX(id) FROM nodes))"
docker compose restart analyzer-server
```

### Disk fills up

```bash
df -h /
docker exec analyzer-postgres psql -U xray_analyzer -d xray_analyzer -c "\dt+" | sort -k7 -h -r | head -10
```

Если `bridged_flows` >25 GB — partition manager не работает, проверь `/health`:

```bash
curl https://analyzer.example.com/health
```

---

## Часть 6 — Удаление

### Полное удаление сервера

```bash
cd /opt/xray-analyzer/log-analyzer
sudo docker compose down -v       # -v убивает Postgres volume — все данные
sudo rm -rf /opt/xray-analyzer
```

### Удаление агента с ноды

```bash
cd /opt/xray-analyzer/log-analyzer
sudo docker compose -f docker-compose.agent.yml down
sudo rm -rf /opt/xray-analyzer
sudo rm /etc/logrotate.d/remnanode
```

---

## Дальше

- [README.md](./README.md) — общий обзор и архитектура
- [docs/](../docs/) — design specs, plans, ADR
- Issues: https://github.com/qwertyhq/xray-analyzer/issues
