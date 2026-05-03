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
cd /opt/xray-analyzer
docker compose up -d
```

### Шаг 4. Reverse-proxy (с особым вниманием к WebSocket)

Скрипт **не настраивает** Caddy/nginx — это специфично. **WebSocket — самая частая точка отказа на этом шаге**, поэтому важно настроить корректно с первого раза.

#### Что должен пропустить proxy:

| Path | Backend | Особенности |
|---|---|---|
| `/ws*` | `localhost:8237` | **WebSocket** — нужен Upgrade/Connection headers, длинный read timeout, no buffering |
| `/api/*` | `localhost:8237` | Обычный HTTP REST |
| `/health` | `localhost:8237` | Healthcheck |
| `/` (всё остальное) | `localhost:3925` | Next.js UI |

#### Caddy (рекомендуется — auto-HTTPS, простой синтаксис, WS работает out-of-the-box)

`/etc/caddy/Caddyfile`:

```caddy
analyzer.example.com {
    # /ws* и /api/* идут на Go-backend
    @backend path /ws* /api/* /health
    reverse_proxy @backend localhost:8237

    # Всё остальное — Next.js UI
    reverse_proxy localhost:3925
}
```

Перезагрузи: `sudo systemctl reload caddy`.

Caddy сам корректно обрабатывает WebSocket Upgrade — ничего дополнительно настраивать не нужно.

#### nginx (нужны явные WS headers)

`/etc/nginx/sites-available/analyzer.example.com`:

```nginx
# WebSocket Upgrade map — обязательно для WS
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name analyzer.example.com;

    # SSL — если используешь certbot:
    #   sudo certbot --nginx -d analyzer.example.com
    ssl_certificate     /etc/letsencrypt/live/analyzer.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/analyzer.example.com/privkey.pem;

    # WebSocket — критичные настройки
    location /ws {
        proxy_pass http://127.0.0.1:8237;
        proxy_http_version 1.1;                       # ОБЯЗАТЕЛЬНО — HTTP/1.1 для Upgrade
        proxy_set_header Upgrade $http_upgrade;       # пропустить Upgrade: websocket
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WS — длинная сессия, отключаем буферизацию + большой timeout
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 86400s;                    # 24h — иначе WS отвалится при тишине
        proxy_send_timeout 86400s;
    }

    # Обычные API endpoints
    location ~ ^/(api/|health$) {
        proxy_pass http://127.0.0.1:8237;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Next.js UI
    location / {
        proxy_pass http://127.0.0.1:3925;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;       # Next dev server использует HMR-WS
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name analyzer.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -sf /etc/nginx/sites-available/analyzer.example.com /etc/nginx/sites-enabled/
sudo nginx -t                  # проверка синтаксиса
sudo systemctl reload nginx
```

#### Apache (если очень надо)

В `httpd.conf` или vhost-конфиге:

```apache
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so

<VirtualHost *:443>
    ServerName analyzer.example.com

    SSLEngine on
    SSLCertificateFile      /etc/letsencrypt/live/analyzer.example.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/analyzer.example.com/privkey.pem

    # WebSocket — отдельная директива
    ProxyPass        /ws    ws://127.0.0.1:8237/ws    upgrade=websocket timeout=86400
    ProxyPassReverse /ws    ws://127.0.0.1:8237/ws

    ProxyPass        /api   http://127.0.0.1:8237/api
    ProxyPassReverse /api   http://127.0.0.1:8237/api
    ProxyPass        /health http://127.0.0.1:8237/health
    ProxyPassReverse /health http://127.0.0.1:8237/health

    ProxyPass        /      http://127.0.0.1:3925/
    ProxyPassReverse /      http://127.0.0.1:3925/

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

#### Cloudflare / другие edge-прокси

Если перед твоим nginx/Caddy стоит **Cloudflare** или другой CDN:
- WebSocket поддержка должна быть включена (Cloudflare: `Network → WebSockets: ON`)
- На Free-плане WebSocket работает, но **idle timeout = 100 секунд** — WS будет рваться при отсутствии трафика. Решение: agent уже шлёт ping каждые 30s (см. `agent/internal/websocket/client.go`), это удерживает соединение.
- Cloudflare Proxy режим (orange cloud) **поддерживает WSS** — менять не нужно.
- **gRPC / HTTP/3 / "Rocket Loader"** — НЕ используй для analyzer.example.com, они ломают WebSocket.

#### Проверка после настройки proxy

```bash
# 1. DNS резолвится?
dig +short analyzer.example.com

# 2. TCP открыт на 443?
nc -zv analyzer.example.com 443

# 3. TLS handshake работает?
echo | openssl s_client -servername analyzer.example.com -connect analyzer.example.com:443 2>/dev/null | grep -E "subject=|issuer="

# 4. /health отвечает 200?
curl -fsS https://analyzer.example.com/health

# 5. WebSocket Upgrade проходит? (HTTP 101 Switching Protocols)
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  https://analyzer.example.com/ws
```

В шаге 5 ожидаемый ответ:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: ...
```

Если ты видишь `200 OK`, `404 Not Found` или `400 Bad Request` — proxy не настроен на WS Upgrade. См. таблицу troubleshooting в Части 5.

#### Установить websocat для дополнительной проверки

```bash
# На любой машине с сетевым доступом
cargo install websocat                          # если есть Rust
# или
sudo curl -fsSL -o /usr/local/bin/websocat \
  https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl
sudo chmod +x /usr/local/bin/websocat

# Тест с правильным AGENT_TOKEN (из server .env)
websocat -H="Authorization: Bearer $AGENT_TOKEN" wss://analyzer.example.com/ws
```

Если соединение остаётся открытым — proxy настроен правильно. Закроется сразу с `403` — токен неверный.

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
cd /opt/xray-analyzer
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

sudo docker compose build analyzer-server
sudo docker compose up -d analyzer-server
```

Postgres / Redis обычно не нужно перезапускать. Если есть schema миграции (новые таблицы) — analyzer-server применит их сам на старте.

### Агенты

На каждой ноде:

```bash
cd /opt/xray-analyzer
sudo git pull origin main

sudo docker compose -f docker-compose.agent.yml build
sudo docker compose -f docker-compose.agent.yml up -d --force-recreate
```

Раскатывай по одной с проверкой `nodes_connected`.

---

## Часть 5 — Что-то сломалось

### Агент не подключается (WebSocket failures)

**Это частая проблема. Большинство случаев = неправильно настроенный reverse-proxy (см. Часть 1, Шаг 4) или неверный AUTH_TOKEN.**

Сначала смотри логи агента:

```bash
# На агентной ноде
docker compose -f /opt/xray-analyzer/docker-compose.agent.yml logs --tail 50 xray-log-agent
```

#### Таблица типичных ошибок

| Что в логах агента | Причина | Куда смотреть |
|---|---|---|
| `websocket: bad handshake` | Server вернул не 101. Чаще всего proxy не пропускает Upgrade headers | Часть 1 Шаг 4 → проверь nginx Upgrade/Connection headers; для Cloudflare — WebSockets включены? |
| `403 Forbidden` | AUTH_TOKEN не совпадает с AGENT_TOKEN на сервере | На сервере: `grep AGENT_TOKEN /opt/xray-analyzer/.env`, на агенте: `grep AUTH_TOKEN /opt/xray-analyzer/.env`. Должны быть одинаковыми. |
| `404 Not Found` | proxy не роутит `/ws` куда нужно | nginx: проверь `location /ws { proxy_pass http://127.0.0.1:8237; }` |
| `400 Bad Request` | proxy буферизует или ломает Upgrade | nginx: `proxy_buffering off`, `proxy_http_version 1.1` |
| `tls: failed to verify certificate` | self-signed cert / wrong domain | `openssl s_client -connect <server>:443` — посмотреть кто issuer. Если самоподписанный: нужен Let's Encrypt (через certbot или Caddy auto-HTTPS) |
| `dial tcp: lookup ... no such host` | DNS не резолвится | `dig +short analyzer.example.com` на ноде. Если пусто — A-запись не настроена |
| `connection refused` | server не слушает на этом порту | На сервере: `ss -tlnp \| grep 8237` — должен быть LISTEN. Проверь `docker ps` — analyzer-server up? |
| `i/o timeout` / `connection reset` | firewall блокирует или idle timeout слишком короткий | Server: `ufw status` / `iptables -L`. Cloudflare Free — idle timeout 100s, agent ping каждые 30s должен спасать |
| `no such file: /var/log/remnanode/access.log` | xray не пишет access log | См. Часть 2 Шаг 1 (config profile + volume mount) |
| `i/o timeout` после `Connected` | proxy_read_timeout слишком короткий | nginx: `proxy_read_timeout 86400s;` обязательно |

#### Пошаговая проверка с агентной ноды

Запускай команды НА НОДЕ (не на сервере):

```bash
# 1. DNS резолвится?
dig +short analyzer.example.com
# Должен вернуть IP. Пусто → DNS не настроен.

# 2. TCP открыт на 443? (или 80 если без TLS)
nc -zv analyzer.example.com 443
# "succeeded" = порт открыт. "Connection refused" / "timed out" = firewall или server down.

# 3. TLS handshake работает?
echo | openssl s_client -servername analyzer.example.com -connect analyzer.example.com:443 2>&1 | grep -E "subject=|verify return code"
# Ожидаем "verify return code: 0 (ok)". 18 (self signed) / 21 = сертификат проблемный.

# 4. /health отвечает 200?
curl -fsS https://analyzer.example.com/health
# 200 / "ok" = backend жив. 502 / 504 = proxy не достучался до backend. 404 = proxy не настроен.

# 5. WebSocket handshake проходит?
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  https://analyzer.example.com/ws
# Ожидаем "HTTP/1.1 101 Switching Protocols". Любое другое = proxy/server проблема.

# 6. С токеном (полная имитация агента, нужен websocat):
websocat -H="Authorization: Bearer $AGENT_TOKEN_FROM_SERVER" wss://analyzer.example.com/ws
# "Connected" и виcит = всё работает. "403" = токен неверный.
```

#### Если на шаге 4 вернулось `502 Bad Gateway`

Backend не отвечает — на сервере проверь:

```bash
docker ps --filter name=xray-log-analyzer --format "{{.Status}}"
# Должно быть "Up X (healthy)". Если "unhealthy" или нет — рестартнуть:
cd /opt/xray-analyzer && docker compose restart analyzer-server

curl -fsS http://localhost:8237/health
# Если 200 локально, а через домен 502 → proxy промахивается с upstream-адресом.
```

#### Если на шаге 5 возвращается `200 OK` вместо `101`

Proxy не пробрасывает Upgrade headers. Самое частое:
- **nginx**: забыли `proxy_http_version 1.1` или `proxy_set_header Upgrade $http_upgrade`
- **Cloudflare**: WebSockets выключены в Network settings, или включён "Rocket Loader"
- **HAProxy**: нужен `option http-server-close` + `timeout tunnel 24h` для backend

#### Логи на сервере

Параллельно смотри что видит сервер:

```bash
# На сервере
docker logs --since 2m xray-log-analyzer 2>&1 | grep -iE "agent|connect|ws"
```

Ожидаемое при подключении агента: строчка вида `agent connected: node_id=germany-1` или подобная. Если в логах ничего — request до сервера не доходит, проблема на уровне proxy/network.

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
cd /opt/xray-analyzer
sudo docker compose down -v       # -v убивает Postgres volume — все данные
sudo rm -rf /opt/xray-analyzer
```

### Удаление агента с ноды

```bash
cd /opt/xray-analyzer
sudo docker compose -f docker-compose.agent.yml down
sudo rm -rf /opt/xray-analyzer
sudo rm /etc/logrotate.d/remnanode
```

---

## Дальше

- [README.md](./README.md) — общий обзор и архитектура
- [docs/](../docs/) — design specs, plans, ADR
- Issues: https://github.com/qwertyhq/xray-analyzer/issues
