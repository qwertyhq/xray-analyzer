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
- **DNS**: A-запись `analyzer.example.com` → IP сервера (см. шаг 1.2)

### Шаг 1. Подготовка сервера

#### 1.1 Обновление системы и базовые тулзы

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ca-certificates openssl dnsutils
```

#### 1.2 DNS — настрой ДО установки Caddy/nginx

Caddy при первом старте получает Let's Encrypt сертификат через ACME challenge. Для этого DNS должен резолвиться **до** первого старта Caddy.

**В панели твоего DNS-провайдера** (Cloudflare, Hetzner DNS, Route53, ...) создай:

```
Type:  A
Name:  analyzer  (или analyzer.example.com — зависит от UI провайдера)
Value: <публичный IP твоего сервера>
TTL:   автоматический / 60
```

Подожди 1-5 минут на пропагацию, проверь:

```bash
# С твоего сервера
dig +short analyzer.example.com
# Должен вернуть IP сервера. Пусто или другой IP — DNS не пропагнулся.

# Альтернативно — с любой машины
nslookup analyzer.example.com 1.1.1.1
```

⚠️ Если используешь **Cloudflare с прокси (orange cloud)** — выключи прокси на этой A-записи перед первым запуском Caddy (LE challenge не пройдёт через CF-прокси). После выпуска сертификата прокси можно включить обратно.

#### 1.3 Firewall — открой порты

```bash
# Если ufw активен (на Ubuntu по умолчанию)
sudo ufw status                                   # проверка состояния
sudo ufw allow 80/tcp comment 'HTTP / ACME'
sudo ufw allow 443/tcp comment 'HTTPS analyzer'
sudo ufw allow 22/tcp comment 'SSH'              # на всякий, чтобы сам себя не запер
sudo ufw status numbered

# Если используешь iptables напрямую
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

#### 1.4 Проверь что порты 8237 и 3925 свободны

Контейнеры будут слушать на этих портах локально:

```bash
sudo ss -tlnp | grep -E ':(8237|3925) '
```

Пусто = всё ок. Если что-то висит — найди и останови, иначе compose не сможет занять порты.

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

**Установка Caddy с нуля (Ubuntu/Debian):**

```bash
# 1. Добавь репо Caddy
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  sudo tee /etc/apt/sources.list.d/caddy-stable.list

# 2. Установка
sudo apt update && sudo apt install -y caddy

# 3. Открой firewall
sudo ufw allow 80/tcp comment 'HTTP for Caddy ACME challenge'
sudo ufw allow 443/tcp comment 'HTTPS analyzer'

# 4. Запиши Caddyfile (замени analyzer.example.com на свой домен)
sudo tee /etc/caddy/Caddyfile > /dev/null <<'EOF'
analyzer.example.com {
    # /ws*, /api/* и /health → Go-backend
    @backend path /ws* /api/* /health
    reverse_proxy @backend localhost:8237

    # Всё остальное → Next.js UI
    reverse_proxy localhost:3925
}
EOF

# 5. Проверка синтаксиса + reload
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo systemctl enable caddy

# 6. Проверь что слушает
sudo ss -tlnp | grep ':\(80\|443\) '
```

Caddy автоматически получит Let's Encrypt сертификат при первом запросе (если DNS уже указывает на сервер). Ничего дополнительно настраивать для TLS не нужно.

Проверь логи если что-то не так:
```bash
sudo journalctl -u caddy -n 50 --no-pager
```

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

#### Первичная загрузка дашборда

Открой `https://analyzer.example.com` в браузере. Будет login-форма — **введи туда `API_TOKEN`** (его значение из `/opt/xray-analyzer/.env`, поле `API_TOKEN=...`). Это твой "пароль" в дашборд, отдельной системы пользователей нет.

Получить значение:

```bash
grep '^API_TOKEN=' /opt/xray-analyzer/.env | cut -d= -f2
```

⚠️ **Первые 1-3 минуты после первого старта** дашборд может показывать неполные/нулевые данные:
- Threat-intel feeds грузят 1.5M+ indicators (ads/malware/casino/social/tor) — занимает 30-90 сек
- Remnawave sync стартует с задержкой `REMNAWAVE_SYNC_INTERVAL` (default 1m)
- Партиции для сегодня создаются при старте partition manager

Это нормально. Подожди 2-3 минуты, обнови страницу. В логах сервера увидишь:

```bash
docker logs --since 5m xray-log-analyzer 2>&1 | grep -E "threatintel|partition|remnawave"
```

Должны быть строки вида `threatintel: loaded 1634005 indicators`, `partition manager: started`, `remnawave: synced N users`.

#### Если Caddy не выдаёт сертификат

```bash
sudo journalctl -u caddy -n 50 --no-pager | grep -iE "error|certificate|acme"
```

Типичные причины:

| Что в логах | Причина | Фикс |
|---|---|---|
| `connection refused: 80` | Порт 80 закрыт извне (firewall / провайдер) | Проверь что 80 открыт в ufw + у провайдера |
| `no such host` / `NXDOMAIN` | DNS не резолвится / не пропагнулся | `dig +short analyzer.example.com` — должен вернуть IP сервера |
| `rate limited` | LE rate limit (5 сертификатов/неделя на домен) | Подожди или используй staging: добавь `acme_ca https://acme-staging-v02.api.letsencrypt.org/directory` в Caddyfile (получит untrusted cert) |
| `redirected to /cdn-cgi/...` | Cloudflare proxy (orange cloud) | Выключи CF-прокси на этой A-записи на время выпуска сертификата |

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

⚠️ **Backup на ту же машину = не backup.** Если сервер умрёт — потеряешь всё. Настрой syncing на отдельный storage (rsync на S3/B2, Backblaze, Hetzner Storage Box):

```bash
# Пример с rclone к S3-совместимому storage
sudo apt install -y rclone
rclone config                  # настрой remote один раз

# Добавь в crontab после pg_dump:
# 30 2 * * * rclone copy /opt/xray-analyzer/backups remote:analyzer-backups/$(hostname) --max-age 7d
```

#### Восстановление из backup на новом сервере

Если основной сервер умер и нужно поднять analyzer на новой машине:

```bash
# 1. На новом сервере — стандартная установка (Часть 1, Шаги 1-4)
git clone https://github.com/qwertyhq/xray-analyzer.git /opt/xray-analyzer
sudo bash /opt/xray-analyzer/scripts/install-server.sh
# (запомни новые tokens — их подменишь старыми ниже!)

# 2. Останови analyzer-server, чтобы не писал поверх восстановления
cd /opt/xray-analyzer
docker compose stop analyzer-server

# 3. Скопируй backup-файл на новый сервер
# (с резерва или старого сервера)
scp pg-backup-YYYYMMDD.dump root@<new-server>:/tmp/

# 4. Восстанови БД
docker exec -i analyzer-postgres pg_restore -U xray_analyzer -d xray_analyzer --clean --if-exists < /tmp/pg-backup-YYYYMMDD.dump

# 5. Восстанови старый .env (или хотя бы старые токены)
# Иначе агенты на нодах не подключатся (AGENT_TOKEN изменится)
sudo nano /opt/xray-analyzer/.env

# 6. Запусти сервер обратно
docker compose up -d analyzer-server
```

После восстановления:
- Если IP сервера сменился — обнови DNS A-запись
- Если **AGENT_TOKEN сменился** — на каждой ноде обновить `/opt/xray-analyzer/.env` и `docker compose -f docker-compose.agent.yml restart`

---

## Часть 2 — Агенты на VPN-нодах

Запускается на **каждой** Xray-ноде, которая должна слать access logs в analyzer.

### Требования

- Docker уже работает (на Remnawave-нодах он есть)
- Xray пишет access log (по умолчанию `/var/log/remnanode/access.log` для Remnawave-нод; для vanilla Xray путь другой — см. ниже)
- **NTP** (system clock sync) — обязательно если используешь bridge correlation (она работает в окне ±15s, расхождение времени между нодами ломает атрибуцию). Проверка: `timedatectl` должен показать `System clock synchronized: yes`. Если нет — `sudo systemctl enable --now systemd-timesyncd` или `sudo apt install -y chrony`.

#### Если у тебя НЕ Remnawave-нода (чистый Xray)

Гайд написан в первую очередь под Remnawave (стандартный путь логов `/var/log/remnanode/`). Для vanilla Xray:

- Путь логов обычно `/var/log/xray/access.log` или `/var/log/xray-core/access.log` (зависит от пакета/способа установки)
- Запись логов настраивается в `/usr/local/etc/xray/config.json` через тот же `log` блок
- В `.env` агента поменяй `LOG_HOST_PATH=/var/log/xray` и `LOG_FILE_PATH=/var/log/xray/access.log`

Дальше всё аналогично Remnawave-флоу.

### Шаг 1. Настрой Xray на запись access log

#### 1.1 В Remnawave panel

Открой **Config Profiles** → выбери профиль конкретной ноды → в JSON добавь блок `log`:

```json
{
  "log": {
    "access":   "/var/log/remnanode/access.log",
    "error":    "/var/log/remnanode/error.log",
    "loglevel": "warning"
  },
  "inbounds": [...],
  "outbounds": [...]
}
```

Сохрани, **отправь конфиг на ноду** (кнопка Sync / Apply в panel).

#### 1.2 На ноде — проверь volume mount у remnanode

```bash
# Подключись к ноде по SSH, проверь docker-compose remnanode
ssh root@<node-ip>
cd /opt/remnanode    # или где у тебя стоит remnanode

# Посмотри docker-compose.yml — должен быть volume на /var/log/remnanode
grep -A 5 'volumes:' docker-compose.yml
```

Если volume отсутствует или закомментирован — добавь:

```bash
sudo nano docker-compose.yml
```

```yaml
services:
  remnanode:
    # ...existing config
    volumes:
      - /var/log/remnanode:/var/log/remnanode    # <— добавь эту строку
```

Создай директорию (если её нет) и перезапусти remnanode:

```bash
sudo mkdir -p /var/log/remnanode
sudo chmod 755 /var/log/remnanode
docker compose up -d --force-recreate remnanode
```

#### 1.3 Проверка что xray пишет access.log

Подожди 30-60 секунд (нужно реальное соединение через ноду), потом:

```bash
# Файл существует и не пустой?
ls -la /var/log/remnanode/access.log

# Свежие записи появляются?
tail -f /var/log/remnanode/access.log     # Ctrl+C через 5-10 секунд
```

Должны видеть строки вида:
```
2026/05/03 12:34:56 192.168.1.5:54321 accepted tcp:example.com:443 [vless-in -> direct] email: user-uuid
```

**Если файл пустой через минуту:**
- Конфиг не сохранился в panel — повтори шаг 1.1, проверь Sync
- xray не перезапустился с новым конфигом: `docker compose restart remnanode`
- Loglevel слишком высокий: убедись что `"loglevel": "warning"` или `"info"`
- Volume не смонтирован: `docker exec remnanode ls -la /var/log/remnanode/` — должна быть та же директория что на хосте

### Шаг 2. Установка агента

Есть два варианта установки. Делают одно и то же — выбирай тот что удобнее.

| | Что делает | Когда выбрать |
|---|---|---|
| **Вариант А** — автоскрипт | Один curl-bash, скрипт делает всё | Стандартная установка, доверяешь репо |
| **Вариант Б** — пошагово вручную | Те же действия, но каждая команда видна | Хочешь аудит каждого шага / нет sudo / встроишь в свой Ansible / Terraform |

Оба варианта требуют интернет на ноде (Docker pull, git clone, и т.д.).

#### Получи AGENT_TOKEN с сервера (понадобится для обоих вариантов)

На **сервере** (где стоит analyzer):

```bash
grep '^AGENT_TOKEN=' /opt/xray-analyzer/.env | cut -d= -f2
```

Скопируй вывод — это длинная hex-строка типа `e9b8e8b0cb4aa2bb1d78a16955186ed97dbe6332ec3c8ee2`. **Один и тот же** AGENT_TOKEN используется на всех нодах (это server-side токен который сервер ожидает от агентов).

#### Вариант А — Автоматически через скрипт (рекомендуется)

Один curl-and-bash. На ноде, замени значения переменных:

```bash
curl -fsSL https://raw.githubusercontent.com/qwertyhq/xray-analyzer/main/scripts/install-agent.sh | \
  sudo SERVER_URL="wss://analyzer.example.com/ws" \
       AUTH_TOKEN="ВСТАВЬ_AGENT_TOKEN_ИЗ_SERVER_ENV" \
       NODE_ID="germany-1" \
       bash
```

`NODE_ID` должен быть **уникальным на каждой ноде** (`germany-1`, `est-1`, `poland-1`, `ru-bridge`, ...). Скрипт автоматически:
- Проверит ОС, поставит Docker если нет
- Клонирует репо в `/opt/xray-analyzer`
- Создаст `.env` для агента (mode 600)
- Настроит logrotate для `/var/log/remnanode/*.log` (ротация 50M × 5)
- Соберёт image, поднимет контейнер
- Через 8 секунд проверит что подключение к серверу работает и расскажет об ошибке если что-то не так

#### Вариант Б — Вручную, шаг за шагом

Те же действия что делает скрипт, но видны явно — удобно если хочешь аудитить каждый шаг, встраивать в свой Ansible/Terraform, или разбираться что вообще происходит:

```bash
# 1. Поставь Docker если нет (Ubuntu/Debian)
if ! command -v docker >/dev/null; then
  sudo apt update
  sudo apt install -y ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$(. /etc/os-release && echo $ID)/gpg" | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo $ID) $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list
  sudo apt update
  sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# 2. Клонируй репо
sudo git clone https://github.com/qwertyhq/xray-analyzer.git /opt/xray-analyzer
cd /opt/xray-analyzer

# 3. Создай .env агента (замени значения)
sudo tee .env > /dev/null <<EOF
NODE_ID=germany-1
SERVER_URL=wss://analyzer.example.com/ws
AUTH_TOKEN=ВСТАВЬ_AGENT_TOKEN_ИЗ_SERVER
LOG_HOST_PATH=/var/log/remnanode
LOG_FILE_PATH=/var/log/remnanode/access.log
BATCH_SIZE=1000
BATCH_TIMEOUT=5s
ENABLE_COMPRESSION=true
EOF
sudo chmod 600 .env

# 4. Logrotate для access.log (без него файл разрастётся до GB)
sudo tee /etc/logrotate.d/remnanode > /dev/null <<'EOF'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    delaycompress
    notifempty
    missingok
    copytruncate
}
EOF

# 5. Билд + запуск агента
sudo docker compose -f docker-compose.agent.yml build xray-log-agent
sudo docker compose -f docker-compose.agent.yml up -d xray-log-agent

# 6. Проверь подключение через 10 секунд
sleep 10
sudo docker compose -f docker-compose.agent.yml logs --tail 30 xray-log-agent
```

В логах должно появиться `connected` или `websocket connection established`. Если ошибки — см. Часть 5 (Troubleshooting).

#### Полезные команды для управления агентом

```bash
cd /opt/xray-analyzer

# Логи в реальном времени
sudo docker compose -f docker-compose.agent.yml logs -f xray-log-agent

# Restart
sudo docker compose -f docker-compose.agent.yml restart xray-log-agent

# Stop
sudo docker compose -f docker-compose.agent.yml down

# Status
sudo docker compose -f docker-compose.agent.yml ps
```

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
