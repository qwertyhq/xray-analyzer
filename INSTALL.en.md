# Xray Log Analyzer — step-by-step install

**Languages:** [Русский](./INSTALL.md) · **English**

A full guide for a production deployment. Server + agents + reverse-proxy + integrations.

## What we're building

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

And on every Xray node:

```
xray-log-agent (docker)  →  WSS /ws  →  analyzer-server
       │
       ▼
/var/log/remnanode/access.log (read-only mount)
```

---

## Part 1 — Server

### Requirements

- **OS**: Ubuntu 22.04+ or Debian 12+
- **CPU**: 2 cores (4 recommended)
- **RAM**: 4 GB minimum, 8 GB recommended
- **Disk**: 20 GB free (15 GB for system + Postgres growth)
- **Network**: ports 80/443 open (or a reverse-proxy is already configured)
- **Domain**: one for the analyzer (e.g. `analyzer.example.com`)
- **DNS**: an `A` record `analyzer.example.com` → server IP (see step 1.2)

### Step 1. Prepare the server

#### 1.1 System update and base tooling

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ca-certificates openssl dnsutils
```

#### 1.2 DNS — set this up BEFORE installing Caddy/nginx

On first start, Caddy obtains a Let's Encrypt certificate through the ACME challenge. For that, DNS must resolve **before** the first Caddy start.

**In your DNS provider's panel** (Cloudflare, Hetzner DNS, Route53, ...) create:

```
Type:  A
Name:  analyzer  (or analyzer.example.com — depends on provider UI)
Value: <public IP of your server>
TTL:   automatic / 60
```

Wait 1–5 minutes for propagation, then verify:

```bash
# From your server
dig +short analyzer.example.com
# Should return the server's IP. Empty or a different IP — DNS hasn't propagated.

# Alternatively — from any machine
nslookup analyzer.example.com 1.1.1.1
```

⚠️ If you use **Cloudflare with proxy enabled (orange cloud)** — disable proxy on this A record before the first Caddy start (the LE challenge won't go through the CF proxy). You can re-enable the proxy after the certificate has been issued.

#### 1.3 Firewall — open the ports

```bash
# If ufw is active (default on Ubuntu)
sudo ufw status                                   # check status
sudo ufw allow 80/tcp comment 'HTTP / ACME'
sudo ufw allow 443/tcp comment 'HTTPS analyzer'
sudo ufw allow 22/tcp comment 'SSH'              # just in case, so you don't lock yourself out
sudo ufw status numbered

# If you use iptables directly
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

#### 1.4 Make sure ports 8237 and 3925 are free

Containers will listen on these ports locally:

```bash
sudo ss -tlnp | grep -E ':(8237|3925) '
```

Empty = all good. If something is bound — find and stop it, otherwise compose won't be able to take the ports.

### Step 2. Install via the script (recommended)

```bash
git clone https://github.com/qwertyhq/xray-analyzer.git /opt/xray-analyzer
sudo bash /opt/xray-analyzer/scripts/install-server.sh
```

The script:
- Installs Docker + docker-compose-plugin
- Generates `.env` with random tokens (`API_TOKEN`, `AGENT_TOKEN`, `POSTGRES_PASSWORD`)
- Builds the server image (Go + Next.js, ~3–5 minutes)
- Brings up the stack and waits for healthchecks
- **Prints endpoints + tokens** — save them

After it finishes you have:
- `analyzer-server` listening on `:8237` (API+WS) and `:3925` (UI)
- Postgres + Redis running in Docker
- `/opt/xray-analyzer/.env` with tokens

### Step 3. Fill in Remnawave + Telegram settings

```bash
sudo nano /opt/xray-analyzer/.env
```

The minimum you need to set:

```bash
# Remnawave (get an API token from panel → Settings → API)
REMNAWAVE_ENABLED=true
REMNAWAVE_URL=https://panel.example.com
REMNAWAVE_API_TOKEN=eyJhbGc...

# Telegram alerts (create a bot via @BotFather, look up chat_id)
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=1234567890:AAA...
TELEGRAM_CHAT_ID=-100...

# Optional — link agent NODE_ID to Remnawave node names
NODE_REMNA_MAP=germany-1=Germany 2,est-1=Estonia,poland-1=Poland
```

After edits, apply:

```bash
cd /opt/xray-analyzer
docker compose up -d
```

### Step 4. Reverse-proxy (pay special attention to WebSocket)

The script does **not** configure Caddy/nginx — that's specific to your setup. **WebSocket is the most common failure point at this step**, so it's important to get it right on the first try.

#### What the proxy must forward:

| Path | Backend | Notes |
|---|---|---|
| `/ws*` | `localhost:8237` | **WebSocket** — needs Upgrade/Connection headers, long read timeout, no buffering |
| `/api/*` | `localhost:8237` | Plain HTTP REST |
| `/health` | `localhost:8237` | Healthcheck |
| `/` (everything else) | `localhost:3925` | Next.js UI |

#### Caddy (recommended — auto-HTTPS, simple syntax, WS works out of the box)

**Installing Caddy from scratch (Ubuntu/Debian):**

```bash
# 1. Add the Caddy repo
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  sudo tee /etc/apt/sources.list.d/caddy-stable.list

# 2. Install
sudo apt update && sudo apt install -y caddy

# 3. Open firewall
sudo ufw allow 80/tcp comment 'HTTP for Caddy ACME challenge'
sudo ufw allow 443/tcp comment 'HTTPS analyzer'

# 4. Write the Caddyfile (replace analyzer.example.com with your domain)
sudo tee /etc/caddy/Caddyfile > /dev/null <<'EOF'
analyzer.example.com {
    # /ws*, /api/* and /health → Go backend
    @backend path /ws* /api/* /health
    reverse_proxy @backend localhost:8237

    # Everything else → Next.js UI
    reverse_proxy localhost:3925
}
EOF

# 5. Syntax check + reload
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo systemctl enable caddy

# 6. Verify it's listening
sudo ss -tlnp | grep ':\(80\|443\) '
```

Caddy will automatically obtain a Let's Encrypt certificate on the first request (provided DNS already points to the server). No extra TLS configuration is needed.

Check logs if anything is off:
```bash
sudo journalctl -u caddy -n 50 --no-pager
```

#### nginx (explicit WS headers required)

`/etc/nginx/sites-available/analyzer.example.com`:

```nginx
# WebSocket Upgrade map — required for WS
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name analyzer.example.com;

    # SSL — if using certbot:
    #   sudo certbot --nginx -d analyzer.example.com
    ssl_certificate     /etc/letsencrypt/live/analyzer.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/analyzer.example.com/privkey.pem;

    # WebSocket — critical settings
    location /ws {
        proxy_pass http://127.0.0.1:8237;
        proxy_http_version 1.1;                       # REQUIRED — HTTP/1.1 for Upgrade
        proxy_set_header Upgrade $http_upgrade;       # pass through Upgrade: websocket
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WS — long-lived session, disable buffering + large timeout
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 86400s;                    # 24h — otherwise WS drops on idle
        proxy_send_timeout 86400s;
    }

    # Plain API endpoints
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
        proxy_set_header Upgrade $http_upgrade;       # Next dev server uses HMR-WS
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
sudo nginx -t                  # syntax check
sudo systemctl reload nginx
```

#### Apache (if you really must)

In `httpd.conf` or a vhost config:

```apache
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so

<VirtualHost *:443>
    ServerName analyzer.example.com

    SSLEngine on
    SSLCertificateFile      /etc/letsencrypt/live/analyzer.example.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/analyzer.example.com/privkey.pem

    # WebSocket — dedicated directive
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

#### Cloudflare / other edge proxies

If a **Cloudflare** or another CDN sits in front of your nginx/Caddy:
- WebSocket support must be enabled (Cloudflare: `Network → WebSockets: ON`)
- On the Free plan WebSocket works, but **idle timeout = 100 seconds** — WS will drop when there's no traffic. Mitigation: the agent already sends a ping every 30s (see `agent/internal/websocket/client.go`), which keeps the connection alive.
- Cloudflare Proxy mode (orange cloud) **supports WSS** — no need to change it.
- **gRPC / HTTP/3 / "Rocket Loader"** — do NOT enable these for analyzer.example.com, they break WebSocket.

#### Verification after proxy setup

```bash
# 1. DNS resolves?
dig +short analyzer.example.com

# 2. TCP reachable on 443?
nc -zv analyzer.example.com 443

# 3. TLS handshake works?
echo | openssl s_client -servername analyzer.example.com -connect analyzer.example.com:443 2>/dev/null | grep -E "subject=|issuer="

# 4. /health returns 200?
curl -fsS https://analyzer.example.com/health

# 5. WebSocket Upgrade succeeds? (HTTP 101 Switching Protocols)
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  https://analyzer.example.com/ws
```

Expected response for step 5:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: ...
```

If you see `200 OK`, `404 Not Found` or `400 Bad Request` — the proxy isn't configured for WS Upgrade. See the troubleshooting table in Part 5.

#### Install websocat for an extra check

```bash
# On any machine with network access
cargo install websocat                          # if you have Rust
# or
sudo curl -fsSL -o /usr/local/bin/websocat \
  https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl
sudo chmod +x /usr/local/bin/websocat

# Test with the correct AGENT_TOKEN (from server .env)
websocat -H="Authorization: Bearer $AGENT_TOKEN" wss://analyzer.example.com/ws
```

If the connection stays open — the proxy is configured correctly. An immediate close with `403` — the token is wrong.

### Step 5. Verify

```bash
# Health endpoint (should return 200 OK)
curl -fsS https://analyzer.example.com/health

# Stats endpoint (needs API_TOKEN from .env)
source /opt/xray-analyzer/.env
curl -sS -H "Authorization: Bearer $API_TOKEN" \
  https://analyzer.example.com/api/stats | jq
```

#### First dashboard load

Open `https://analyzer.example.com` in a browser. You'll see a login form — **enter your `API_TOKEN`** (the value from `/opt/xray-analyzer/.env`, the `API_TOKEN=...` field). This is your "password" for the dashboard; there's no separate user system.

To grab the value:

```bash
grep '^API_TOKEN=' /opt/xray-analyzer/.env | cut -d= -f2
```

⚠️ **For the first 1–3 minutes after the first start**, the dashboard may show incomplete / zero data:
- Threat-intel feeds load 1.5M+ indicators (ads/malware/casino/social/tor) — takes 30–90 sec
- Remnawave sync starts after a `REMNAWAVE_SYNC_INTERVAL` delay (default 1m)
- Today's partitions are created when the partition manager starts

That's normal. Wait 2–3 minutes and refresh. In the server logs you'll see:

```bash
docker logs --since 5m xray-log-analyzer 2>&1 | grep -E "threatintel|partition|remnawave"
```

You should see lines like `threatintel: loaded 1634005 indicators`, `partition manager: started`, `remnawave: synced N users`.

#### If Caddy doesn't issue a certificate

```bash
sudo journalctl -u caddy -n 50 --no-pager | grep -iE "error|certificate|acme"
```

Typical causes:

| Log line | Cause | Fix |
|---|---|---|
| `connection refused: 80` | Port 80 closed from outside (firewall / ISP) | Verify 80 is open in ufw + at your provider |
| `no such host` / `NXDOMAIN` | DNS doesn't resolve / hasn't propagated | `dig +short analyzer.example.com` — should return the server's IP |
| `rate limited` | LE rate limit (5 certificates/week per domain) | Wait, or use staging: add `acme_ca https://acme-staging-v02.api.letsencrypt.org/directory` to the Caddyfile (it will issue an untrusted cert) |
| `redirected to /cdn-cgi/...` | Cloudflare proxy (orange cloud) | Turn off the CF proxy on this A record while the certificate is issued |

### Step 6. Backup (recommended via cron)

```bash
sudo mkdir -p /opt/xray-analyzer/backups
sudo crontab -e
```

Add:

```cron
# Daily pg_dump at 2:00 AM, 7-day retention
0 2 * * * docker exec analyzer-postgres pg_dump -U xray_analyzer -Fc xray_analyzer > /opt/xray-analyzer/backups/pg-$(date +\%Y\%m\%d).dump 2>&1 ; find /opt/xray-analyzer/backups -name "pg-*.dump" -mtime +7 -delete
```

⚠️ **A backup on the same machine is not a backup.** If the server dies, you lose everything. Configure syncing to separate storage (rsync to S3/B2, Backblaze, Hetzner Storage Box):

```bash
# Example with rclone to S3-compatible storage
sudo apt install -y rclone
rclone config                  # configure the remote once

# Add to crontab after pg_dump:
# 30 2 * * * rclone copy /opt/xray-analyzer/backups remote:analyzer-backups/$(hostname) --max-age 7d
```

#### Restoring from a backup on a new server

If the main server has died and you need to bring the analyzer up on a fresh machine:

```bash
# 1. On the new server — the standard install (Part 1, Steps 1-4)
git clone https://github.com/qwertyhq/xray-analyzer.git /opt/xray-analyzer
sudo bash /opt/xray-analyzer/scripts/install-server.sh
# (remember the new tokens — you'll swap them with the old ones below!)

# 2. Stop analyzer-server so it doesn't write during restore
cd /opt/xray-analyzer
docker compose stop analyzer-server

# 3. Copy the backup file to the new server
# (from your offsite copy or the old server)
scp pg-backup-YYYYMMDD.dump root@<new-server>:/tmp/

# 4. Restore the DB
docker exec -i analyzer-postgres pg_restore -U xray_analyzer -d xray_analyzer --clean --if-exists < /tmp/pg-backup-YYYYMMDD.dump

# 5. Restore the old .env (or at least the old tokens)
# Otherwise node agents won't connect (AGENT_TOKEN will have changed)
sudo nano /opt/xray-analyzer/.env

# 6. Bring the server back up
docker compose up -d analyzer-server
```

After restore:
- If the server's IP changed — update the DNS A record
- If the **AGENT_TOKEN changed** — on every node, update `/opt/xray-analyzer/.env` and `docker compose -f docker-compose.agent.yml restart`

---

## Part 2 — Agents on the VPN nodes

Run on **every** Xray node that should ship access logs to the analyzer.

### Requirements

- Docker is already running (Remnawave nodes have it)
- Xray writes an access log (default `/var/log/remnanode/access.log` for Remnawave nodes; vanilla Xray uses a different path — see below)
- **NTP** (system clock sync) — recommended so log timestamps stay consistent across nodes. Check: `timedatectl` should show `System clock synchronized: yes`. If not — `sudo systemctl enable --now systemd-timesyncd` or `sudo apt install -y chrony`.

#### If you're NOT on a Remnawave node (plain Xray)

This guide is primarily written for Remnawave (standard log path `/var/log/remnanode/`). For vanilla Xray:

- Log path is usually `/var/log/xray/access.log` or `/var/log/xray-core/access.log` (depends on the package / install method)
- Logging is configured in `/usr/local/etc/xray/config.json` through the same `log` block
- In the agent `.env`, change `LOG_HOST_PATH=/var/log/xray` and `LOG_FILE_PATH=/var/log/xray/access.log`

Everything else mirrors the Remnawave flow.

### Step 1. Configure Xray to write the access log

#### 1.1 In the Remnawave panel

Open **Config Profiles** → pick the profile for this specific node → in the JSON add a `log` block:

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

Save and **push the config to the node** (Sync / Apply button in the panel).

#### 1.2 On the node — check the remnanode volume mount

```bash
# SSH into the node, look at the remnanode docker-compose
ssh root@<node-ip>
cd /opt/remnanode    # or wherever remnanode is installed

# Look at docker-compose.yml — there must be a volume on /var/log/remnanode
grep -A 5 'volumes:' docker-compose.yml
```

If the volume is missing or commented out — add it:

```bash
sudo nano docker-compose.yml
```

```yaml
services:
  remnanode:
    # ...existing config
    volumes:
      - /var/log/remnanode:/var/log/remnanode    # <— add this line
```

Create the directory (if it doesn't exist) and restart remnanode:

```bash
sudo mkdir -p /var/log/remnanode
sudo chmod 755 /var/log/remnanode
docker compose up -d --force-recreate remnanode
```

#### 1.3 Verify that xray is writing access.log

Wait 30–60 seconds (a real connection through the node is needed), then:

```bash
# File exists and is non-empty?
ls -la /var/log/remnanode/access.log

# Fresh entries appearing?
tail -f /var/log/remnanode/access.log     # Ctrl+C after 5–10 seconds
```

You should see lines like:
```
2026/05/03 12:34:56 192.168.1.5:54321 accepted tcp:example.com:443 [vless-in -> direct] email: user-uuid
```

**If the file is still empty after a minute:**
- The config wasn't saved in the panel — repeat step 1.1, check Sync
- xray didn't restart with the new config: `docker compose restart remnanode`
- Log level is too high: make sure it's `"loglevel": "warning"` or `"info"`
- Volume isn't mounted: `docker exec remnanode ls -la /var/log/remnanode/` — should show the same directory as on the host

### Step 2. Install the agent

There are two install options. They do the same thing — pick whichever is convenient.

| | What it does | When to pick |
|---|---|---|
| **Option A** — autoscript | A single curl-bash that does everything | Standard install, you trust the repo |
| **Option B** — step-by-step manual | The same actions, but every command is visible | You want to audit every step / no sudo / wire it into your Ansible / Terraform |

Both options require internet access on the node (Docker pull, git clone, etc.).

#### Get AGENT_TOKEN from the server (needed for both options)

On the **server** (where the analyzer runs):

```bash
grep '^AGENT_TOKEN=' /opt/xray-analyzer/.env | cut -d= -f2
```

Copy the output — it's a long hex string like `e9b8e8b0cb4aa2bb1d78a16955186ed97dbe6332ec3c8ee2`. **The same** AGENT_TOKEN is used on every node (it's the server-side token the server expects from agents).

#### Option A — Automatic, via script (recommended)

A single curl-and-bash. On the node, fill in the variable values:

```bash
curl -fsSL https://raw.githubusercontent.com/qwertyhq/xray-analyzer/main/scripts/install-agent.sh | \
  sudo SERVER_URL="wss://analyzer.example.com/ws" \
       AUTH_TOKEN="PASTE_AGENT_TOKEN_FROM_SERVER_ENV" \
       NODE_ID="germany-1" \
       bash
```

`NODE_ID` must be **unique on every node** (`germany-1`, `est-1`, `poland-1`, `finland-1`, ...). The script automatically:
- Checks the OS, installs Docker if missing
- Clones the repo into `/opt/xray-analyzer`
- Creates an agent `.env` (mode 600)
- Sets up logrotate for `/var/log/remnanode/*.log` (rotate 50M × 5)
- Builds the image, brings the container up
- After 8 seconds, verifies the connection to the server works and reports an error if anything is wrong

#### Option B — Manually, step by step

The same actions the script performs, but explicit — useful if you want to audit each step, wire it into your Ansible/Terraform, or just understand what's happening:

```bash
# 1. Install Docker if missing (Ubuntu/Debian)
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

# 2. Clone the repo
sudo git clone https://github.com/qwertyhq/xray-analyzer.git /opt/xray-analyzer
cd /opt/xray-analyzer

# 3. Create the agent .env (replace the values)
sudo tee .env > /dev/null <<EOF
NODE_ID=germany-1
SERVER_URL=wss://analyzer.example.com/ws
AUTH_TOKEN=PASTE_AGENT_TOKEN_FROM_SERVER
LOG_HOST_PATH=/var/log/remnanode
LOG_FILE_PATH=/var/log/remnanode/access.log
BATCH_SIZE=1000
BATCH_TIMEOUT=5s
ENABLE_COMPRESSION=true
EOF
sudo chmod 600 .env

# 4. Logrotate for access.log (without it the file will grow to GBs)
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

# 5. Build + launch the agent
sudo docker compose -f docker-compose.agent.yml build xray-log-agent
sudo docker compose -f docker-compose.agent.yml up -d xray-log-agent

# 6. Check the connection after 10 seconds
sleep 10
sudo docker compose -f docker-compose.agent.yml logs --tail 30 xray-log-agent
```

The logs should show `connected` or `websocket connection established`. If there are errors — see Part 5 (Troubleshooting).

#### Handy commands for managing the agent

```bash
cd /opt/xray-analyzer

# Live logs
sudo docker compose -f docker-compose.agent.yml logs -f xray-log-agent

# Restart
sudo docker compose -f docker-compose.agent.yml restart xray-log-agent

# Stop
sudo docker compose -f docker-compose.agent.yml down

# Status
sudo docker compose -f docker-compose.agent.yml ps
```

### Step 3. Verify on the server

```bash
# On the server, not the node
source /opt/xray-analyzer/.env
curl -sS -H "Authorization: Bearer $API_TOKEN" \
  https://analyzer.example.com/api/nodes | \
  jq '.[] | {node_id, is_connected, total_requests}'
```

Your node should show up with `is_connected: true`.

### Step 4. Repeat for every node

Roll out one node at a time, checking `nodes_connected` after each:

```bash
curl -sS -H "Authorization: Bearer $API_TOKEN" https://analyzer.example.com/api/stats | \
  jq '.nodes_connected'
```

The number should grow after every new agent connects.

---

## Part 3 — Optional integrations

### AI assistant (OpenAI-compatible)

Enables a built-in AI chat in the dashboard for queries like "find abusers in the last hour".

In the server `.env`:

```bash
# OpenAI
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini

# or Together AI
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://api.together.xyz/v1
OPENAI_MODEL=meta-llama/Llama-3.3-70B-Instruct-Turbo

# or OpenRouter
OPENAI_API_KEY=sk-or-...
OPENAI_BASE_URL=https://openrouter.ai/api/v1
OPENAI_MODEL=anthropic/claude-3.5-sonnet

# or local llama.cpp/vLLM
OPENAI_API_KEY=local
OPENAI_BASE_URL=http://localhost:8080/v1
OPENAI_MODEL=qwen2.5-72b
```

Restart:

```bash
cd /opt/xray-analyzer
docker compose up -d analyzer-server
```

### Mapbox (geo map in the dashboard)

Grab a free token: https://account.mapbox.com/access-tokens/

```bash
# In .env
NEXT_PUBLIC_MAPBOX_TOKEN=pk.eyJ1...
```

⚠️ This token is baked into the JS bundle, so you **must rebuild the UI**:

```bash
docker compose build analyzer-server
docker compose up -d analyzer-server
```

---

## Part 4 — Updating

### Server

```bash
cd /opt/xray-analyzer
sudo git pull origin main

sudo docker compose build analyzer-server
sudo docker compose up -d analyzer-server
```

Postgres / Redis usually don't need a restart. If there are schema migrations (new tables), analyzer-server applies them itself on startup.

### Agents

On every node:

```bash
cd /opt/xray-analyzer
sudo git pull origin main

sudo docker compose -f docker-compose.agent.yml build
sudo docker compose -f docker-compose.agent.yml up -d --force-recreate
```

Roll out one at a time, checking `nodes_connected`.

---

## Part 5 — Something broke

### Agent won't connect (WebSocket failures)

**This is a common issue. Most cases are a misconfigured reverse-proxy (see Part 1, Step 4) or an incorrect AUTH_TOKEN.**

First, look at the agent logs:

```bash
# On the agent node
docker compose -f /opt/xray-analyzer/docker-compose.agent.yml logs --tail 50 xray-log-agent
```

#### Common error table

| What's in the agent logs | Cause | Where to look |
|---|---|---|
| `websocket: bad handshake` | Server returned something other than 101. Most often the proxy isn't forwarding Upgrade headers | Part 1 Step 4 → verify nginx Upgrade/Connection headers; for Cloudflare — is WebSockets enabled? |
| `403 Forbidden` | AUTH_TOKEN doesn't match AGENT_TOKEN on the server | On the server: `grep AGENT_TOKEN /opt/xray-analyzer/.env`, on the agent: `grep AUTH_TOKEN /opt/xray-analyzer/.env`. They must match. |
| `404 Not Found` | The proxy isn't routing `/ws` correctly | nginx: check `location /ws { proxy_pass http://127.0.0.1:8237; }` |
| `400 Bad Request` | The proxy is buffering or breaking Upgrade | nginx: `proxy_buffering off`, `proxy_http_version 1.1` |
| `tls: failed to verify certificate` | self-signed cert / wrong domain | `openssl s_client -connect <server>:443` — see who the issuer is. If self-signed: you need Let's Encrypt (via certbot or Caddy auto-HTTPS) |
| `dial tcp: lookup ... no such host` | DNS doesn't resolve | `dig +short analyzer.example.com` from the node. Empty → no A record |
| `connection refused` | Server isn't listening on the port | On the server: `ss -tlnp \| grep 8237` — must be LISTEN. Check `docker ps` — is analyzer-server up? |
| `i/o timeout` / `connection reset` | Firewall is blocking or idle timeout is too short | Server: `ufw status` / `iptables -L`. Cloudflare Free — idle timeout 100s; agent pings every 30s should keep it alive |
| `no such file: /var/log/remnanode/access.log` | xray isn't writing the access log | See Part 2 Step 1 (config profile + volume mount) |
| `i/o timeout` after `Connected` | proxy_read_timeout is too short | nginx: `proxy_read_timeout 86400s;` is mandatory |

#### Step-by-step check from the agent node

Run these ON THE NODE (not on the server):

```bash
# 1. DNS resolves?
dig +short analyzer.example.com
# Should return the IP. Empty → DNS isn't set up.

# 2. TCP open on 443? (or 80 without TLS)
nc -zv analyzer.example.com 443
# "succeeded" = port open. "Connection refused" / "timed out" = firewall or server down.

# 3. TLS handshake works?
echo | openssl s_client -servername analyzer.example.com -connect analyzer.example.com:443 2>&1 | grep -E "subject=|verify return code"
# Expect "verify return code: 0 (ok)". 18 (self signed) / 21 = certificate problem.

# 4. /health returns 200?
curl -fsS https://analyzer.example.com/health
# 200 / "ok" = backend is alive. 502 / 504 = proxy can't reach the backend. 404 = proxy not configured.

# 5. WebSocket handshake succeeds?
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  https://analyzer.example.com/ws
# Expect "HTTP/1.1 101 Switching Protocols". Anything else = proxy/server issue.

# 6. With a token (full agent emulation, needs websocat):
websocat -H="Authorization: Bearer $AGENT_TOKEN_FROM_SERVER" wss://analyzer.example.com/ws
# "Connected" and hangs = everything works. "403" = wrong token.
```

#### If step 4 returns `502 Bad Gateway`

The backend isn't responding — on the server check:

```bash
docker ps --filter name=xray-log-analyzer --format "{{.Status}}"
# Should be "Up X (healthy)". If "unhealthy" or absent — restart:
cd /opt/xray-analyzer && docker compose restart analyzer-server

curl -fsS http://localhost:8237/health
# If 200 locally but 502 through the domain → the proxy has the wrong upstream address.
```

#### If step 5 returns `200 OK` instead of `101`

The proxy isn't forwarding Upgrade headers. The usual culprits:
- **nginx**: missing `proxy_http_version 1.1` or `proxy_set_header Upgrade $http_upgrade`
- **Cloudflare**: WebSockets disabled in Network settings, or "Rocket Loader" enabled
- **HAProxy**: needs `option http-server-close` + `timeout tunnel 24h` on the backend

#### Server-side logs

In parallel, look at what the server sees:

```bash
# On the server
docker logs --since 2m xray-log-analyzer 2>&1 | grep -iE "agent|connect|ws"
```

Expected on agent connect: a line like `agent connected: node_id=germany-1` or similar. If the logs show nothing — the request isn't reaching the server, the problem is at the proxy/network layer.

### Dashboard shows 0 users

`remna_users` hasn't synced yet. Wait 1–5 minutes after start, then check:

```bash
docker logs analyzer-server 2>&1 | grep -i remnawave | tail -5
```

If you see `remnawave: failed to sync` — verify `REMNAWAVE_URL` (full URL with https://) and `REMNAWAVE_API_TOKEN`.

### Postgres error `nodes_id_seq overflow` (smallint)

Unlikely after the v2 refactor — nodes are cached in memory. If it still happens:

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

If any hot table >25 GB — the partition manager isn't running; check `/health`:

```bash
curl https://analyzer.example.com/health
```

---

## Part 6 — Uninstall

### Full server removal

```bash
cd /opt/xray-analyzer
sudo docker compose down -v       # -v wipes the Postgres volume — all data
sudo rm -rf /opt/xray-analyzer
```

### Removing the agent from a node

```bash
cd /opt/xray-analyzer
sudo docker compose -f docker-compose.agent.yml down
sudo rm -rf /opt/xray-analyzer
sudo rm /etc/logrotate.d/remnanode
```

---

## Next

- [README.en.md](./README.en.md) — overview and architecture
- [docs/](../docs/) — design specs, plans, ADRs
- Issues: https://github.com/qwertyhq/xray-analyzer/issues
