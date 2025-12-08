# CI/CD Setup Guide

## Как работает автоматический деплой

1. **Push в main** → GitHub Actions запускает workflow
2. **Build** → Собирается Docker образ и пушится в GitHub Container Registry
3. **Deploy** → SSH на сервер, pull нового образа, перезапуск контейнера
4. **Health Check** → Проверка что сервис работает (60 секунд)
5. **Rollback** → Если health check не прошёл, откатывается на предыдущую версию
6. **Уведомление** → Telegram сообщение о результате

## Настройка GitHub Secrets

В репозитории: **Settings → Secrets and variables → Actions**

### Обязательные секреты:

| Secret | Описание | Пример |
|--------|----------|--------|
| `SERVER_HOST` | IP или домен сервера | `123.45.67.89` |
| `SERVER_USER` | SSH пользователь | `root` или `deploy` |
| `SERVER_SSH_KEY` | Приватный SSH ключ | Содержимое `~/.ssh/id_rsa` |
| `DEPLOY_PATH` | Путь к docker-compose.yml на сервере | `/opt/xray/log-analyzer` |

### Опциональные (для Telegram уведомлений):

| Secret | Описание |
|--------|----------|
| `TELEGRAM_TOKEN` | Токен бота от @BotFather |
| `TELEGRAM_CHAT_ID` | ID чата для уведомлений |

## Настройка сервера

### 1. Создайте SSH ключ для деплоя:

```bash
ssh-keygen -t ed25519 -C "github-deploy" -f ~/.ssh/github_deploy
```

### 2. Добавьте публичный ключ на сервер:

```bash
cat ~/.ssh/github_deploy.pub >> ~/.ssh/authorized_keys
```

### 3. Приватный ключ добавьте в GitHub Secrets как `SERVER_SSH_KEY`

### 4. Залогиньтесь в GitHub Container Registry на сервере:

```bash
# Создайте Personal Access Token на GitHub с правом read:packages
# Settings → Developer settings → Personal access tokens → Tokens (classic)

echo "YOUR_GITHUB_TOKEN" | docker login ghcr.io -u YOUR_USERNAME --password-stdin
```

### 5. Создайте директорию и скопируйте docker-compose:

```bash
mkdir -p /opt/xray/log-analyzer
cd /opt/xray/log-analyzer
# Скопируйте docker-compose.yml и .env файлы
```

## Получение Chat ID для Telegram

1. Напишите боту `/start`
2. Откройте: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Найдите `"chat":{"id":123456789}` — это ваш Chat ID

## Ручной деплой

Если нужно задеплоить без пуша:

```bash
# На сервере
cd /opt/xray/log-analyzer
docker compose pull
docker compose up -d
```

## Просмотр логов

```bash
# GitHub Actions
# Перейдите в Actions → последний workflow run

# На сервере
docker compose logs -f analyzer-server
```

## Rollback вручную

```bash
# Откатиться на backup версию
docker tag ghcr.io/qwertyhq/xray/log-analyzer:backup ghcr.io/qwertyhq/xray/log-analyzer:latest
docker compose up -d --force-recreate analyzer-server
```
