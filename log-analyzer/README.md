# Xray Log Analyzer

Система анализа логов Xray/Remnanode в реальном времени с проверкой по черному списку и алертами в Telegram.

## Архитектура

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Node 1    │     │   Node 2    │     │   Node N    │
│  (Agent)    │     │  (Agent)    │     │  (Agent)    │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │    WebSocket + gzip (batches)        │
       └───────────────────┼───────────────────┘
                          │
                  ┌───────▼───────┐
                  │  Main Server  │
                  │  (Analyzer)   │
                  ├───────────────┤
                  │   SQLite DB   │
                  │  (aggregates) │
                  └───────┬───────┘
                          │
                  ┌───────▼───────┐
                  │   Telegram    │
                  │    Alerts     │
                  └───────────────┘
```

## Компоненты

### Agent (Worker Node)
- Читает access log Xray в реальном времени
- Парсит записи и собирает в батчи (1000 записей или 5 сек)
- Отправляет сжатые батчи на сервер через WebSocket
- Автоматическое переподключение при обрывах

### Server (Main Node)
- Принимает батчи от всех агентов
- Проверяет каждый запрос по черному списку
- Хранит агрегированную статистику (без сырых логов)
- Генерирует алерты при превышении порогов
- Отправляет алерты в Telegram
- REST API для статистики

## Быстрый старт

### 1. Запуск сервера

```bash
cd log-analyzer

# Скопируйте и настройте .env
cp .env.example .env
# Отредактируйте .env - добавьте токен Telegram бота

# Отредактируйте blacklist.txt - добавьте запрещенные домены

# Запустите сервер
docker-compose up -d
```

### 2. Запуск агента на каждой Xray ноде

```bash
# Скопируйте папку agent и docker-compose.agent.yml на ноду
scp -r agent docker-compose.agent.yml user@node:/opt/xray-agent/

# На ноде:
cd /opt/xray-agent

# Настройте переменные
export NODE_ID="node-moscow-1"  # Уникальное имя ноды
export SERVER_URL="ws://your-analyzer-server:8080/ws"

# Запустите
docker-compose -f docker-compose.agent.yml up -d
```

## Конфигурация

### Переменные окружения сервера

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| LISTEN_ADDR | :8080 | Адрес для HTTP/WebSocket |
| DB_PATH | ./data/analyzer.db | Путь к SQLite базе |
| BLACKLIST_PATH | ./blacklist.txt | Путь к черному списку |
| BLACKLIST_RELOAD | 5m | Интервал перезагрузки списка |
| TELEGRAM_ENABLED | false | Включить Telegram алерты |
| TELEGRAM_TOKEN | - | Токен бота |
| TELEGRAM_CHAT_ID | - | ID чата/канала |
| SUSPICIOUS_REQUEST_COUNT | 5 | Порог запросов для алерта |
| SUSPICIOUS_TIME_WINDOW | 1h | Временное окно |

### Переменные окружения агента

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| NODE_ID | - | Уникальный ID ноды |
| LOG_FILE_PATH | /var/log/xray/access.log | Путь к access логу |
| SERVER_URL | ws://localhost:8080/ws | URL сервера |
| BATCH_SIZE | 1000 | Размер батча |
| BATCH_TIMEOUT | 5s | Таймаут батча |

## Формат черного списка

```
# Комментарии начинаются с #
# Один домен на строку

# Точное совпадение
rutracker.org

# Wildcard (все поддомены)
*.rutracker.org
```

## API

### GET /health
Проверка здоровья сервера

### GET /api/stats
Общая статистика
```json
{
  "total_requests": 1234567,
  "total_blacklist": 123,
  "nodes_total": 5,
  "nodes_connected": 4
}
```

### GET /api/nodes
Статистика по нодам

### GET /api/users
Топ пользователей по blacklist hits

## Telegram бот

1. Создайте бота через @BotFather
2. Получите токен
3. Добавьте бота в канал/чат
4. Получите chat_id (можно через @userinfobot)
5. Укажите в .env

## Разработка

### Сборка без Docker

```bash
# Сервер
cd server
go build -o server ./cmd/server
./server

# Агент
cd agent
go build -o agent ./cmd/agent
./agent
```

### Запуск тестов

```bash
go test ./...
```

## TODO

- [ ] Web UI для статистики
- [ ] Grafana дашборды
- [ ] Поддержка нескольких форматов логов
- [ ] Rate limiting по пользователям
- [ ] Автоматическая блокировка пользователей
- [ ] Экспорт метрик в Prometheus
