# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server ./cmd/server

# Runtime stage
FROM alpine:3.19

# Add non-root user
RUN adduser -D -u 1000 analyzer

WORKDIR /app

# Create data directory
RUN mkdir -p /app/data && chown -R analyzer:analyzer /app

# Copy binary
COPY --from=builder /server /app/server

# Copy default blacklist
COPY blacklist.txt /app/blacklist.txt

# Set ownership
RUN chown -R analyzer:analyzer /app

USER analyzer

# Environment variables
ENV LISTEN_ADDR=":8080"
ENV DB_PATH="/app/data/analyzer.db"
ENV BLACKLIST_PATH="/app/blacklist.txt"
ENV BLACKLIST_RELOAD="5m"
ENV TELEGRAM_ENABLED="false"
ENV TELEGRAM_TOKEN=""
ENV TELEGRAM_CHAT_ID=""
ENV SUSPICIOUS_REQUEST_COUNT="5"
ENV SUSPICIOUS_TIME_WINDOW="1h"

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/server"]
