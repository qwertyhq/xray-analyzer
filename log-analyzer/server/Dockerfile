# Build stage for Go backend
FROM golang:1.21-alpine AS go-builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy go mod files
COPY go.mod ./
RUN go mod download

# Copy source code (exclude web folder)
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY *.go ./

# Generate go.sum and build
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server ./cmd/server

# Build stage for Next.js frontend
FROM node:20-alpine AS web-builder

WORKDIR /app

# Copy package files
COPY web/package*.json ./

# Install dependencies
RUN npm ci

# Copy source
COPY web/ ./

# Build args for NEXT_PUBLIC variables
ARG NEXT_PUBLIC_MAPBOX_TOKEN
ENV NEXT_PUBLIC_MAPBOX_TOKEN=${NEXT_PUBLIC_MAPBOX_TOKEN}

# Set API URL for build
ENV NEXT_PUBLIC_API_URL=""

# Build Next.js
RUN npm run build

# Runtime stage
FROM alpine:3.19

# Install Node.js for Next.js runtime
RUN apk add --no-cache nodejs npm

# Add non-root user
RUN adduser -D -u 1000 analyzer

WORKDIR /app

# Create data directory
RUN mkdir -p /app/data && chown -R analyzer:analyzer /app

# Copy Go binary
COPY --from=go-builder /server /app/server

# Copy Next.js standalone build
COPY --from=web-builder /app/.next/standalone /app/web
COPY --from=web-builder /app/.next/static /app/web/.next/static
COPY --from=web-builder /app/public /app/web/public

# Copy default blacklist
COPY blacklist.txt /app/blacklist.txt

# Copy startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Set ownership
RUN chown -R analyzer:analyzer /app

USER analyzer

# Environment variables
ENV LISTEN_ADDR=":8237"
ENV DB_PATH="/app/data/analyzer.db"
ENV BLACKLIST_PATH="/app/blacklist.txt"
ENV BLACKLIST_RELOAD="5m"
ENV TELEGRAM_ENABLED="false"
ENV TELEGRAM_TOKEN=""
ENV TELEGRAM_CHAT_ID=""
ENV SUSPICIOUS_REQUEST_COUNT="5"
ENV SUSPICIOUS_TIME_WINDOW="1h"
ENV WEB_PORT="3000"

# Expose ports (API: 8237, Web: 3000)
EXPOSE 8237 3000

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
  CMD wget -q --spider http://localhost:8237/health || exit 1

ENTRYPOINT ["/app/start.sh"]
