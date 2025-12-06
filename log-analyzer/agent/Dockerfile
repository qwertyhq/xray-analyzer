# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Generate go.sum and build
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /agent ./cmd/agent

# Runtime stage
FROM alpine:3.19

# Add non-root user
RUN adduser -D -u 1000 agent

WORKDIR /app

# Copy binary
COPY --from=builder /agent /app/agent

# Set ownership
RUN chown -R agent:agent /app

USER agent

# Environment variables (can be overridden)
ENV NODE_ID=""
ENV LOG_FILE_PATH="/var/log/remnanode/access.log"
ENV SERVER_URL="wss://analyzer.example.com/ws"
ENV BATCH_SIZE="1000"
ENV BATCH_TIMEOUT="5s"

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD pgrep agent || exit 1

ENTRYPOINT ["/app/agent"]
