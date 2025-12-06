#!/bin/sh

# Start Go backend in background
echo "Starting API server on port 8237..."
/app/server &
GO_PID=$!

# Wait for API to be ready (max 30 seconds)
echo "Waiting for API server to be ready..."
for i in $(seq 1 30); do
    if wget -q --spider http://localhost:8237/health 2>/dev/null; then
        echo "API server is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Warning: API server may not be ready yet, starting web UI anyway"
    fi
    sleep 1
done

# Start Next.js frontend
echo "Starting Web UI on port 3000..."
cd /app/web
HOSTNAME=0.0.0.0 PORT=3000 NODE_ENV=production node server.js
