#!/bin/sh

# Start Go backend in background
echo "Starting API server on port 8237..."
/app/server &

# Wait for API to be ready
sleep 2

# Start Next.js frontend on port 3925
echo "Starting Web UI on port 3925..."
cd /app/web
HOSTNAME=0.0.0.0 PORT=3925 NODE_ENV=production node server.js
