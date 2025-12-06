#!/bin/sh

# Start Go backend in background
echo "Starting API server on port 8080..."
/app/server &

# Wait for API to be ready
sleep 2

# Start Next.js frontend
echo "Starting Web UI on port 3000..."
cd /app/web
NODE_ENV=production node server.js
