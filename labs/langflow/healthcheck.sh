#!/bin/bash
set -euo pipefail

TARGET="${LANGFLOW_HOST:-192.168.44.136}"
PORT="${LANGFLOW_PORT:-7860}"
URL="http://${TARGET}:${PORT}/health"

response=$(curl -sf -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 30 "$URL" 2>/dev/null)

if [ "$response" = "200" ]; then
  echo "[OK] Langflow health check passed: $URL -> $response"
  exit 0
else
  echo "[FAIL] Langflow health check failed: $URL -> ${response:-timeout}"
  exit 1
fi
