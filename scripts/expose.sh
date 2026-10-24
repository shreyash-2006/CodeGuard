#!/usr/bin/env bash
# scripts/expose.sh — start CodeGuard (uvicorn) + ngrok and print the public URL.
#
#   bash scripts/expose.sh [PORT]
#
# Prereqs: `ngrok config add-authtoken <TOKEN>` (one-time), dependencies installed.
# Keep the terminal open while the URL is in use. Ctrl+C stops both processes.

set -euo pipefail
PORT="${1:-8000}"
cd "$(dirname "$0")/.."

command -v ngrok >/dev/null 2>&1 || { echo "[x] ngrok not found on PATH"; exit 1; }
command -v python >/dev/null 2>&1 || { echo "[x] python not found on PATH"; exit 1; }

echo "[1/3] Starting uvicorn on port $PORT ..."
python -m uvicorn main:app --host 0.0.0.0 --port "$PORT" --workers 1 &
UV_PID=$!
cleanup() { echo "Stopping ..."; kill "$NG_PID" "$UV_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

for _ in $(seq 1 80); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 || { echo "[x] uvicorn not healthy"; exit 1; }
echo "      /health OK."

echo "[2/3] Starting ngrok tunnel ..."
ngrok http "$PORT" >/dev/null 2>&1 &
NG_PID=$!

PUBLIC=""
for _ in $(seq 1 60); do
  PUBLIC=$(curl -fsS http://127.0.0.1:4040/api/tunnels 2>/dev/null \
            | python -c "import sys,json; d=json.load(sys.stdin); print(next((t['public_url'] for t in d['tunnels'] if t['public_url'].startswith('https')), ''))" 2>/dev/null || true)
  [ -n "$PUBLIC" ] && break
  sleep 0.5
done

if [ -z "$PUBLIC" ]; then
  echo "[x] No public URL from ngrok. Set the token: ngrok config add-authtoken <TOKEN>"
  exit 1
fi

echo ""
echo "[3/3] PUBLIC ENDPOINT: $PUBLIC/check"
echo ""
echo "Verify from the public URL (not localhost):"
echo "  curl -X POST $PUBLIC/check -H 'Content-Type: application/json' -H 'ngrok-skip-browser-warning: true' -d '{\"code\":\"rm -rf /\"}'"
echo ""
echo "Callers must send: Content-Type: application/json + ngrok-skip-browser-warning: true"
echo "Do NOT restart ngrok (the URL changes). Ctrl+C stops both."

wait "$UV_PID"
