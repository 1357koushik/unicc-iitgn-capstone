#!/usr/bin/env bash
# Stop the service started by run_service.sh (work package A2).
# Run on the server:   scripts/deploy/stop_service.sh [port]      (default port 8766)
set -euo pipefail

PORT="${1:-8766}"
if [ "$PORT" = "8765" ]; then
  echo "refusing to touch port 8765 (v1)" >&2
  exit 2
fi
PIDFILE="$HOME/team2/run/service-$PORT.pid"

if [ ! -f "$PIDFILE" ]; then
  echo "no pid file for port $PORT; nothing to stop"
  exit 0
fi
PID="$(cat "$PIDFILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  for _ in $(seq 1 60); do
    kill -0 "$PID" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$PID" 2>/dev/null; then
    echo "pid $PID did not exit after 60 s; sending SIGKILL" >&2
    kill -9 "$PID" || true
  fi
  echo "stopped pid $PID"
else
  echo "pid $PID was not running"
fi
rm -f "$PIDFILE"

# confirm the port is free
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  echo "WARNING: something still listens on port $PORT" >&2
  exit 1
fi
echo "port $PORT is free"
