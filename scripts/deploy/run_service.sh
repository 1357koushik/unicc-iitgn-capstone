#!/usr/bin/env bash
# Start the retrieval service from ~/team2/current (work package A2).
# Run on the server:   scripts/deploy/run_service.sh [port]      (default port 8766)
#
# Port 8765 belongs to the v1 deployment in ~/threat_retrieval_engine; never use it here.
# CPU only: CUDA_VISIBLE_DEVICES is forced empty (the GPUs belong to someone else).
# No PYTHONPATH: the package is installed (pip install -e) into the release venv.
#
# Environment overrides: TRE_DATA_DIR, TRE_CONFIG_PATH, TRE_NUM_THREADS,
#   TRE_WAIT_FILE (wait while this file exists, 60 s poll), TRE_START_TIMEOUT (seconds, default 600).
set -euo pipefail

PORT="${1:-8766}"
if [ "$PORT" = "8765" ]; then
  echo "refusing to use port 8765 (v1)" >&2
  exit 2
fi

T="$HOME/team2"
CURRENT="$T/current"
RUN="$T/run"
PIDFILE="$RUN/service-$PORT.pid"
LOG="$RUN/service-$PORT.log"

[ -L "$CURRENT" ] || { echo "no release deployed: $CURRENT missing (run deploy.sh first)" >&2; exit 1; }
REL="$(readlink -f "$CURRENT")"
[ -x "$REL/.venv/bin/python" ] || { echo "release venv missing in $REL" >&2; exit 1; }
mkdir -p "$RUN" "$HOME/tmp"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "already running: pid $(cat "$PIDFILE") on port $PORT"
  exit 0
fi

if [ -n "${TRE_WAIT_FILE:-}" ]; then
  while [ -e "$TRE_WAIT_FILE" ]; do echo "waiting: $TRE_WAIT_FILE exists"; sleep 60; done
fi

# Run from the run directory, not the checkout, so nothing can import by cwd accident.
cd "$RUN"
env -u PYTHONPATH \
  CUDA_VISIBLE_DEVICES= \
  HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
  TMPDIR="$HOME/tmp" \
  TRE_DATA_DIR="${TRE_DATA_DIR:-$HOME/data}" \
  TRE_CONFIG_PATH="${TRE_CONFIG_PATH:-$HOME/config/retrieval_config.yaml}" \
  TRE_NUM_THREADS="${TRE_NUM_THREADS:-16}" \
  setsid nohup "$REL/.venv/bin/python" -m uvicorn threat_retrieval_engine.api.main:app \
    --host 127.0.0.1 --port "$PORT" --app-dir "$RUN" \
  > "$LOG" 2>&1 < /dev/null &
echo $! > "$PIDFILE"
echo "started pid $(cat "$PIDFILE") port $PORT release $(basename "$REL"); log $LOG"

# Wait for the health endpoint (model loading can take minutes).
DEADLINE=$(( $(date +%s) + ${TRE_START_TIMEOUT:-600} ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "service exited during start-up; tail of $LOG:" >&2
    tail -n 30 "$LOG" >&2
    rm -f "$PIDFILE"
    exit 1
  fi
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$PORT/api/v1/health" || true)"
  if [ "$code" = "200" ]; then
    echo "health OK on http://127.0.0.1:$PORT/api/v1/health"
    exit 0
  fi
  sleep 3
done
echo "timed out waiting for health; service left running (pid $(cat "$PIDFILE"))" >&2
exit 1
