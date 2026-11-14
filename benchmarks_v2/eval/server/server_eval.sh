#!/usr/bin/env bash
# Runs ON the server, under server_lock.sh (work package B4). Called by remote_eval.sh.
# Usage: server_eval.sh <v1|v2> <name> <harness_commit> <variant> [<variant>...]
# Starts the service, runs each variant over ~/team2/eval/in/<name>.queries.jsonl with the harness in
# ~/team2/eval/pkg (append-only, resumable run files in ~/team2/eval/out/<name>-<variant>.jsonl), and always
# stops the service on exit. Extra `run` arguments come from $RUN_ARGS (e.g. --pause-after-error 30). CPU only (CUDA_VISIBLE_DEVICES is empty). Nothing is written under ~/data.
set -u
SERVICE="$1"; NAME="$2"; COMMIT="$3"; shift 3
E="$HOME/team2/eval"
RUN="$HOME/team2/run"
PY="$HOME/py312/bin/python"
mkdir -p "$RUN" "$HOME/tmp" "$E/out"
QUERIES="$E/in/$NAME.queries.jsonl"
[ -f "$QUERIES" ] || { echo "missing $QUERIES" >&2; exit 2; }

case "$SERVICE" in
  v1)
    PORT=8765
    PIDFILE="$RUN/eval-v1.pid"
    LOG="$RUN/eval-v1.log"
    ;;
  v2)
    PORT=8766
    PIDFILE="$RUN/service-8766.pid"
    LOG="$RUN/service-8766.log"
    ;;
  *) echo "service must be v1 or v2" >&2; exit 2 ;;
esac

stop_all() {
  if [ "$SERVICE" = v1 ]; then
    if [ -f "$PIDFILE" ]; then
      p="$(cat "$PIDFILE")"
      kill "$p" 2>/dev/null
      for _ in $(seq 1 60); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
      kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
      rm -f "$PIDFILE"
      echo "[server_eval] v1 (pid $p) stopped"
    fi
  else
    "$HOME/team2/bench/stop_service.sh" 8766
  fi
}

for p in 8765 8766; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is already in use; refusing to start" >&2
    exit 3
  fi
done
trap stop_all EXIT

echo "[server_eval] $(date '+%F %T') starting $SERVICE on $PORT; load $(cut -d' ' -f1-3 /proc/loadavg)"
if [ "$SERVICE" = v1 ]; then
  (
    cd "$HOME" || exit 1
    echo $BASHPID > "$PIDFILE"
    exec env CUDA_VISIBLE_DEVICES= TMPDIR="$HOME/tmp" PYTHONPATH="$HOME/threat_retrieval_engine/search_engine" \
      HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 "$HOME/py312/bin/python3" -m uvicorn threat_retrieval_engine.api.main:app \
      --host 127.0.0.1 --port 8765 > "$LOG" 2>&1
  ) &
else
  "$HOME/team2/bench/run_service.sh" 8766
fi

ok=0
for _ in $(seq 1 180); do
  if curl -sf "http://127.0.0.1:$PORT/api/v1/health" 2>/dev/null | grep -qi -E "healthy|ok"; then ok=1; break; fi
  sleep 5
done
[ $ok = 1 ] || { echo "service did not become healthy within 15 minutes; log tail:" >&2; tail -20 "$LOG" >&2; exit 4; }
echo "[server_eval] $(date '+%F %T') healthy"

rc=0
for V in "$@"; do
  OUT="$E/out/$NAME-$V.jsonl"
  echo "[server_eval] $(date '+%F %T') variant $V -> $OUT"
  ( cd "$E/pkg" && env CUDA_VISIBLE_DEVICES= PYTHONPATH="$E/pkg" TRE_HARNESS_COMMIT="$COMMIT" \
      "$PY" -m benchmarks_v2.eval run --variant "$V" --queries "$QUERIES" --out "$OUT" ${RUN_ARGS:-} )
  r=$?
  echo "[server_eval] variant $V exit $r"
  [ $r -ne 0 ] && rc=$r
done
echo "[server_eval] $(date '+%F %T') done; load $(cut -d' ' -f1-3 /proc/loadavg)"
exit $rc
