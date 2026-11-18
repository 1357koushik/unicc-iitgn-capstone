#!/usr/bin/env bash
# Runs ON the server, under server_lock.sh (work package B5). Called by run_load.sh.
# Usage: remote_run.sh <v1|v2> <levels> <out.json> [extra load_harness.py args...]
# The service is started by the harness itself (--start-cmd) so cold start is measured;
# it is always stopped on exit. CPU only: CUDA_VISIBLE_DEVICES is empty.
set -u
WHICH="$1"; LEVELS="$2"; OUT="$3"; shift 3
B="$HOME/team2/bench"
RUN="$HOME/team2/run"
PY="$HOME/py312/bin/python"
mkdir -p "$RUN" "$HOME/tmp" "$B/out"

case "$WHICH" in
  v1)
    PORT=8765
    REL=(--release-link none)
    PIDFILE="$RUN/bench-v1.pid"
    LOG="$RUN/bench-v1.log"
    START="echo \$\$ > $PIDFILE; cd \$HOME; exec env CUDA_VISIBLE_DEVICES= TMPDIR=\$HOME/tmp PYTHONPATH=\$HOME/threat_retrieval_engine/search_engine HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \$HOME/py312/bin/python3 -m uvicorn threat_retrieval_engine.api.main:app --host 127.0.0.1 --port 8765 > $LOG 2>&1"
    ;;
  v2)
    PORT=8766
    REL=()
    PIDFILE="$RUN/service-8766.pid"
    LOG="$RUN/service-8766.log"
    START="$B/run_service.sh 8766"
    ;;
  *) echo "which must be v1 or v2" >&2; exit 2 ;;
esac

stop_all() {
  if [ "$WHICH" = v1 ]; then
    if [ -f "$PIDFILE" ]; then
      p="$(cat "$PIDFILE")"
      kill "$p" 2>/dev/null
      for _ in $(seq 1 60); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
      kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
      rm -f "$PIDFILE"
    fi
  else
    "$B/stop_service.sh" 8766
  fi
}
trap stop_all EXIT

# Refuse to start if either port is already in use (shared Qdrant lock, plan section 12).
for p in 8765 8766; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is already in use; refusing to start" >&2
    trap - EXIT
    exit 3
  fi
done

"$PY" "$B/load_harness.py" --base-url "http://127.0.0.1:$PORT" --queries "$B/latency_smoke.jsonl" \
  --concurrency "$LEVELS" --label "$WHICH" --pid-file "$PIDFILE" --start-cmd "$START" \
  ${REL[@]+"${REL[@]}"} --out "$OUT" "$@"
rc=$?
echo "harness exit $rc"
exit $rc
