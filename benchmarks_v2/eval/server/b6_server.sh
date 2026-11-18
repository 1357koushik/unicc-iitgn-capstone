#!/usr/bin/env bash
# Runs ON the server, under server_lock.sh (work package B6). Called by b6_start.sh.
# Usage: b6_server.sh <harness_commit>
# Starts the frozen v1 service once, then runs v1_match and v1_hybrid over the train and dev splits of
# ~/team2/benchmark/v2.0 (open files only, no sealed/), one run file per variant/split in ~/team2/eval/runs/.
# Run files are append-only and resumable: starting again continues them. The v1 service is always stopped on
# exit. CPU only. Nothing is written under ~/data. Extra `run` arguments: $RUN_ARGS (default pause 30 s after
# an error so work v1 keeps running after its 504 does not spill into the next query).
set -u
COMMIT="${1:-unknown}"
E="$HOME/team2/eval"
RUN="$HOME/team2/run"
PY="$HOME/py312/bin/python"
DATA="$HOME/team2/benchmark/v2.0"
OUTD="$E/runs"
PORT=8765
PIDFILE="$RUN/eval-v1.pid"
LOG="$RUN/eval-v1.log"
RUN_ARGS="${RUN_ARGS:---pause-after-error 30}"
mkdir -p "$RUN" "$HOME/tmp" "$OUTD"
[ -f "$DATA/queries.jsonl" ] || { echo "missing $DATA/queries.jsonl" >&2; exit 2; }

stop_all() {
  if [ -f "$PIDFILE" ]; then
    p="$(cat "$PIDFILE")"
    kill "$p" 2>/dev/null
    for _ in $(seq 1 60); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
    kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
    rm -f "$PIDFILE"
    echo "[b6] v1 (pid $p) stopped"
  fi
}
for p in 8765 8766; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is already in use; refusing to start" >&2
    exit 3
  fi
done
trap stop_all EXIT

echo "[b6] $(date '+%F %T') starting v1 on $PORT; load $(cut -d' ' -f1-3 /proc/loadavg)"
(
  cd "$HOME" || exit 1
  echo $BASHPID > "$PIDFILE"
  exec env CUDA_VISIBLE_DEVICES= TMPDIR="$HOME/tmp" PYTHONPATH="$HOME/threat_retrieval_engine/search_engine" \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 "$HOME/py312/bin/python3" -m uvicorn threat_retrieval_engine.api.main:app \
    --host 127.0.0.1 --port 8765 > "$LOG" 2>&1
) &
ok=0
for _ in $(seq 1 180); do
  if curl -sf "http://127.0.0.1:$PORT/api/v1/health" 2>/dev/null | grep -qi -E "healthy|ok"; then ok=1; break; fi
  sleep 5
done
[ $ok = 1 ] || { echo "v1 did not become healthy within 15 minutes; log tail:" >&2; tail -20 "$LOG" >&2; exit 4; }
echo "[b6] $(date '+%F %T') healthy"

rc=0
# Order (coordinator decision): the fast hybrid endpoint first on train and dev, then /threats/match on dev only.
# v1_match on train is not needed: v1 is compared on dev (and on test in E1); train is only used to fit v2.
# Override with B6_RUNS="variant:split ...".
B6_RUNS="${B6_RUNS:-v1_hybrid:train v1_hybrid:dev v1_match:dev}"
for VS in $B6_RUNS; do
  V="${VS%%:*}"; S="${VS##*:}"
  {
    OUT="$OUTD/$V-$S.jsonl"
    echo "[b6] $(date '+%F %T') $V $S -> $OUT"
    ( cd "$E/pkg" && env CUDA_VISIBLE_DEVICES= PYTHONPATH="$E/pkg" TRE_HARNESS_COMMIT="$COMMIT" \
        "$PY" -m benchmarks_v2.eval run --variant "$V" --dataset "$DATA" --split "$S" --out "$OUT" \
        --concurrency 1 $RUN_ARGS )
    r=$?
    echo "[b6] $V $S exit $r"
    [ $r -ne 0 ] && rc=$r
  }
done
echo "[b6] $(date '+%F %T') done; load $(cut -d' ' -f1-3 /proc/loadavg)"
exit $rc
