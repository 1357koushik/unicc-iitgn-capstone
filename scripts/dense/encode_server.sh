#!/usr/bin/env bash
# C3 / C3b encode jobs on the IITGN server (CPU only), unattended and resumable. Run ON THE SERVER, e.g.
#     nohup scripts/dense/encode_server.sh <documents.jsonl> <work_root> <model> [<model> ...] > log 2>&1 &
#
# Holds the benchmark lock (scripts/bench/server_lock.sh) for the whole job, so no latency measurement runs
# beside it. For each model, two processes encode alternate checkpoint chunks of one job, one per NUMA node
# (numactl --cpunodebind=N --membind=N), 12 threads each (one per physical core of the socket). Measured on
# the server with BGE-M3 on 384 store documents (mean 74 tokens): one process on one node, 12 threads 17.4
# docs/s, 24 threads 18.4; two processes at once, 12 threads each 16.7 + 16.4 = 33.1 docs/s; one process on
# both sockets, 24 threads 21.4, 48 threads 16.9. Re-running the script skips finished chunks
# (threat_retrieval_engine.dense.build encode verifies each chunk's sidecar).
#
# Environment: TRE_MODEL_DIR (default ~/team2/models; BGE-M3 is read from the Hugging Face cache), PY
# (default ~/py312/bin/python), THREADS (12). Nothing is written to ~/data, ~/config or ~/threat_retrieval_engine.
set -u
[ $# -ge 3 ] || { echo "usage: $0 <documents.jsonl> <work_root> <model>..." >&2; exit 2; }
DOCS="$1"; WORK="$2"; shift 2
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PY:-$HOME/py312/bin/python}"
THREADS="${THREADS:-12}"
export CUDA_VISIBLE_DEVICES= HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TMPDIR="$HOME/tmp" PYTHONPATH="$HERE"
export TRE_MODEL_DIR="${TRE_MODEL_DIR:-$HOME/team2/models}"
mkdir -p "$WORK" "$HOME/tmp"
if [ -z "${C3_LOCKED:-}" ]; then
  exec env C3_LOCKED=1 "$HERE/scripts/bench/server_lock.sh" "$0" "$DOCS" "$WORK" "$@"
fi
rc=0
for m in "$@"; do
  W="$WORK/$m"
  mkdir -p "$W"
  echo "[encode_server] $(date '+%F %T') $m start"
  pids=()
  for node in 0 1; do
    numactl --cpunodebind=$node --membind=$node "$PY" -m threat_retrieval_engine.dense.build encode \
      --documents "$DOCS" --model "$m" --work "$W" --part "$node/2" --threads "$THREADS" > "$W/part$node.log" 2>&1 &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  echo "[encode_server] $(date '+%F %T') $m end (rc so far $rc)"
  tail -n 2 "$W/part0.log" "$W/part1.log"
done
exit $rc
