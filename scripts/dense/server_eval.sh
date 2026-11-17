#!/usr/bin/env bash
# Run B4 harness variants (inprocess: dense, fused, lexical) on the IITGN server CPU. Run ON THE SERVER:
#     scripts/dense/server_eval.sh <split> <variant> [<variant> ...]
# Run files go to $C3_RUNS (default ~/team2/dense/runs/<variant>-<split>.jsonl; resumable, the harness skips
# finished queries). Quality runs do not measure latency, so they do not take the benchmark lock; they run with
# TRE_TORCH_THREADS (default 4) to share the CPU with an encode job, and with the offline query-vector store
# (TRE_QUERY_VECTOR_CACHE), so variants sharing an encoder encode each query once. Only the train and dev splits exist on the
# server (the sealed split is not there, and the harness refuses it without TRE_OPEN_SEALED).
# Environment: TRE_DENSE_DIR (~/team2/dense/builds), TRE_LEXICAL_DIR (the C2 build on the server),
# TRE_MODEL_DIR (~/team2/models), TRE_BENCHMARK_DIR (~/team2/benchmark/v2.0), PY (~/py312/bin/python).
set -u
[ $# -ge 2 ] || { echo "usage: $0 <train|dev> <variant>..." >&2; exit 2; }
SPLIT="$1"; shift
case "$SPLIT" in train|dev) ;; *) echo "split must be train or dev" >&2; exit 2;; esac
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PY:-$HOME/py312/bin/python}"
export CUDA_VISIBLE_DEVICES= HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TMPDIR="$HOME/tmp" PYTHONPATH="$HERE"
export TRE_DENSE_DIR="${TRE_DENSE_DIR:-$HOME/team2/dense/builds}"
export TRE_LEXICAL_DIR="${TRE_LEXICAL_DIR:-$HOME/team2/lexical/builds/20261115T203653Z-bfacb4bb1c}"
export TRE_MODEL_DIR="${TRE_MODEL_DIR:-$HOME/team2/models}"
export TRE_TORCH_THREADS="${TRE_TORCH_THREADS:-4}" TRE_BLAS_THREADS="${TRE_BLAS_THREADS:-4}"
# query vectors shared by variants with the same encoder configuration (identical results, encoded once)
export TRE_QUERY_VECTOR_CACHE="${TRE_QUERY_VECTOR_CACHE:-$HOME/team2/dense/qvec}"
DATA="${TRE_BENCHMARK_DIR:-$HOME/team2/benchmark/v2.0}"
RUNS="${C3_RUNS:-$HOME/team2/dense/runs}"
mkdir -p "$RUNS"
unset TRE_OPEN_SEALED
rc=0
for v in "$@"; do
  echo "[server_eval] $(date '+%F %T') $v $SPLIT"
  "$PY" -m benchmarks_v2.eval run --variant "$v" --dataset "$DATA" --split "$SPLIT" \
    --out "$RUNS/$v-$SPLIT.jsonl" --harness-commit "${TRE_GIT_COMMIT:-unknown}" 2>&1 | grep -v "^\[run\] [0-9]" || true
  "$PY" - "$RUNS/$v-$SPLIT.jsonl" <<'EOF' || rc=1
import json, sys
n = err = 0
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line); n += 1; err += bool(r["error"])
print(f"[server_eval] {sys.argv[1]}: {n} records, {err} errors")
sys.exit(1 if err else 0)
EOF
done
exit $rc
