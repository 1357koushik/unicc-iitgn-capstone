#!/usr/bin/env bash
# C3 latency on the IITGN server, under the benchmark lock (waits while an encode job or another benchmark holds
# it). Run ON THE SERVER:  setsid nohup scripts/dense/server_latency.sh [<models>] > log 2>&1 &
#   1. dense search on $TRE_DENSE_DIR/LATEST (the served index), dev queries, BLAS thread sweep, 3 repetitions;
#   2. dense search on a synthetic full-size build (every searchable CVE + ATT&CK document, 1,024 dimensions,
#      random unit vectors): the size a full re-embed produces;
#   3. query encoding, batch 1, for each model (torch thread sweep on a 300-query sample, then every dev query at
#      the chosen count, 3 repetitions).
# Results: ~/team2/dense/out/server-{search,search-synthetic,encode}-*.json (copied back to results/dense/latency).
set -u
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PY:-$HOME/py312/bin/python}"
MODELS="${1:-bge-m3,bge-large-en-v1.5,bge-base-en-v1.5,e5-large-v2,gte-large}"
export CUDA_VISIBLE_DEVICES= HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TMPDIR="$HOME/tmp" PYTHONPATH="$HERE"
export TRE_DENSE_DIR="${TRE_DENSE_DIR:-$HOME/team2/dense/builds}" TRE_MODEL_DIR="${TRE_MODEL_DIR:-$HOME/team2/models}"
unset TRE_QUERY_VECTOR_CACHE TRE_TORCH_THREADS TRE_BLAS_THREADS
OUT="$HOME/team2/dense/out"; mkdir -p "$OUT"
if [ -z "${C3_LOCKED:-}" ]; then
  exec env C3_LOCKED=1 "$HERE/scripts/bench/server_lock.sh" "$0" "$@"
fi
STAMP="$(date +%Y%m%d-%H%M%S)"
DEV="$HOME/team2/dense/dev_queries.jsonl"
"$PY" - "${TRE_BENCHMARK_DIR:-$HOME/team2/benchmark/v2.0}/queries.jsonl" "$DEV" <<'EOF' || exit 2
import json, sys
n = 0
with open(sys.argv[1], encoding="utf-8") as f, open(sys.argv[2], "w", encoding="utf-8") as o:
    for line in f:
        q = json.loads(line)
        if q["split"] == "dev":
            o.write(json.dumps({"qid": q["qid"], "slice": q["slice"], "split": "dev", "text": q["text"]}) + "\n"); n += 1
print(f"{n} dev queries")
EOF
BID="$(tr -d '[:space:]' < "$TRE_DENSE_DIR/LATEST")"
echo "[latency] $(date '+%F %T') search on $BID"
"$PY" -m threat_retrieval_engine.dense.latency search --index "$TRE_DENSE_DIR" --queries "$DEV" \
  --out "$OUT/server-search-$BID-$STAMP.json" || exit 1
SYN="$TRE_DENSE_DIR/synthetic"
if [ ! -f "$SYN/LATEST" ]; then
  echo "[latency] $(date '+%F %T') synthetic full-size build"
  "$PY" -m threat_retrieval_engine.dense.latency synthetic-build --documents "$HOME/team2/dense/inputs/all-20261115T091739Z-f7f744ffa8.jsonl" \
    --out "$SYN" --dim 1024 || exit 1
fi
echo "[latency] $(date '+%F %T') search on the synthetic full-size build"
"$PY" -m threat_retrieval_engine.dense.latency search-random --index "$SYN" --out "$OUT/server-search-synthetic-$STAMP.json" || exit 1
echo "[latency] $(date '+%F %T') query encoding: $MODELS"
"$PY" -m threat_retrieval_engine.dense.latency encode --models "$MODELS" --queries "$DEV" --full all \
  --out "$OUT/server-encode-$STAMP.json" || exit 1
echo "[latency] $(date '+%F %T') done"
