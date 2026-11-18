#!/usr/bin/env bash
# C3 model comparison on the server, unattended: for each model, wait until its encode job
# (scripts/dense/encode_server.sh) has finished both parts, assemble the reduced-corpus build into
# $TRE_DENSE_DIR/compare/<model>, then run the harness variant cmp_<model> on dev and train
# (scripts/dense/server_eval.sh). Run ON THE SERVER:
#     setsid nohup scripts/dense/compare_pipeline.sh <documents.jsonl> <work_root> <model>... > log 2>&1 &
set -u
[ $# -ge 3 ] || { echo "usage: $0 <documents.jsonl> <work_root> <model>..." >&2; exit 2; }
DOCS="$1"; WORK="$2"; shift 2
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PY:-$HOME/py312/bin/python}"
export CUDA_VISIBLE_DEVICES= HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TMPDIR="$HOME/tmp" PYTHONPATH="$HERE"
export TRE_DENSE_DIR="${TRE_DENSE_DIR:-$HOME/team2/dense/builds}"
rc=0
for m in "$@"; do
  W="$WORK/$m"
  until [ -f "$W/part_0_of_2.json" ] && [ -f "$W/part_1_of_2.json" ]; do sleep 60; done
  if [ ! -f "$TRE_DENSE_DIR/compare/$m/LATEST" ]; then
    echo "[compare] $(date '+%F %T') assemble $m"
    "$PY" -m threat_retrieval_engine.dense.build assemble --documents "$DOCS" --work "$W" \
      --out "$TRE_DENSE_DIR/compare/$m" || { rc=1; continue; }
  fi
  for s in dev train; do
    "$HERE/scripts/dense/server_eval.sh" "$s" "cmp_$m" || rc=1
  done
done
echo "[compare] $(date '+%F %T') done rc=$rc"
exit $rc
