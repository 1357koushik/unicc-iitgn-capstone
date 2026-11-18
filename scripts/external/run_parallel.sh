#!/usr/bin/env bash
# Run the public benchmarks on the server with all CPU cores: 12 workers x 4 threads, 6 per NUMA node.
#   bash run_parallel.sh served   # served configuration (one CVE + ATT&CK list)
#   bash run_parallel.sh kind     # candidate search limited to the benchmark's target kind
#   bash run_parallel.sh cti      # CTIConnect over its own corpus (needs cti_corpus.json)
# Inputs in $EXT_DIR (default ~/team2/ext): ext_queries.jsonl from convert.py; outputs in $EXT_DIR/out.
set -u
MODE=${1:?mode: served | kind | cti}
PKG=${TRE_PKG_DIR:-~/team2/dense/pkg8}
EXT_DIR=${EXT_DIR:-~/team2/ext}
PY=${PY:-~/py312/bin/python}
N=${WORKERS:-12}
THREADS=${THREADS:-4}
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$PKG"; . ~/team2/dense/v2env.sh
export PYTHONPATH=$PWD TRE_PIPELINE=v2 TRE_RERANK_WEIGHT=0 TMPDIR=~/tmp TRE_BLAS_THREADS=$THREADS \
       OMP_NUM_THREADS=$THREADS MKL_NUM_THREADS=$THREADS OPENBLAS_NUM_THREADS=$THREADS EXT_DIR
mkdir -p "$EXT_DIR/out"
if [ "$MODE" != cti ] && [ ! -f "$EXT_DIR/ext_queries_ready.jsonl" ]; then
  $PY "$HERE/ext_run.py" prep > "$EXT_DIR/prep.json" || exit 1
fi
echo "start $(date +%T)"
for i in $(seq 0 $((N-1))); do
  node=$((i % 2))
  case $MODE in
    served) args=(run $i $N $THREADS) ; script=ext_run.py ;;
    kind)   args=(run $i $N $THREADS kind) ; script=ext_run.py ;;
    cti)    args=($i $N $THREADS) ; script=cti_run.py ;;
    *) echo "unknown mode $MODE"; exit 2 ;;
  esac
  numactl --cpunodebind=$node --membind=$node $PY "$HERE/$script" "${args[@]}" > "$EXT_DIR/out/$MODE$i.log" 2>&1 &
done
wait
echo "done $(date +%T)"
