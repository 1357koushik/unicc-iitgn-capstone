#!/bin/bash
# Run on the server: ./run_baseline.sh <run_label>; quality_tests.py and stage_timings.py must sit next to it.
set -u
LABEL=${1:-run1}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT_DIR:-$HOME/baseline_out}
mkdir -p "$OUT" "$HOME/tmp"
cd ~
CUDA_VISIBLE_DEVICES= TMPDIR=$HOME/tmp PYTHONPATH=$HOME/threat_retrieval_engine/search_engine HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 ~/py312/bin/python3 -m uvicorn threat_retrieval_engine.api.main:app --host 127.0.0.1 --port 8765 > "$OUT/server_$LABEL.log" 2>&1 &
SPID=$!
trap 'kill $SPID 2>/dev/null; wait $SPID 2>/dev/null' EXIT
ok=0
for i in $(seq 1 120); do
  if curl -sf http://127.0.0.1:8765/api/v1/health 2>/dev/null | grep -qi -E "healthy|ok"; then ok=1; break; fi
  sleep 5
done
[ $ok = 1 ] || { echo "server did not become healthy"; exit 1; }
CUDA_VISIBLE_DEVICES= ~/py312/bin/python3 "$HERE/quality_tests.py" --out "$OUT/quality_$LABEL.json" | tee "$OUT/quality_$LABEL.txt"
CUDA_VISIBLE_DEVICES= ~/py312/bin/python3 "$HERE/stage_timings.py" --out "$OUT/stage_timings_$LABEL.json" | tee "$OUT/stage_timings_$LABEL.txt"
