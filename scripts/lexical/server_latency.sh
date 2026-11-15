#!/usr/bin/env bash
# C2 lexical latency on the IITGN server (gate: p95 <= 30 ms). Run on the PC from the repository:
#     scripts/lexical/server_latency.sh [<lexical build dir>]        (default: data/lexical/LATEST)
#
# 1. writes the dev-split query texts (never test) to a temporary file;
# 2. copies the index build (lexical.sqlite, impact_*.npy, manifest.json; skipped when the server copy has the same sha256)
#    and the stdlib-only code it needs (threat_retrieval_engine/{__init__,runtime}.py, text/, lexical/) to
#    ~/team2/lexical on the server; nothing is written to ~/data, ~/config or ~/threat_retrieval_engine;
# 3. under the benchmark lock (scripts/bench/server_lock.sh, flock on ~/team2/run/bench.lock; waits while B6 or
#    any other benchmark holds it) runs `python -m threat_retrieval_engine.lexical.latency` with ~/py312, CPU
#    only, 3 repetitions warm and cold, median reported, load average recorded (B5 conventions);
# 4. detaches the remote job (nohup) and polls it, then copies the JSON back to
#    results/lexical/latency/server-<build_id>-<stamp>.json, which check_c2 reads.
# Environment: TRE_SSH_TARGET, TRE_SSH_PORT, TRE_BENCHMARK_DIR (default data/benchmark/v2.0), REPEAT (3).
set -uo pipefail
TARGET="${TRE_SSH_TARGET:-koushik.moram@10.0.62.212}"
PORT="${TRE_SSH_PORT:-2022}"
cd "$(git rev-parse --show-toplevel)"
ROOT="$(pwd)"
BUILD="${1:-}"
if [ -z "$BUILD" ]; then
  L="${TRE_LEXICAL_DIR:-data/lexical}"
  BUILD="$L/$(tr -d '[:space:]' < "$L/LATEST")"
fi
[ -f "$BUILD/lexical.sqlite" ] || { echo "no lexical.sqlite in $BUILD" >&2; exit 2; }
BID="$(basename "$BUILD")"
SHA="$(python -c "import json,sys; print(json.load(open(sys.argv[1]))['index_sha256'])" "$BUILD/manifest.json")"
DATA="${TRE_BENCHMARK_DIR:-data/benchmark/v2.0}"
STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="server-$BID-$STAMP"
SSHO=(-o BatchMode=yes -o ServerAliveInterval=30 -o LogLevel=ERROR -p "$PORT")
rs() { ssh "${SSHO[@]}" "$TARGET" "$@"; }
cp_to() { scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" "$@"; }

TMPQ="$(mktemp)"
python - "$DATA/queries.jsonl" "$TMPQ" <<'EOF' || exit 2
import json, sys
n = 0
with open(sys.argv[1], encoding="utf-8") as f, open(sys.argv[2], "w", encoding="utf-8", newline="\n") as o:
    for line in f:
        q = json.loads(line)
        if q["split"] == "dev":
            o.write(json.dumps({"qid": q["qid"], "slice": q["slice"], "split": "dev", "text": q["text"]}) + "\n")
            n += 1
print(f"{n} dev queries")
EOF

R='$HOME/team2/lexical'
echo "== copying code and index $BID to the server"
rs "mkdir -p ~/team2/lexical/pkg/threat_retrieval_engine/text ~/team2/lexical/pkg/threat_retrieval_engine/lexical ~/team2/lexical/builds/$BID ~/team2/lexical/out ~/team2/run ~/tmp" || exit 1
cp_to threat_retrieval_engine/__init__.py threat_retrieval_engine/runtime.py "$TARGET:team2/lexical/pkg/threat_retrieval_engine/" || exit 1
cp_to threat_retrieval_engine/text/*.py "$TARGET:team2/lexical/pkg/threat_retrieval_engine/text/" || exit 1
cp_to threat_retrieval_engine/lexical/*.py "$TARGET:team2/lexical/pkg/threat_retrieval_engine/lexical/" || exit 1
cp_to scripts/bench/server_lock.sh "$TARGET:team2/lexical/" || exit 1
cp_to "$TMPQ" "$TARGET:team2/lexical/dev_queries.jsonl" || exit 1
rm -f "$TMPQ"
remote_sha="$(rs "sha256sum ~/team2/lexical/builds/$BID/lexical.sqlite 2>/dev/null | cut -d' ' -f1")"
if [ "$remote_sha" != "$SHA" ]; then
  cp_to "$BUILD/lexical.sqlite" "$BUILD/manifest.json" "$BUILD"/impact_*.npy "$TARGET:team2/lexical/builds/$BID/" || exit 1
fi
rs "cd ~/team2/lexical && sed -i 's/\r$//' server_lock.sh && chmod +x server_lock.sh" || exit 1
remote_sha="$(rs "sha256sum ~/team2/lexical/builds/$BID/lexical.sqlite | cut -d' ' -f1")"
[ "$remote_sha" = "$SHA" ] || { echo "server copy sha256 differs from the manifest" >&2; exit 1; }

OUT="$R/out/$NAME.json"; LOG="$R/out/$NAME.log"; DONE="$R/out/$NAME.exit"
CMD="cd $R/pkg && env CUDA_VISIBLE_DEVICES= TMPDIR=\$HOME/tmp PYTHONPATH=$R/pkg \$HOME/py312/bin/python -m threat_retrieval_engine.lexical.latency --index $R/builds/$BID --queries $R/dev_queries.jsonl --repeat ${REPEAT:-3} --label server --out $OUT"
echo "== starting $NAME under the benchmark lock (waits while another benchmark holds it)"
rs "rm -f $DONE; nohup bash -c '$R/server_lock.sh bash -c \"$CMD\"; echo \$? > $DONE' > $LOG 2>&1 < /dev/null &"

printed=0
while true; do
  sleep 20
  out="$(rs "cat $DONE 2>/dev/null; echo ---; tail -n +$((printed + 1)) $LOG" 2>/dev/null)" || { echo "(ssh hiccup, retrying)"; continue; }
  code="${out%%---*}"; code="$(echo "$code" | tr -d '[:space:]')"
  body="${out#*---}"; body="${body#$'\n'}"
  if [ -n "$body" ]; then echo "$body"; printed=$((printed + $(echo "$body" | wc -l))); fi
  [ -n "$code" ] && break
done
echo "== remote exit code $code"
mkdir -p results/lexical/latency
cp_from() { scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" "$@"; }
cp_from "$TARGET:team2/lexical/out/$NAME.json" "results/lexical/latency/$NAME.json" || { echo "no result file" >&2; exit 1; }
echo "== saved results/lexical/latency/$NAME.json"
exit "$code"
