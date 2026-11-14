#!/usr/bin/env bash
# Server-side evaluation run (work package B4). Run on the PC from the repository:
#     benchmarks_v2/eval/server/remote_eval.sh <v1|v2> <queries.jsonl> <name> <variant> [<variant>...]
#
# Copies the harness (standard library + PyYAML part only) and the query file to ~/team2/eval on the server,
# then, under the benchmark lock (scripts/bench/server_lock.sh), starts the service, runs each variant with
# ~/py312/bin/python, stops the service, and copies the run files back to results/eval/runs/.
# Runs are resumable: invoking again with the same <name> continues the server-side run files.
# The remote job is detached (nohup) and polled, so a dropped SSH connection does not stop it.
# Query files with test-split queries are refused unless TRE_OPEN_SEALED=E1 (passed on to the server).
# Environment: TRE_SSH_TARGET, TRE_SSH_PORT.
set -uo pipefail
SERVICE="${1:-}"; QFILE="${2:-}"; NAME="${3:-}"
[ $# -ge 4 ] || { echo "usage: $0 <v1|v2> <queries.jsonl> <name> <variant> [<variant>...]" >&2; exit 2; }
shift 3
case "$SERVICE" in v1|v2) ;; *) echo "service must be v1 or v2" >&2; exit 2 ;; esac
TARGET="${TRE_SSH_TARGET:-koushik.moram@10.0.62.212}"
PORT="${TRE_SSH_PORT:-2022}"
cd "$(git rev-parse --show-toplevel)"
SSHO=(-o BatchMode=yes -o ServerAliveInterval=30 -o LogLevel=ERROR -p "$PORT")
rs() { ssh "${SSHO[@]}" "$TARGET" "$@"; }
cp_to() { scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" "$@"; }

# Validate the query file and apply the sealed rule before anything leaves the PC.
python -c "
import sys
from benchmarks_v2.eval.schema import load_queries
from benchmarks_v2.eval import sealed
qs = load_queries(sys.argv[1])
sealed.check_query_splits({q.split for q in qs}, 'sending test-split queries to the server')
print(f'{len(qs)} queries validated')
" "$QFILE" || exit 4
for V in "$@"; do
  python -c "from benchmarks_v2.eval.registry import get_variant; import sys; get_variant(sys.argv[1])" "$V" || exit 2
done
COMMIT="$(git rev-parse HEAD)"

echo "== copying harness to server"
rs 'mkdir -p ~/team2/eval/pkg/benchmarks_v2/eval ~/team2/eval/in ~/team2/eval/out ~/team2/run' || exit 1
cp_to benchmarks_v2/__init__.py "$TARGET:team2/eval/pkg/benchmarks_v2/" || exit 1
cp_to benchmarks_v2/eval/*.py benchmarks_v2/eval/variants.yaml "$TARGET:team2/eval/pkg/benchmarks_v2/eval/" || exit 1
cp_to scripts/bench/server_lock.sh benchmarks_v2/eval/server/server_eval.sh "$TARGET:team2/eval/" || exit 1
cp_to "$QFILE" "$TARGET:team2/eval/in/$NAME.queries.jsonl" || exit 1
rs 'cd ~/team2/eval && sed -i "s/\r$//" *.sh pkg/benchmarks_v2/*.py pkg/benchmarks_v2/eval/*.py pkg/benchmarks_v2/eval/*.yaml in/*.jsonl && chmod +x *.sh'

RLOG="\$HOME/team2/eval/out/$NAME.log"
RDONE="\$HOME/team2/eval/out/$NAME.exit"
SEALED_ENV=""
[ "${TRE_OPEN_SEALED:-}" = "E1" ] && SEALED_ENV="TRE_OPEN_SEALED=E1"
echo "== starting $SERVICE run $NAME: $*"
rs "rm -f $RDONE; nohup env $SEALED_ENV bash -c '\$HOME/team2/eval/server_lock.sh \$HOME/team2/eval/server_eval.sh $SERVICE $NAME $COMMIT $*; echo \$? > $RDONE' > $RLOG 2>&1 < /dev/null &"

printed=0
while true; do
  sleep 20
  out="$(rs "cat $RDONE 2>/dev/null; echo ---; tail -n +$((printed + 1)) $RLOG" 2>/dev/null)" || { echo "(ssh hiccup, retrying)"; continue; }
  code="${out%%---*}"; code="$(echo "$code" | tr -d '[:space:]')"
  body="${out#*---}"
  body="${body#$'\n'}"
  if [ -n "$body" ]; then echo "$body"; printed=$((printed + $(echo "$body" | wc -l))); fi
  [ -n "$code" ] && break
done
echo "== remote exit code $code"

mkdir -p results/eval/runs
for V in "$@"; do
  for f in "$NAME-$V.jsonl" "$NAME-$V.jsonl.meta.json"; do
    cp_from="$TARGET:team2/eval/out/$f"
    scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" "$cp_from" "results/eval/runs/$f" && echo "== saved results/eval/runs/$f"
  done
done
exit "$code"
