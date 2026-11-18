#!/usr/bin/env bash
# One command to measure latency and capacity of v1 or v2 on the IITGN server (work package B5).
# Run on the PC from the repository:
#     scripts/bench/run_load.sh <v1|v2> [levels]            (levels default 1,4,16)
#
# Copies the harness and queries to ~/team2/bench on the server, then, under the benchmark lock,
# starts the chosen service (v1 on 8765, v2 on 8766 via run_service.sh), runs the harness,
# stops the service, and copies the JSON back to results/load/<v1|v2>-<date>-<time>.json.
#
# Environment overrides:
#   REQUESTS (requests per level and repetition, default 60)   DURATION (seconds; replaces REQUESTS)
#   REPEAT (default 3)   WARMUP (default 3)   QUERIES (default scripts/bench/queries/latency_smoke.jsonl)
#   TRE_SSH_TARGET, TRE_SSH_PORT
# The remote run is detached (nohup) and polled, so a dropped SSH connection does not kill it.
set -uo pipefail

WHICH="${1:-}"; LEVELS="${2:-1,4,16}"
case "$WHICH" in v1|v2) ;; *) echo "usage: $0 <v1|v2> [levels]" >&2; exit 2 ;; esac
TARGET="${TRE_SSH_TARGET:-koushik.moram@10.0.62.212}"
PORT="${TRE_SSH_PORT:-2022}"
cd "$(git rev-parse --show-toplevel)"
QUERIES="${QUERIES:-scripts/bench/queries/latency_smoke.jsonl}"
STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="$WHICH-$STAMP"
SSHO=(-o BatchMode=yes -o ServerAliveInterval=30 -o LogLevel=ERROR -p "$PORT")
rs() { ssh "${SSHO[@]}" "$TARGET" "$@"; }

EXTRA="--repeat ${REPEAT:-3} --warmup ${WARMUP:-3} --build-note repo-$(git rev-parse --short HEAD)"
if [ -n "${DURATION:-}" ]; then EXTRA="$EXTRA --duration $DURATION"; else EXTRA="$EXTRA --requests ${REQUESTS:-60}"; fi

echo "== copying harness to server"
rs 'mkdir -p ~/team2/bench/out ~/team2/run' || exit 1
scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" \
  scripts/bench/load_harness.py scripts/bench/server_lock.sh scripts/bench/remote_run.sh \
  scripts/deploy/run_service.sh scripts/deploy/stop_service.sh "$TARGET:team2/bench/" || exit 1
scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" "$QUERIES" "$TARGET:team2/bench/latency_smoke.jsonl" || exit 1
rs 'cd ~/team2/bench && sed -i "s/\r$//" *.sh *.py && chmod +x *.sh'

ROUT="\$HOME/team2/bench/out/$NAME.json"
RLOG="\$HOME/team2/bench/out/$NAME.log"
RDONE="\$HOME/team2/bench/out/$NAME.exit"
echo "== starting $WHICH run $NAME (levels $LEVELS, $EXTRA)"
rs "rm -f $RDONE; nohup bash -c '\$HOME/team2/bench/server_lock.sh \$HOME/team2/bench/remote_run.sh $WHICH $LEVELS $ROUT $EXTRA; echo \$? > $RDONE' > $RLOG 2>&1 < /dev/null &"

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

mkdir -p results/load
LOCAL="results/load/$NAME.json"
scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" "$TARGET:team2/bench/out/$NAME.json" "$LOCAL" || { echo "no result file" >&2; exit 1; }
echo "== saved $LOCAL"
python scripts/bench/summarize_load.py "$LOCAL"
exit "$code"
