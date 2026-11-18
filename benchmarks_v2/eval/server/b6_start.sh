#!/usr/bin/env bash
# Work package B6: start the v1 baseline on the server, detached (nohup), then return.
#     B6_BENCH_DIR=<path to data/benchmark/v2.0> benchmarks_v2/eval/server/b6_start.sh
# Copies the harness and the OPEN benchmark v2.0 files (never sealed/) to the server, then starts
# b6_server.sh under server_lock.sh. Safe to run again after an interruption: run files resume.
# Environment: TRE_SSH_TARGET, TRE_SSH_PORT, RUN_ARGS (default "--pause-after-error 30"), B6_BENCH_DIR.
set -uo pipefail
TARGET="${TRE_SSH_TARGET:-koushik.moram@10.0.62.212}"
PORT="${TRE_SSH_PORT:-2022}"
cd "$(git rev-parse --show-toplevel)"
BENCH="${B6_BENCH_DIR:-data/benchmark/v2.0}"
SSHO=(-o BatchMode=yes -o ServerAliveInterval=30 -o LogLevel=ERROR -p "$PORT")
rs() { ssh "${SSHO[@]}" "$TARGET" "$@"; }
cp_to() { scp -q -o BatchMode=yes -o LogLevel=ERROR -P "$PORT" "$@"; }
COMMIT="$(git rev-parse HEAD)"

rs 'mkdir -p ~/team2/eval/pkg/benchmarks_v2/eval ~/team2/eval/runs ~/team2/eval/out ~/team2/benchmark/v2.0 ~/team2/run' || exit 1
for f in queries.jsonl qrels.jsonl equivalence.jsonl manifest.json build_report.json; do
  cp_to "$BENCH/$f" "$TARGET:team2/benchmark/v2.0/" || exit 1
done
cp_to benchmarks_v2/__init__.py "$TARGET:team2/eval/pkg/benchmarks_v2/" || exit 1
cp_to benchmarks_v2/eval/*.py benchmarks_v2/eval/variants.yaml "$TARGET:team2/eval/pkg/benchmarks_v2/eval/" || exit 1
cp_to scripts/bench/server_lock.sh benchmarks_v2/eval/server/b6_server.sh "$TARGET:team2/eval/" || exit 1
rs 'cd ~/team2/eval && sed -i "s/\r$//" *.sh pkg/benchmarks_v2/*.py pkg/benchmarks_v2/eval/*.py pkg/benchmarks_v2/eval/*.yaml ~/team2/benchmark/v2.0/*.jsonl ~/team2/benchmark/v2.0/*.json && chmod +x *.sh' || exit 1
rs "test ! -e ~/team2/benchmark/v2.0/sealed" || { echo "sealed/ present on server" >&2; exit 5; }
RA="${RUN_ARGS:---pause-after-error 30}"
rs "rm -f \$HOME/team2/eval/out/b6.exit; nohup env RUN_ARGS='$RA' bash -c '\$HOME/team2/eval/server_lock.sh \$HOME/team2/eval/b6_server.sh $COMMIT; echo \$? > \$HOME/team2/eval/out/b6.exit' > \$HOME/team2/eval/out/b6.log 2>&1 < /dev/null & echo started pid \$!"
