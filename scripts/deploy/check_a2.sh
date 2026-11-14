#!/usr/bin/env bash
# Acceptance checks for work package A2 (packaging, lock file, deploy path).
# Run on the PC from the repository:   scripts/deploy/check_a2.sh
# Prints PASS/FAIL per item and exits non-zero if any item fails.
#
# Environment:
#   SKIP_SERVER=1        only run the PC-side items (a) and (b)
#   TRE_WAIT_FILE        file on the server to wait on before heavy steps
#                        (default ~/A1_BASELINE_RUNNING)
#   BASELINE_PASSED      tests that passed before the A2 change (default 108)
set -uo pipefail

TARGET="${TRE_SSH_TARGET:-koushik.moram@10.0.62.212}"
PORT="${TRE_SSH_PORT:-2022}"
WAIT_FILE="${TRE_WAIT_FILE:-\$HOME/A1_BASELINE_RUNNING}"
BASELINE_PASSED="${BASELINE_PASSED:-108}"
cd "$(git rev-parse --show-toplevel)"

FAILS=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILS=$((FAILS + 1)); }
info() { echo "      $1"; }
rs() { ssh -o BatchMode=yes -p "$PORT" "$TARGET" "$@" 2>/dev/null; }
wait_server_idle() {
  rs "while [ -e $WAIT_FILE ]; do echo waiting-for-baseline >&2; sleep 60; done; true"
}

# ---------------------------------------------------------------- (a) imports
echo "== (a) import clean-up (PC)"
if [ -z "$(grep -rn 'sys\.path' threat_retrieval_engine --include='*.py')" ]; then
  pass "(a1) no sys.path manipulation in threat_retrieval_engine"
else
  fail "(a1) sys.path still used:"; grep -rn 'sys\.path' threat_retrieval_engine --include='*.py'
fi
if [ -z "$(grep -rn 'from validator import' threat_retrieval_engine --include='*.py')" ]; then
  pass "(a2) no 'from validator import'"
else
  fail "(a2) bare validator import remains"
fi
# remaining "except ImportError": allowed only when the guarded body is a third-party import
REMAIN="$(python - <<'EOF'
import os, re
bad, ok = [], []
for dp, _, fns in os.walk("threat_retrieval_engine"):
    for fn in fns:
        if not fn.endswith(".py"):
            continue
        p = os.path.join(dp, fn)
        L = open(p, encoding="utf-8").read().split("\n")
        for i, line in enumerate(L):
            if re.match(r"\s*except ImportError", line):
                j = i - 1
                while j >= 0 and not re.match(r"\s*try:\s*$", L[j]):
                    j -= 1
                body = "\n".join(L[j + 1:i])
                (bad if "threat_retrieval_engine" in body or re.search(r"^\s*from (config|helpers|schemas|validator|pipeline|indicators|sources|api)\b", body, re.M) else ok).append(f"{p}:{i + 1}")
print("BAD", len(bad), *bad)
print("OK", len(ok), *ok)
EOF
)"
if echo "$REMAIN" | grep -q '^BAD 0'; then
  pass "(a3) every remaining 'except ImportError' guards an optional third-party import"
else
  fail "(a3) package-internal ImportError fallbacks remain: $(echo "$REMAIN" | grep '^BAD')"
fi
info "third-party-optional guards kept: $(echo "$REMAIN" | grep '^OK' | cut -c1-2000)"

# ------------------------------------------------------------------ (b) tests
echo "== (b) test suites (PC)"
OUT="$(python -m pytest verify tests -q -p no:cacheprovider 2>&1 | tail -n 3)"
SUMMARY="$(echo "$OUT" | grep -E '[0-9]+ (passed|failed|error)' | tail -n 1)"
info "pytest: $SUMMARY (before the change: $BASELINE_PASSED passed, 1 skipped, 0 failed)"
PASSED="$(echo "$SUMMARY" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo 0)"
if ! echo "$SUMMARY" | grep -qE 'failed|error' && [ "${PASSED:-0}" -ge "$BASELINE_PASSED" ]; then
  pass "(b) no failing tests; passed count not below baseline"
else
  fail "(b) failing tests or fewer passes than baseline"
fi

if [ "${SKIP_SERVER:-0}" = "1" ]; then
  echo "== server items skipped (SKIP_SERVER=1)"
  [ "$FAILS" -eq 0 ] && exit 0 || exit 1
fi

# ------------------------------------------------- (c) offline fresh-venv install
echo "== (c) fresh venv, offline install from ~/wheels (server)"
echo "   waiting while $WAIT_FILE exists ..."
wait_server_idle
DAY="$(date +%Y-%m-%d)"
VENV="\$HOME/team2/venvs/check-$DAY"
rs 'cat > $HOME/tmp/a2-check.lock' < requirements-retrieval.lock
if rs "set -e; rm -rf $VENV; \$HOME/py312/bin/python -m venv $VENV; $VENV/bin/python -m pip install --quiet --no-index --find-links \$HOME/wheels -r \$HOME/tmp/a2-check.lock && $VENV/bin/python -m pip check && $VENV/bin/python -c 'import torch, FlagEmbedding, fastapi, qdrant_client, pytest; print(\"imports ok\")'"; then
  pass "(c) venv check-$DAY installed offline from ~/wheels with the lock file"
else
  fail "(c) offline install into check-$DAY failed"
fi

# ------------------------------------------------------------ (d) deploy and run
echo "== (d) deploy.sh + run_service.sh + stop_service.sh (server)"
HEAD_SHA="$(git rev-parse HEAD)"
if ! git diff --quiet || ! git diff --cached --quiet; then
  info "working tree has uncommitted changes; deploying committed HEAD only"
fi
TRE_WAIT_FILE="$WAIT_FILE" scripts/deploy/deploy.sh "$HEAD_SHA" >/tmp/a2-deploy.log 2>&1 \
  && pass "(d1) deploy.sh $HEAD_SHA" || { fail "(d1) deploy.sh failed"; tail -n 20 /tmp/a2-deploy.log; }
# second run must be a no-op (idempotent)
scripts/deploy/deploy.sh "$HEAD_SHA" >/tmp/a2-deploy2.log 2>&1 \
  && pass "(d2) deploy.sh is idempotent (second run ok)" || fail "(d2) second deploy.sh run failed"
CUR="$(rs 'readlink $HOME/team2/current')"
[ "$(basename "$CUR")" = "${HEAD_SHA:0:9}" ] && pass "(d3) ~/team2/current -> ${HEAD_SHA:0:9}" || fail "(d3) current is '$CUR'"

wait_server_idle
if rs "TRE_START_TIMEOUT=900 \$HOME/team2/current/scripts/deploy/run_service.sh 8766 >&2" ; then
  :
fi
HEALTH="$(rs 'curl -s -m 30 http://127.0.0.1:8766/api/v1/health')"
info "health: $(echo "$HEALTH" | cut -c1-300)"
if echo "$HEALTH" | python -c 'import sys,json
d=json.load(sys.stdin)
ok=d.get("status")=="healthy" and not d.get("degraded_components") and d.get("components",{}).get("qdrant")=="available"
sys.exit(0 if ok else 1)' 2>/dev/null; then
  pass "(d4) /api/v1/health healthy, no degraded components, qdrant available"
else
  fail "(d4) health not fully healthy (qdrant 'unavailable' means v1 on 8765 still holds the Qdrant lock)"
fi
SEARCH="$(rs "curl -s -m 120 -X POST http://127.0.0.1:8766/api/v1/search/hybrid -H 'Content-Type: application/json' -d '{\"query\":\"Log4j remote code execution\",\"top_k\":5}'")"
NRES="$(echo "$SEARCH" | python -c 'import sys,json
d=json.load(sys.stdin)
r=d.get("results", d if isinstance(d,list) else [])
print(len(r), sum(1 for x in r if x.get("dense_rank") is not None))' 2>/dev/null || echo "0 0")"
if [ "${NRES%% *}" = "5" ] && [ "${NRES##* }" != "0" ]; then
  pass "(d5) hybrid search returned 5 results (${NRES##* } with a dense rank)"
else
  fail "(d5) hybrid search returned '$NRES' (results, with-dense-rank)"; echo "$SEARCH" | cut -c1-300
fi
PYP="$(rs 'pid=$(cat $HOME/team2/run/service-8766.pid); tr "\0" "\n" < /proc/$pid/environ | grep -c "^PYTHONPATH=" || true')"
[ "$(echo "$PYP" | tr -d '[:space:]')" = "0" ] && pass "(d6) process environment has no PYTHONPATH" || fail "(d6) PYTHONPATH present in /proc/<pid>/environ ($PYP)"
ENVV="$(rs 'pid=$(cat $HOME/team2/run/service-8766.pid); tr "\0" "\n" < /proc/$pid/environ | grep -E "^(CUDA_VISIBLE_DEVICES|TRE_|HF_HUB_OFFLINE|TRANSFORMERS_OFFLINE|TMPDIR|OMP_NUM_THREADS)" | tr "\n" " "')"
info "env: $ENVV"
rs 'grep -h "CPU threads" $HOME/team2/run/service-8766.log | head -2' | while read -r l; do info "log: $l"; done
if rs '$HOME/team2/current/scripts/deploy/stop_service.sh 8766 >&2'; then
  LEFT="$(rs '(exec 3<>/dev/tcp/127.0.0.1/8766) 2>/dev/null && echo busy || echo free')"
  [ "$LEFT" = "free" ] && pass "(d7) stop_service.sh: nothing left on port 8766" || fail "(d7) port 8766 still busy"
else
  fail "(d7) stop_service.sh failed"
fi

# --------------------------------------------------------------- (e) v1 still ok
echo "== (e) v1 on port 8765 (server)"
if [ "$(rs "[ -e $WAIT_FILE ] && echo busy || echo free")" = "busy" ]; then
  fail "(e) skipped: $WAIT_FILE exists (baseline running); re-run when it is gone"
else
  V1_LISTEN="$(rs '(exec 3<>/dev/tcp/127.0.0.1/8765) 2>/dev/null && echo yes || echo no')"
  if [ "$V1_LISTEN" = "yes" ]; then
    H="$(rs 'curl -s -m 30 -o /dev/null -w %{http_code} http://127.0.0.1:8765/api/v1/health')"
    [ "$H" = "200" ] && pass "(e) v1 was already running on 8765 and answers health (left running, not started by this check)" || fail "(e) v1 on 8765 answers $H"
  else
    rs 'cd ~; CUDA_VISIBLE_DEVICES= PYTHONPATH=$HOME/threat_retrieval_engine/search_engine HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 setsid nohup ~/py312/bin/python3 -m uvicorn threat_retrieval_engine.api.main:app --host 127.0.0.1 --port 8765 > $HOME/team2/run/v1-check.log 2>&1 < /dev/null & echo $! > $HOME/team2/run/v1-check.pid'
    H=000
    for _ in $(seq 1 120); do
      H="$(rs 'curl -s -m 5 -o /dev/null -w %{http_code} http://127.0.0.1:8765/api/v1/health')"
      [ "$H" = "200" ] && break
      sleep 5
    done
    [ "$H" = "200" ] && pass "(e) v1 command starts and answers health on 8765" || fail "(e) v1 health answered $H"
    rs 'kill $(cat $HOME/team2/run/v1-check.pid) 2>/dev/null; sleep 3; (exec 3<>/dev/tcp/127.0.0.1/8765) 2>/dev/null && echo "v1 still up" || echo "v1 stopped"'
  fi
fi

echo "== summary: $FAILS failing item(s)"
[ "$FAILS" -eq 0 ]
