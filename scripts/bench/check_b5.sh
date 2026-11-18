#!/usr/bin/env bash
# Acceptance checks for work package B5 (load and latency harness).
# Run on the PC from the repository:   scripts/bench/check_b5.sh
# Prints PASS/FAIL per item and exits non-zero if any item fails.
#   SKIP_SERVER=1   skip the server items (e)
#   BASELINE_PASSED tests that passed before the B5 change (default 112)
set -uo pipefail
TARGET="${TRE_SSH_TARGET:-koushik.moram@10.0.62.212}"
PORT="${TRE_SSH_PORT:-2022}"
BASELINE_PASSED="${BASELINE_PASSED:-112}"
cd "$(git rev-parse --show-toplevel)"
FAILS=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILS=$((FAILS + 1)); }
info() { echo "      $1"; }
rs() { ssh -o BatchMode=yes -o LogLevel=ERROR -p "$PORT" "$TARGET" "$@" 2>/dev/null; }

echo "== (a) files"
for f in scripts/bench/server_lock.sh scripts/bench/load_harness.py scripts/bench/run_load.sh \
         scripts/bench/summarize_load.py scripts/bench/queries/latency_smoke.jsonl tests/test_load_harness.py; do
  [ -f "$f" ] && pass "(a) $f exists" || fail "(a) $f missing"
done
for f in scripts/bench/*.sh; do
  bash -n "$f" 2>/dev/null && pass "(a) bash -n $f" || fail "(a) syntax error in $f"
done

echo "== (b) query file"
python - <<'EOF' && pass "(b) 60 queries: 20 short, 15 cve_only, 15 incident, 10 off_topic" || fail "(b) latency_smoke.jsonl composition"
import json, collections, re, sys
rows = [json.loads(l) for l in open("scripts/bench/queries/latency_smoke.jsonl", encoding="utf-8") if l.strip()]
c = collections.Counter(r["route"] for r in rows)
ok = len(rows) == 60 and c == {"short_text": 20, "cve_only": 15, "incident": 15, "off_topic": 10}
cve = [r["query"] for r in rows if r["route"] == "cve_only"]
ok &= all(re.search(r"(?i)cve-\d{4}-\d+", q) for q in cve) and any(q != q.upper() for q in cve)
ok &= any(len(re.findall(r"(?i)cve-\d{4}-\d+", q)) > 1 for q in cve)
inc = [r["query"] for r in rows if r["route"] == "incident"]
ok &= all(3 <= len(re.findall(r"[.!?](?:\s|$)", q)) <= 6 for q in inc)
sys.exit(0 if ok else 1)
EOF

echo "== (c) unit tests (percentiles, median aggregation, status counts, fake server)"
if python -m pytest tests/test_load_harness.py -q 2>&1 | tail -3 | tee /tmp/b5_unit.txt | grep -q " passed" && ! grep -q failed /tmp/b5_unit.txt; then
  pass "(c) tests/test_load_harness.py: $(tail -1 /tmp/b5_unit.txt)"
else
  fail "(c) tests/test_load_harness.py"; cat /tmp/b5_unit.txt
fi

echo "== (d) v1 demonstration result"
RES="$(ls -1 results/load/v1-*.json 2>/dev/null | tail -1)"
if [ -z "$RES" ]; then
  fail "(d) no results/load/v1-*.json"
else
  info "file: $RES"
  RES="$RES" python - <<'EOF' && pass "(d) result has all fields and medians match the raw records" || fail "(d) result file incomplete or inconsistent"
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("lh", "scripts/bench/load_harness.py")
lh = importlib.util.module_from_spec(spec); spec.loader.exec_module(lh)
r = json.load(open(os.environ["RES"]))
bad = []
def need(cond, msg):
    if not cond: bad.append(msg)
e = r["environment"]
for k in ("date_utc", "hostname", "cpu_model", "health", "build", "load_at_start", "load_at_end"):
    need(e.get(k) not in (None, {}), "environment." + k)
cs = r.get("cold_start") or {}
need(cs.get("to_health_s") and cs.get("to_first_query_s"), "cold_start")
m = r.get("memory") or {}
need(m.get("peak_rss_mb") and m.get("idle_rss_mb_before_load") and m.get("samples_kb"), "memory")
need(r["levels"], "levels")
need(not r.get("error"), "run error: %s" % r.get("error"))
for lv in r["levels"]:
    need(lv.get("load_before") and lv.get("load_after"), "load before/after level %s" % lv["concurrency"])
    need(len(lv["reps"]) >= 3, "3 repetitions at level %s" % lv["concurrency"])
    for rep in lv["reps"]:
        need(rep.get("load_before") and rep.get("load_after"), "rep load avg")
        st = rep["stats"]
        for k in ("latency_ms", "stage_ms", "throughput_rps", "status_counts", "errors", "retry_after_seen", "memory"):
            need(k in st, "stats." + k)
        need(set(st["status_counts"]) == {"200", "503", "504", "other"}, "status keys")
    med = lv["median"]
    for k in ("p50", "p95", "p99", "max"):
        need(med["latency_ms"].get(k) is not None or med["status_counts"]["200"] == 0, "median %s" % k)
    need(med["stage_ms"] or med["status_counts"]["200"] == 0, "median stage_ms")
need(r["records"] and all("latency_ms" in x and "status" in x and "profile" in x for x in r["records"]), "raw records")
# medians vs raw records
again = lh.recompute_from_records(r)
def close(a, b):
    if isinstance(a, dict):
        return all(close(a[k], b[k]) for k in a)
    if a is None or b is None:
        return a is b
    return abs(a - b) <= 1e-6 * max(1.0, abs(a))
for lv in r["levels"]:
    need(close(lv["median"], again[lv["concurrency"]]), "median mismatch at level %s" % lv["concurrency"])
for b in bad: print("      missing/inconsistent:", b)
sys.exit(1 if bad else 0)
EOF
fi

echo "== (e) server state"
if [ "${SKIP_SERVER:-0}" = 1 ]; then
  info "skipped (SKIP_SERVER=1)"
else
  OUT="$(rs 'for p in 8765 8766; do if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then echo "listening:$p"; fi; done; if flock -n ~/team2/run/bench.lock true; then echo lock-free; else echo lock-held; fi' )"
  echo "$OUT" | grep -q listening && fail "(e1) something still listens on 8765/8766: $OUT" || pass "(e1) nothing listening on 8765 or 8766"
  echo "$OUT" | grep -q lock-free && pass "(e2) benchmark lock released" || fail "(e2) benchmark lock is held"
  # lock actually excludes a second user
  T="$(rs 'B=~/team2/bench; (flock -n 8 || exit 9; BENCH_LOCK=$HOME/team2/run/bench.lock timeout 3 $B/server_lock.sh true; echo inner=$?) 8>>~/team2/run/bench.lock' )"
  echo "$T" | grep -q 'inner=124' && pass "(e3) second user waits while the lock is held" || { fail "(e3) lock exclusion test: $T"; }
fi

echo "== (f) full test suite"
OUTF="$(python -m pytest verify tests -q 2>&1 | tail -3)"
echo "$OUTF" | sed 's/^/      /'
N="$(echo "$OUTF" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+')"
if echo "$OUTF" | grep -qE 'failed|error' || [ -z "$N" ]; then fail "(f) test suite"; \
elif [ "$N" -ge "$BASELINE_PASSED" ]; then pass "(f) $N passed (baseline $BASELINE_PASSED)"; else fail "(f) only $N passed (baseline $BASELINE_PASSED)"; fi

echo
[ "$FAILS" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "$FAILS CHECK(S) FAILED"
exit "$FAILS"
