"""Acceptance checks for work package B4 (evaluation harness). Prints PASS/FAIL per item; exit 1 if any fails.

    python benchmarks_v2/eval/check_b4.py            (from the repository root)
    SKIP_SERVER=1  skip the server item;  SKIP_TESTS=1  skip the full test run
    BASELINE_PASSED  tests that passed before B4 (default 146)
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
EVAL = ROOT / "benchmarks_v2" / "eval"
EXAMPLE = ROOT / "results" / "eval" / "example"
FAILS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
    if not ok:
        FAILS.append(name)


def cli(*args, env=None) -> subprocess.CompletedProcess:
    e = dict(os.environ if env is None else env)
    return subprocess.run([sys.executable, "-m", "benchmarks_v2.eval", *args], cwd=ROOT, capture_output=True,
                          text=True, env=e)


def item_files():
    print("== (a) deliverables present")
    need = ["__init__.py", "__main__.py", "cli.py", "schema.py", "sealed.py", "metrics.py", "calibration.py",
            "stats.py", "scoring.py", "report.py", "gates.py", "pool.py", "registry.py", "adapters.py", "runner.py",
            "variants.yaml", "gates.yaml", "METHODS.md", "server/remote_eval.sh", "server/server_eval.sh",
            "example/dataset/queries.jsonl", "example/dataset/qrels.jsonl", "example/dataset/manifest.json"]
    missing = [n for n in need if not (EVAL / n).exists()]
    tests = sorted(p.name for p in (ROOT / "tests").glob("test_eval_*.py"))
    check("(a) harness files", not missing, ", ".join(missing) or f"{len(need)} files")
    check("(a) tests/test_eval_*.py", len(tests) >= 6, ", ".join(tests))
    from benchmarks_v2.eval.gates import load_gates
    from benchmarks_v2.eval.registry import load_registry
    reg = load_registry()
    check("(a) variants.yaml valid with v1_match, v1_hybrid, v2_match",
          {"v1_match", "v1_hybrid", "v2_match"} <= set(reg))
    g = load_gates()
    check("(a) gates.yaml valid", len(g["gates"]) >= 15, f"{len(g['gates'])} gates, status {g.get('status')}")


def item_tests():
    print("== (b) test suite")
    if os.environ.get("SKIP_TESTS"):
        print("SKIP  (b) SKIP_TESTS set")
        return
    base = int(os.environ.get("BASELINE_PASSED", "146"))
    r = subprocess.run([sys.executable, "-m", "pytest", "verify", "tests", "-q", "-p", "no:cacheprovider"],
                       cwd=ROOT, capture_output=True, text=True)
    tail = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-300:]
    m = re.search(r"(\d+) passed", tail)
    passed = int(m.group(1)) if m else 0
    bad = re.search(r"(\d+) (failed|error)", tail)
    check("(b) python -m pytest verify tests -q", r.returncode == 0 and not bad and passed > base,
          f"{tail}; baseline {base}")
    r2 = subprocess.run([sys.executable, "-m", "pytest", *sorted(str(p) for p in (ROOT / "tests").glob("test_eval_*.py")),
                         "-q", "-p", "no:cacheprovider"], cwd=ROOT, capture_output=True, text=True)
    t2 = r2.stdout.strip().splitlines()[-1] if r2.stdout.strip() else ""
    check("(b) B4 tests", r2.returncode == 0, t2)


def item_methods():
    print("== (c) METHODS.md consistent with the code")
    from benchmarks_v2.eval import calibration as cal, metrics, stats
    from benchmarks_v2.eval.cli import build_parser
    from benchmarks_v2.eval.metrics import Settings, query_judgements, ranking_metrics
    from benchmarks_v2.eval.schema import Query, build_equivalence
    import numpy as np
    text = (EVAL / "METHODS.md").read_text(encoding="utf-8")
    m = re.search(r"```methods-check\n(.*?)```", text, re.S)
    check("(c) METHODS.md has a methods-check block", m is not None)
    if not m:
        return
    spec = json.loads(m.group(1))
    s = Settings().as_dict()
    diff = {k: (v, s.get(k)) for k, v in spec["settings"].items() if s.get(k) != v}
    check("(c) default settings match Settings()", not diff, str(diff) if diff else f"{len(spec['settings'])} values")
    sc = build_parser()._subparsers._group_actions[0].choices["score"]
    dflt = {a.dest: a.default for a in sc._actions}
    cli_map = {"bootstrap": "bootstrap", "seed": "seed", "min_grade": "min_grade", "ece_bins": "ece_bins",
               "calib_depth": "calib_depth", "ni_alpha": "ni_alpha", "ni_margin": "noninferiority_margin",
               "false_accept_min_tier": "false_accept_min_tier"}
    cdiff = {k: (spec["settings"][k], dflt[c]) for k, c in cli_map.items() if dflt[c] != spec["settings"][k]}
    cdiff.update({} if dflt["ni_metrics"].split(",") == spec["settings"]["ni_metrics"] else
                 {"ni_metrics": (spec["settings"]["ni_metrics"], dflt["ni_metrics"])})
    check("(c) score CLI defaults match METHODS.md", not cdiff, str(cdiff) if cdiff else "")
    consts_ok = (metrics.DEPTH == spec["depth"] and metrics.UNJUDGED_RELEVANT_GRADE == spec["unjudged_relevant_grade"]
                 and stats.CHUNK == spec["bootstrap_block"]
                 and all(metrics.gain(int(g)) == v for g, v in spec["gain"].items())
                 and math.isclose(metrics.discount(3), 0.5))
    check("(c) depth, scenario grade, bootstrap block, gain 2^g-1, log2 discount", consts_ok)
    for ex in spec["examples"]:
        if "ranking" in ex:
            eq = build_equivalence([(f"s{i}", mm) for i, mm in enumerate(ex["equivalence"])])
            q = Query("T0-1", "T0", "dev", "t", True, False, {"name": "generated"}, {})
            got = ranking_metrics([eq.unit(d) for d in ex["ranking"]], query_judgements(q, ex["grades"], eq),
                                  spec["settings"]["min_grade"])[0][ex["metric"]]
        elif "p" in ex:
            sp = cal.SortedPredictions(np.array(ex["p"]), np.array(ex["y"]), np.arange(len(ex["p"])))
            got = cal.ece(sp, None, ex["bins"])[0]
        else:
            got = cal.wilson_interval(ex["x"], ex["n"])[1]
        check(f"(c) worked example: {ex['what']}", abs(got - ex["expected"]) < 1e-6, f"code {got:.6f}, doc {ex['expected']}")


def item_example():
    print("== (d) example report from the server demonstration")
    reps = sorted(EXAMPLE.glob("*.json"))
    reps = [p for p in reps if not p.name.endswith(".meta.json")]
    check("(d) results/eval/example/*.json exists", bool(reps), ", ".join(p.name for p in reps))
    for p in reps:
        rep = json.loads(p.read_text(encoding="utf-8"))
        ov = rep["populations"]["overall"]
        cis = [ov["metrics"][k]["ci"] for k in ("success@1", "ndcg@10", "mrr@10")]
        check(f"(d) {p.name}: intervals on overall metrics", all(c is not None and len(c) == 2 for c in cis),
              ", ".join(f"{k} {ov['metrics'][k]['value']:.3f} {ov['metrics'][k]['ci']}" for k in ("success@1", "ndcg@10")))
        check(f"(d) {p.name}: markdown present", p.with_suffix(".md").exists())
        cfg = rep["variant"].get("config") or {}
        srv = rep["variant"].get("server") or {}
        check(f"(d) {p.name}: http_v1 run on the server with provenance",
              cfg.get("adapter") == "http_v1" and bool(srv.get("host")) and bool(rep["harness"].get("commit"))
              and len(rep["dataset"].get("manifest_sha256") or "") == 64 and rep["dataset"].get("manifest_verified"),
              f"host {srv.get('host')}, harness {str(rep['harness'].get('commit'))[:10]}, {rep['n_evaluated']} queries")
        run_name = Path(rep["variant"]["run_file"]).name
        local = EXAMPLE / run_name
        if local.exists():
            from benchmarks_v2.eval.schema import sha256_file
            check(f"(d) {p.name}: committed run file matches the report's sha256",
                  sha256_file(local) == rep["variant"]["run_sha256"], run_name)
        else:
            check(f"(d) {p.name}: run file {run_name} committed next to the report", False)


def item_sealed():
    print("== (e) sealed test split refused without TRE_OPEN_SEALED=E1")
    env = {k: v for k, v in os.environ.items() if k != "TRE_OPEN_SEALED"}
    ds = EVAL / "example" / "dataset"
    with tempfile.TemporaryDirectory() as td:
        r = cli("run", "--variant", "v1_match", "--dataset", str(ds), "--split", "test", "--out", f"{td}/o.jsonl", env=env)
        check("(e) run --split test refused (exit 4, nothing contacted or written)",
              r.returncode == 4 and "TRE_OPEN_SEALED=E1" in r.stderr and not Path(f"{td}/o.jsonl").exists(),
              r.stderr.strip()[:120])
        r = cli("score", "--run", str(next(EXAMPLE.glob("*.jsonl"), ds / "queries.jsonl")), "--dataset", str(ds),
                "--split", "test", env=env)
        check("(e) score --split test refused", r.returncode == 4)
        env2 = dict(env, TRE_OPEN_SEALED="e1")
        r = cli("validate", "--dataset", str(ds), "--split", "test", env=env2)
        check("(e) a wrong TRE_OPEN_SEALED value does not open it", r.returncode == 4)


def item_one_command():
    print("== (f) one command evaluates a named variant")
    ds = EVAL / "example" / "dataset"
    with tempfile.TemporaryDirectory() as td:
        r = cli("run", "--variant", "example_v1_match", "--dataset", str(ds), "--split", "dev", "--out", f"{td}/r.jsonl")
        r2 = cli("score", "--run", f"{td}/r.jsonl", "--dataset", str(ds), "--bootstrap", "200", "--allow-unjudged",
                 "--json-out", f"{td}/r.json")
        ok = r.returncode == 0 and r2.returncode == 0 and Path(f"{td}/r.json").exists()
        check("(f) run + score of the registered example variant", ok, (r.stderr + r2.stderr).strip()[:200])


def item_server():
    print("== (g) nothing left running on the server")
    if os.environ.get("SKIP_SERVER"):
        print("SKIP  (g) SKIP_SERVER set")
        return
    target = os.environ.get("TRE_SSH_TARGET", "koushik.moram@10.0.62.212")
    port = os.environ.get("TRE_SSH_PORT", "2022")
    cmd = ("ps -u $USER -o pid=,cmd= | grep -E 'uvicorn|benchmarks_v2.eval|server_eval|server_lock' | grep -v grep; "
           "echo ---; for p in 8765 8766; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo port $p open; done; "
           "echo ---; flock -n ~/team2/run/bench.lock -c 'echo lock-free' || echo lock-held")
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-p", port, target, cmd],
                       capture_output=True, text=True, timeout=60)
    parts = r.stdout.split("---")
    if len(parts) != 3:
        check("(g) server reachable", False, r.stderr.strip()[:200])
        return
    procs, ports, lock = (x.strip() for x in parts)
    check("(g) no service or harness process of this user", procs == "", procs[:200])
    check("(g) ports 8765 and 8766 closed", ports == "", ports)
    check("(g) benchmark lock free", lock == "lock-free", lock)


def main() -> int:
    for f in (item_files, item_tests, item_methods, item_example, item_sealed, item_one_command, item_server):
        try:
            f()
        except Exception as exc:  # a crashing check is a failing check
            check(f"{f.__name__} raised {type(exc).__name__}", False, str(exc)[:300])
    print(f"== B4 acceptance: {'PASS' if not FAILS else 'FAIL'} ({len(FAILS)} failing)")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
