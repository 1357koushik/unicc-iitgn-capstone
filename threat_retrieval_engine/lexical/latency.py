"""Latency of the lexical retriever: query building + impact-matrix scoring + top-100, per query.

    python -m threat_retrieval_engine.lexical.latency --index <build> --queries <queries.jsonl> --out <json>

Standard library only (runs on the server with ~/py312/bin/python). Measured, following the B5 conventions
(plan 6.1 item 6: three repetitions, median reported, load average recorded):

* ``cold``: a fresh process opens the index and runs every query once; the SQLite page cache is empty. The
  operating system's file cache is not dropped (no root on the server, no equivalent on Windows), so the file
  may already be in memory; the figure is "cold process", stated as such.
* ``cold_after_warmup``: as ``cold`` but ``LexicalIndex.warm()`` runs at open, as at service start-up.
* ``warm``: in the same process, after one full warm-up pass, every query again; repeated ``--repeat`` times.

Only query texts are read from the queries file (qid, slice, split, text); a file holding test-split queries
is refused (the sealed split is never measured outside E1).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sqlite3
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def load_queries(path: Path) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                q = json.loads(line)
                if q.get("split") == "test":
                    raise SystemExit("refusing a queries file with test-split queries")
                out.append({"qid": q["qid"], "slice": q.get("slice"), "text": q["text"]})
    return out


def pct(values: list[float], p: float) -> float:
    """Nearest-rank percentile."""
    v = sorted(values)
    if not v:
        return float("nan")
    i = max(0, min(len(v) - 1, int(round(p / 100.0 * len(v) + 0.5)) - 1))
    return v[i]


def summary(ms: list[float]) -> dict:
    return {"n": len(ms), "p50": round(pct(ms, 50), 3), "p95": round(pct(ms, 95), 3), "p99": round(pct(ms, 99), 3),
            "max": round(max(ms), 3), "mean": round(sum(ms) / len(ms), 3)}


def load_average() -> list[float] | None:
    try:
        return [float(x) for x in Path("/proc/loadavg").read_text().split()[:3]]
    except OSError:
        return None


def one_pass(ix, queries: list[dict], k: int) -> list[float]:
    out = []
    for q in queries:
        t0 = time.perf_counter()
        ix.search(q["text"], k=k)
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def cold_child(index: str, queries_path: str, k: int, warm: bool) -> None:
    """Runs in a fresh process: open (and, with ``warm``, LexicalIndex.warm() as the service does at start-up),
    one pass, print the per-query times as JSON."""
    from threat_retrieval_engine.lexical.index import LexicalIndex
    qs = load_queries(Path(queries_path))
    t0 = time.perf_counter()
    ix = LexicalIndex.open(index)
    open_ms = (time.perf_counter() - t0) * 1000.0
    warm_ms = ix.warm() * 1000.0 if warm else 0.0
    times = one_pass(ix, qs, k)
    print(json.dumps({"open_ms": open_ms, "warm_ms": warm_ms, "times": times}))


def measure(index: str, queries_path: Path, k: int = 100, repeat: int = 3, label: str = "") -> dict:
    from threat_retrieval_engine.lexical.index import LexicalIndex
    qs = load_queries(queries_path)
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    cold = {}
    for mode in ("cold", "cold_after_warmup"):
        runs = []
        for _ in range(repeat):
            cmd = [sys.executable, "-m", "threat_retrieval_engine.lexical.latency", "--cold-child",
                   "--index", index, "--queries", str(queries_path), "--k", str(k)]
            if mode == "cold_after_warmup":
                cmd.append("--warm-start")
            p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=root)
            if p.returncode != 0:
                raise RuntimeError(f"cold run failed: {p.stderr[-2000:]}")
            runs.append(json.loads(p.stdout.strip().splitlines()[-1]))
        cold[mode] = runs
    ix = LexicalIndex.open(index, verify=True)
    one_pass(ix, qs, k)  # warm-up
    warm_runs = [one_pass(ix, qs, k) for _ in range(repeat)]

    def med(runs: list[list[float]]) -> dict:
        per = [summary(r) for r in runs]
        return {"repetitions": per, "median": {m: statistics.median(x[m] for x in per)
                                               for m in ("p50", "p95", "p99", "max", "mean")}}

    by_slice: dict[str, list[float]] = {}
    for q, t in zip(qs, warm_runs[-1]):
        by_slice.setdefault(q["slice"] or "-", []).append(t)
    return {
        "label": label, "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version, "cpu_count": os.cpu_count(), "load_average": load_average(),
        "index": {"build_id": ix.build_id, "index_sha256": ix.manifest.get("index_sha256"),
                  "documents": ix.n_docs, "ranking": ix.ranking.as_dict(), "impact_nnz": int(len(ix.data)),
                  "impact_mib": round(ix.memory_bytes() / 2**20, 1), "impact_load_s": round(ix.impact_seconds, 3)},
        "queries": {"path": str(queries_path), "n": len(qs)}, "k": k, "repeat": repeat,
        "what": "LexicalIndex.search: query building + impact-matrix scoring + top-k, one query at a time",
        "cold": {**med([c["times"] for c in cold["cold"]]),
                 "open_ms": statistics.median(c["open_ms"] for c in cold["cold"]),
                 "note": "fresh process, first pass, no warm-up; OS file cache not dropped"},
        "cold_after_warmup": {**med([c["times"] for c in cold["cold_after_warmup"]]),
                              "warm_ms": statistics.median(c["warm_ms"] for c in cold["cold_after_warmup"]),
                              "note": "fresh process, LexicalIndex.warm() at open (the service start-up path), "
                                      "first pass"},
        "warm": med(warm_runs),
        "warm_by_slice": {s: summary(v) for s, v in sorted(by_slice.items())},
        "load_average_end": load_average(),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--index", required=True)
    ap.add_argument("--queries", required=True)
    ap.add_argument("--k", type=int, default=100)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--label", default="")
    ap.add_argument("--out")
    ap.add_argument("--cold-child", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--warm-start", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.cold_child:
        cold_child(a.index, a.queries, a.k, a.warm_start)
        return 0
    res = measure(a.index, Path(a.queries), a.k, a.repeat, a.label)
    txt = json.dumps(res, indent=1)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(txt, encoding="utf-8", newline="\n")
    print(json.dumps({"cold": res["cold"]["median"], "cold_after_warmup": res["cold_after_warmup"]["median"],
                      "warm": res["warm"]["median"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
