"""Latency of dense retrieval on the server: exact search and query encoding, measured separately.

    python -m threat_retrieval_engine.dense.latency search --index <build> --queries dev_queries.jsonl --out s.json
    python -m threat_retrieval_engine.dense.latency encode --models bge-m3,... --queries dev_queries.jsonl --out e.json

Run under the benchmark lock (scripts/dense/server_latency.sh), CPU only. B5 conventions: three repetitions,
median of the per-repetition percentiles reported, load average recorded at start and end.

``search``: every query is encoded once (not timed), then ``DenseIndex.search(v, k=100)`` is timed one query
at a time, CVE kind and all kinds, for each BLAS thread count of ``--blas-threads`` (the count is fixed from
this sweep: the lowest p95, ties to fewer threads); the index open time (sha256 checks + reading the matrix
into RAM) is reported from a fresh process.
``encode``: one query at a time (batch 1, the serving path, cache off), for each torch thread count of
``--torch-threads`` on a fixed sample of ``--sample`` queries (seeded, stratified by slice), then the chosen
count on every query, three repetitions. With several models, each model's p50/p95 at the chosen count is
reported (the comparison's tie-break input).

Only query texts are read; a queries file holding test-split queries is refused.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


def load_queries(path: Path) -> list[dict]:
    out = []
    for line in open(path, encoding="utf-8"):
        if line.strip():
            q = json.loads(line)
            if q.get("split") == "test":
                raise SystemExit("refusing a queries file with test-split queries")
            out.append({"qid": q["qid"], "slice": q.get("slice"), "text": q["text"]})
    return out


def pct(values: list[float], p: float) -> float:
    v = sorted(values)
    if not v:
        return float("nan")
    i = max(0, min(len(v) - 1, int(round(p / 100.0 * len(v) + 0.5)) - 1))
    return v[i]


def summary(ms: list[float]) -> dict:
    return {"n": len(ms), "p50": round(pct(ms, 50), 3), "p95": round(pct(ms, 95), 3), "p99": round(pct(ms, 99), 3),
            "max": round(max(ms), 3), "mean": round(sum(ms) / len(ms), 3)}


def med(runs: list[list[float]]) -> dict:
    per = [summary(r) for r in runs]
    return {"repetitions": per, "median": {m: statistics.median(x[m] for x in per) for m in ("p50", "p95", "p99", "max",
                                                                                              "mean")}}


def load_average():
    try:
        return [float(x) for x in Path("/proc/loadavg").read_text().split()[:3]]
    except OSError:
        return None


def host() -> dict:
    return {"host": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version(),
            "cpu_count": os.cpu_count(), "numpy": np.__version__,
            "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def sample(qs: list[dict], n: int, seed: int = 20261117) -> list[dict]:
    if n >= len(qs):
        return list(qs)
    by: dict[str, list[dict]] = {}
    for q in qs:
        by.setdefault(q["slice"] or "-", []).append(q)
    rnd = random.Random(seed)
    out = []
    for sl in sorted(by):
        k = max(1, round(n * len(by[sl]) / len(qs)))
        out += rnd.sample(by[sl], min(k, len(by[sl])))
    return out[:n]


def open_child(index: str) -> None:
    from threat_retrieval_engine.dense.index import DenseIndex
    t0 = time.perf_counter()
    ix = DenseIndex.open(index)
    print(json.dumps({"open_ms": (time.perf_counter() - t0) * 1000, "mib": ix.memory_bytes() / 2**20}))


def measure_search(index: str, queries: Path, blas_threads: list[int], repeat: int, torch_threads: int) -> dict:
    from threat_retrieval_engine.dense.index import DenseIndex, set_blas_threads
    from threat_retrieval_engine.dense.retriever import DenseRetriever
    qs = load_queries(queries)
    la0 = load_average()
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    opens = []
    for _ in range(repeat):
        p = subprocess.run([sys.executable, "-m", "threat_retrieval_engine.dense.latency", "open-child", "--index", index],
                           capture_output=True, text=True, env=env, cwd=root)
        if p.returncode != 0:
            raise RuntimeError(p.stderr[-2000:])
        opens.append(json.loads(p.stdout.strip().splitlines()[-1]))
    ix = DenseIndex.open(index)
    r = DenseRetriever(ix, torch_threads=torch_threads)
    t0 = time.perf_counter()
    vecs = [r.encode(q["text"])[0] for q in qs]
    enc_s = time.perf_counter() - t0
    sweep = {}
    for kinds_name, kinds in (("cve", ("cve",)), ("all", None)):
        sweep[kinds_name] = {}
        for bt in blas_threads:
            info = set_blas_threads(bt)
            for v in vecs[:50]:
                ix.search(v, k=100, kinds=kinds)  # warm-up
            runs = []
            for _ in range(repeat):
                ms = []
                for v in vecs:
                    t = time.perf_counter()
                    ix.search(v, k=100, kinds=kinds)
                    ms.append((time.perf_counter() - t) * 1000)
                runs.append(ms)
            sweep[kinds_name][str(bt)] = {**med(runs), "blas": info}
    chosen = min(blas_threads, key=lambda b: (sweep["cve"][str(b)]["median"]["p95"], b))
    by_slice = {}
    set_blas_threads(chosen)
    for q, v in zip(qs, vecs):
        t = time.perf_counter()
        ix.search(v, k=100, kinds=("cve",))
        by_slice.setdefault(q["slice"] or "-", []).append((time.perf_counter() - t) * 1000)
    return {"what": "DenseIndex.search(v, k=100): one BLAS matrix-vector product + exact top-100, one query at a time",
            **host(), "load_average": la0, "load_average_end": load_average(),
            "index": ix.info(), "queries": {"path": str(queries), "n": len(qs)}, "repeat": repeat,
            "query_encoding_untimed_s": round(enc_s, 1), "blas_sweep": sweep, "blas_threads_chosen": chosen,
            "chosen": {"cve": sweep["cve"][str(chosen)]["median"], "all": sweep["all"][str(chosen)]["median"]},
            "by_slice_cve": {s: summary(v) for s, v in sorted(by_slice.items())},
            "open_fresh_process": {"repetitions": opens, "median_ms": statistics.median(o["open_ms"] for o in opens)}}


def measure_encode(models: list[str], queries: Path, torch_threads: list[int], n_sample: int, repeat: int,
                   full_model: str | None, max_tokens: int) -> dict:
    import torch
    from threat_retrieval_engine.dense.encoder import Encoder, set_torch_threads
    qs = load_queries(queries)
    sm = sample(qs, n_sample)
    la0 = load_average()
    out: dict = {"what": "query encoding, batch 1, tokenization + forward + pooling + normalisation, cache off",
                 **host(), "load_average": la0, "queries": {"path": str(queries), "n": len(qs), "sample": len(sm)},
                 "max_tokens": max_tokens, "repeat": repeat, "torch": torch.__version__, "models": {}}

    def one_pass(enc, items):
        ms = []
        for q in items:
            t = time.perf_counter()
            enc.encode_queries([q["text"]], max_tokens=max_tokens)
            ms.append((time.perf_counter() - t) * 1000)
        return ms

    for name in models:
        enc = Encoder.load(name, batch_size=1)
        sweep = {}
        for tt in torch_threads:
            set_torch_threads(tt)
            one_pass(enc, sm[:20])
            sweep[str(tt)] = med([one_pass(enc, sm) for _ in range(repeat)])
        chosen = min(torch_threads, key=lambda t: (sweep[str(t)]["median"]["p95"], t))
        entry = {"thread_sweep_sample": sweep, "torch_threads_chosen": chosen,
                 "sample_at_chosen": sweep[str(chosen)]["median"], "encoder": enc.info()}
        if full_model in (name, "all") or name in (full_model or "").split(","):
            set_torch_threads(chosen)
            runs = [one_pass(enc, qs) for _ in range(repeat)]
            entry["all_queries_at_chosen"] = med(runs)
            by: dict[str, list[float]] = {}
            for q, t in zip(qs, runs[-1]):
                by.setdefault(q["slice"] or "-", []).append(t)
            entry["all_queries_by_slice"] = {s: summary(v) for s, v in sorted(by.items())}
        out["models"][name] = entry
        del enc
    out["load_average_end"] = load_average()
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("search")
    p.add_argument("--index", required=True)
    p.add_argument("--queries", required=True, type=Path)
    p.add_argument("--blas-threads", default="1,2,4,8,12,16,24")
    p.add_argument("--torch-threads", type=int, default=12)
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--out", type=Path)
    p = sub.add_parser("encode")
    p.add_argument("--models", required=True)
    p.add_argument("--queries", required=True, type=Path)
    p.add_argument("--torch-threads", default="4,8,12,16,24")
    p.add_argument("--sample", type=int, default=300)
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--full", help="model measured on every query at its chosen thread count")
    p.add_argument("--max-tokens", type=int, default=256)
    p.add_argument("--out", type=Path)
    p = sub.add_parser("open-child")
    p.add_argument("--index", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "open-child":
        open_child(a.index)
        return 0
    if a.cmd == "search":
        res = measure_search(a.index, a.queries, [int(x) for x in a.blas_threads.split(",")], a.repeat, a.torch_threads)
        brief = {"blas_threads_chosen": res["blas_threads_chosen"], **res["chosen"],
                 "open_ms": res["open_fresh_process"]["median_ms"]}
    else:
        res = measure_encode(a.models.split(","), a.queries, [int(x) for x in a.torch_threads.split(",")], a.sample,
                             a.repeat, a.full, a.max_tokens)
        brief = {m: {"threads": e["torch_threads_chosen"], **e["sample_at_chosen"],
                     **({"all": e["all_queries_at_chosen"]["median"]} if "all_queries_at_chosen" in e else {})}
                 for m, e in res["models"].items()}
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(res, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps(brief, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
