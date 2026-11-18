"""End-to-end latency of the wired v2 service (C6) over HTTP, one request at a time.

    python scripts/v2/e2e_latency.py --url http://127.0.0.1:8767 --queries dev_queries.jsonl --n 300 --out e2e.json

A seeded sample of ``n`` dev questions is sent twice: the first pass measures cold questions (no query-vector
cache hit), the second repeats the same questions (warm). Reported: p50 / p95 / p99 / max per pass and per
slice, HTTP status counts (503 / 504 must be 0 for single requests), and the stages the service skipped.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import time
import urllib.request
from collections import Counter, defaultdict


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else None


def post(url, body, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
            return r.status, (time.perf_counter() - t) * 1000, data
    except urllib.error.HTTPError as e:
        return e.code, (time.perf_counter() - t) * 1000, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8767")
    ap.add_argument("--queries", required=True)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=20261118)
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    qs = [json.loads(l) for l in open(a.queries, encoding="utf-8")]
    rng = random.Random(a.seed)
    rng.shuffle(qs)
    qs = qs[: a.n]
    out = {"url": a.url, "n": len(qs), "seed": a.seed, "top_k": a.top_k, "passes": {}}
    health = json.loads(urllib.request.urlopen(a.url + "/api/v1/health", timeout=30).read())
    out["health"] = health
    for name in ("cold", "warm"):
        ms, by_slice, status, skipped, server_ms = [], defaultdict(list), Counter(), Counter(), []
        for q in qs:
            st, t, data = post(a.url + "/api/v1/threats/match", {"query": q["text"], "top_k": a.top_k})
            status[st] += 1
            ms.append(t)
            by_slice[q["slice"]].append(t)
            if data:
                server_ms.append(data["pipeline_profile"]["total_ms"])
                for s in data.get("skipped_stages", []):
                    skipped[s] += 1
        out["passes"][name] = {
            "p50_ms": pct(ms, 50), "p95_ms": pct(ms, 95), "p99_ms": pct(ms, 99), "max_ms": max(ms),
            "mean_ms": statistics.fmean(ms), "server_total_p95_ms": pct(server_ms, 95),
            "status": dict(status), "skipped_stages": dict(skipped),
            "per_slice_p95_ms": {s: pct(v, 95) for s, v in sorted(by_slice.items())}}
        print(name, json.dumps(out["passes"][name]), flush=True)
    json.dump(out, open(a.out, "w", encoding="utf-8"), indent=1)


if __name__ == "__main__":
    main()
