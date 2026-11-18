#!/usr/bin/env python3
"""Print a markdown summary of one or more load-harness result files (work package B5).

    python scripts/bench/summarize_load.py results/load/v1-*.json [results/load/v2-*.json]

With several files the columns sit side by side (v1 against v2). Values are medians over the repetitions.
"""
import json
import sys
from pathlib import Path


def fmt(v, nd=1):
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def build(files):
    data = [(Path(f).name.replace(".json", ""), json.loads(Path(f).read_text(encoding="utf-8"))) for f in files]
    out = []
    out.append("| | " + " | ".join(n for n, _ in data) + " |")
    out.append("|---|" + "---|" * len(data))

    def row(label, fn):
        out.append(f"| {label} | " + " | ".join(fn(d) for _, d in data) + " |")

    row("label", lambda d: d.get("label") or "-")
    row("date (UTC)", lambda d: d["environment"].get("date_utc", "-"))
    row("host / CPU", lambda d: f"{d['environment'].get('hostname')} / {d['environment'].get('cpu_model')}")
    row("build", lambda d: json.dumps(d["environment"].get("build", {}))[:70])
    row("load avg at start (1m)", lambda d: fmt((d["environment"].get("load_at_start") or {}).get("1m"), 2))
    row("requests per level x reps", lambda d: f"{d['params'].get('requests') or str(d['params'].get('duration')) + 's'} x {d['params'].get('repeat')}")
    row("cold start: to health (s)", lambda d: fmt((d.get("cold_start") or {}).get("to_health_s")))
    row("cold start: to first query (s)", lambda d: fmt((d.get("cold_start") or {}).get("to_first_query_s")))
    mem = lambda d: d.get("memory") or {}
    row("RSS idle before load (MB)", lambda d: fmt(mem(d).get("idle_rss_mb_before_load"), 0))
    row("RSS peak overall (MB)", lambda d: fmt(mem(d).get("peak_rss_mb"), 0))
    row("run error", lambda d: d.get("error") or "none")
    text = "\n".join(out)

    levels = sorted({l["concurrency"] for _, d in data for l in d["levels"]})
    for c in levels:
        meds = []
        for _, d in data:
            m = next((l["median"] for l in d["levels"] if l["concurrency"] == c), None)
            meds.append(m)
        t = [f"\n\n#### Concurrency {c} (median of repetitions)\n",
             "| metric | " + " | ".join(n for n, _ in data) + " |", "|---|" + "---|" * len(data)]

        def r(label, fn, nd=1):
            vals = []
            for m in meds:
                try:
                    vals.append(fmt(fn(m), nd) if m else "-")
                except (KeyError, TypeError):
                    vals.append("-")
            t.append(f"| {label} | " + " | ".join(vals) + " |")

        r("requests per rep", lambda m: m["requests"], 0)
        for k in ("p50", "p95", "p99", "max"):
            r(f"latency {k} (ms, HTTP 200)", lambda m, k=k: m["latency_ms"][k], 0)
        r("latency p95 incl. non-200 (ms)", lambda m: m["latency_all_ms"]["p95"], 0)
        r("throughput (200/s)", lambda m: m["throughput_rps"], 3)
        r("completed (any status)/s", lambda m: m["completed_rps"], 3)
        for k in ("200", "503", "504", "other"):
            r(f"HTTP {k} per rep", lambda m, k=k: m["status_counts"][k], 1)
        r("transport errors per rep", lambda m: m["errors"], 1)
        r("responses with Retry-After per rep", lambda m: m["retry_after_seen"], 1)
        r("RSS peak (MB)", lambda m: m["memory"]["peak_rss_mb"], 0)
        r("RSS steady (MB)", lambda m: m["memory"]["steady_rss_mb"], 0)
        stages = sorted({s for m in meds if m for s in (m.get("stage_ms") or {})})
        for s in stages:
            r(f"{s} p50 (ms)", lambda m, s=s: m["stage_ms"][s]["p50"], 1)
            r(f"{s} p95 (ms)", lambda m, s=s: m["stage_ms"][s]["p95"], 1)
        text += "\n".join(t)
    return text


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    print(build(sys.argv[1:]))
