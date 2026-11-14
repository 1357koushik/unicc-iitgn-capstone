#!/usr/bin/env python3
"""Load and latency harness for the retrieval service (work package B5).

Runs ON the IITGN server with ~/py312/bin/python (standard library + httpx only).
Measures end-to-end latency, per-stage latency (from the response `pipeline_profile`),
throughput, status counts, memory and cold start, at several concurrency levels, with
repetitions; the reported statistic is the MEDIAN over the repetitions. All raw
per-request records are stored in the output file.

Run it under scripts/bench/server_lock.sh so two benchmarks never overlap.

Notes for fair comparison: the same query order is used for every level and repetition.
A v2 response cache will make repeated queries faster on later repetitions; that is
part of the design (plan 4.9) and is visible as lower latency in repetition 2 and 3.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:  # httpx is only needed for real runs; the pure functions below work without it.
    import httpx
except ImportError:  # pragma: no cover
    httpx = None

SCHEMA_VERSION = 1
STATUS_KEYS = ("200", "503", "504", "other")


# ----------------------------------------------------------------- pure statistics
def percentile(values, p):
    """Linear-interpolation percentile (same definition as numpy's default). p in [0, 100]."""
    xs = sorted(values)
    if not xs:
        return None
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * (p / 100.0)
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return float(xs[int(k)])
    return float(xs[lo] + (xs[hi] - xs[lo]) * (k - lo))


def count_statuses(records):
    """Counts of HTTP statuses: 200, 503, 504, other HTTP statuses; transport errors separately."""
    counts = {k: 0 for k in STATUS_KEYS}
    errors = 0
    for r in records:
        if r.get("error"):
            errors += 1
            continue
        s = r.get("status")
        if s == 200:
            counts["200"] += 1
        elif s == 503:
            counts["503"] += 1
        elif s == 504:
            counts["504"] += 1
        else:
            counts["other"] += 1
    return counts, errors


def _lat_stats(values):
    if not values:
        return {"n": 0, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "n": len(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": float(max(values)),
    }


def rep_stats(records, wall_s):
    """Statistics of one repetition at one concurrency level, from its raw records."""
    ok = [r for r in records if not r.get("error") and r.get("status") == 200]
    done = [r for r in records if not r.get("error")]
    counts, errors = count_statuses(records)
    stage_values = {}
    for r in ok:
        prof = r.get("profile")
        if isinstance(prof, dict):
            for k, v in prof.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    stage_values.setdefault(k, []).append(float(v))
    stage = {k: {"p50": percentile(v, 50), "p95": percentile(v, 95)} for k, v in sorted(stage_values.items())}
    wall_s = float(wall_s) if wall_s else 0.0
    return {
        "requests": len(records),
        "wall_s": wall_s,
        "latency_ms": _lat_stats([r["latency_ms"] for r in ok]),
        "latency_all_ms": _lat_stats([r["latency_ms"] for r in done]),
        "stage_ms": stage,
        "throughput_rps": (len(ok) / wall_s) if wall_s > 0 else None,
        "completed_rps": (len(done) / wall_s) if wall_s > 0 else None,
        "status_counts": counts,
        "errors": errors,
        "retry_after_seen": sum(1 for r in records if r.get("retry_after") is not None),
    }


def median_of_reps(stats_list):
    """Median over repetitions of every numeric leaf; recurses through dicts.
    A key missing or None in some repetitions is aggregated over the ones that have it."""
    out = {}
    keys = []
    for s in stats_list:
        for k in s:
            if k not in keys:
                keys.append(k)
    for k in keys:
        vals = [s[k] for s in stats_list if k in s and s[k] is not None]
        if not vals:
            out[k] = None
        elif all(isinstance(v, dict) for v in vals):
            out[k] = median_of_reps(vals)
        elif all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
            out[k] = float(statistics.median(vals))
        else:
            out[k] = vals[0]
    return out


def recompute_from_records(result):
    """Recompute per-level medians from the raw records of a result file (consistency check)."""
    recs = result["records"]
    out = {}
    for lvl in result["levels"]:
        c = lvl["concurrency"]
        per_rep = []
        for rep in lvl["reps"]:
            rr = [r for r in recs if r["concurrency"] == c and r["rep"] == rep["rep"]]
            st = rep_stats(rr, rep["stats"]["wall_s"])
            if rep["stats"].get("memory") is not None:  # memory comes from the RSS sampler, not the records
                st["memory"] = rep["stats"]["memory"]
            per_rep.append(st)
        out[c] = median_of_reps(per_rep)
    return out


# ----------------------------------------------------------------- server probes
def read_loadavg():
    try:
        with open("/proc/loadavg") as fh:
            p = fh.read().split()
        return {"1m": float(p[0]), "5m": float(p[1]), "15m": float(p[2])}
    except OSError:
        try:
            a = os.getloadavg()
            return {"1m": a[0], "5m": a[1], "15m": a[2]}
        except (OSError, AttributeError):
            return None


def read_cpu_model():
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def read_rss_kb(pid):
    """(VmRSS, VmHWM) in kB from /proc/<pid>/status, or None."""
    try:
        rss = hwm = None
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                elif line.startswith("VmHWM:"):
                    hwm = int(line.split()[1])
        return (rss, hwm) if rss is not None else None
    except (OSError, ValueError, IndexError):
        return None


class RssSampler(threading.Thread):
    """Samples the RSS of a process every `interval` seconds."""

    def __init__(self, pid, interval=1.0):
        super().__init__(daemon=True)
        self.pid = pid
        self.interval = interval
        self.samples = []  # (t_monotonic, rss_kb, hwm_kb)
        self._halt = threading.Event()
        self._lock = threading.Lock()

    def run(self):
        while not self._halt.is_set():
            v = read_rss_kb(self.pid)
            if v:
                with self._lock:
                    self.samples.append((time.monotonic(), v[0], v[1]))
            self._halt.wait(self.interval)

    def stop(self):
        self._halt.set()
        self.join(timeout=3)

    def window(self, t0, t1):
        """Peak and steady (median) RSS in MB over a monotonic-time window."""
        with self._lock:
            vals = [s for s in self.samples if t0 <= s[0] <= t1]
        if not vals:
            v = read_rss_kb(self.pid)
            if not v:
                return None
            vals = [(t0, v[0], v[1])]
        rss = [s[1] for s in vals]
        return {"peak_rss_mb": max(rss) / 1024.0, "steady_rss_mb": statistics.median(rss) / 1024.0,
                "samples": len(rss)}


def git_info(health, release_link):
    info = {}
    if isinstance(health, dict):
        for k in ("build_id", "commit", "git_commit", "git_sha", "version", "dataset_hash", "corpus_build"):
            if k in health:
                info[k] = health[k]
    if release_link and release_link != "none":
        try:
            info["current_symlink"] = os.path.realpath(os.path.expanduser(release_link))
        except OSError:
            pass
    return info


# ----------------------------------------------------------------- request execution
def load_queries(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rows.append({"query": d["query"], "route": d.get("route", "unlabelled")})
    if not rows:
        raise SystemExit(f"no queries in {path}")
    return rows


def one_request(client, url, query, top_k, timeout_s):
    t0 = time.perf_counter()
    rec = {"status": None, "latency_ms": None, "profile": None, "retry_after": None, "error": None}
    try:
        resp = client.post(url, json={"query": query, "top_k": top_k}, timeout=timeout_s)
        rec["latency_ms"] = (time.perf_counter() - t0) * 1000.0
        rec["status"] = resp.status_code
        ra = resp.headers.get("retry-after")
        if ra is not None:
            rec["retry_after"] = ra
        if resp.status_code == 200:
            try:
                body = resp.json()
                prof = body.get("pipeline_profile") if isinstance(body, dict) else None
                if isinstance(prof, dict):
                    rec["profile"] = prof
            except ValueError:
                pass
    except Exception as exc:  # transport error or timeout
        rec["latency_ms"] = (time.perf_counter() - t0) * 1000.0
        rec["error"] = f"{type(exc).__name__}: {exc}"[:200]
    return rec


def run_rep(url, queries, concurrency, duration, requests, top_k, timeout_s, level, rep, client_factory):
    """One repetition: `concurrency` workers pull queries until `requests` are issued or `duration` elapses."""
    lock = threading.Lock()
    state = {"next": 0}
    records = []
    clients = [client_factory() for _ in range(concurrency)]  # built before the clock starts
    t_start = time.perf_counter()
    deadline = t_start + duration if duration else None

    def take():
        with lock:
            i = state["next"]
            if requests is not None and i >= requests:
                return None
            if deadline is not None and time.perf_counter() >= deadline:
                return None
            state["next"] = i + 1
            return i

    def worker(client):
        try:
            while True:
                i = take()
                if i is None:
                    return
                q = queries[i % len(queries)]
                t_issue = time.perf_counter() - t_start
                rec = one_request(client, url, q["query"], top_k, timeout_s)
                rec.update({"concurrency": level, "rep": rep, "seq": i, "route": q["route"],
                            "query_index": i % len(queries), "t_issue_s": round(t_issue, 4)})
                with lock:
                    records.append(rec)
        finally:
            client.close()

    threads = [threading.Thread(target=worker, args=(c,), daemon=True) for c in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - t_start
    records.sort(key=lambda r: r["seq"])
    return records, wall


def wait_health(base_url, timeout_s, proc=None, poll=0.25):
    """Seconds until /api/v1/health answers 200, or None on timeout / early exit of `proc`."""
    t0 = time.perf_counter()
    url = base_url.rstrip("/") + "/api/v1/health"
    with httpx.Client(timeout=5.0) as c:
        while time.perf_counter() - t0 < timeout_s:
            try:
                if c.get(url).status_code == 200:
                    return time.perf_counter() - t0
            except Exception:
                pass
            if proc is not None and proc.poll() not in (None, 0):
                return None
            time.sleep(poll)
    return None


def fetch_health(base_url):
    try:
        with httpx.Client(timeout=10.0) as c:
            r = c.get(base_url.rstrip("/") + "/api/v1/health")
            return r.json() if r.status_code == 200 else {"http_status": r.status_code}
    except Exception as exc:
        return {"error": str(exc)[:200]}


# ----------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--queries", required=True, help="JSONL with `query` and optional `route`")
    ap.add_argument("--concurrency", default="1,4,16")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--duration", type=float, help="seconds per level and repetition")
    g.add_argument("--requests", type=int, help="requests per level and repetition")
    ap.add_argument("--warmup", type=int, default=3, help="unrecorded sequential requests before each level")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--out", required=True)
    ap.add_argument("--endpoint", default="/api/v1/threats/match")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=60.0, help="client timeout per request (s)")
    ap.add_argument("--label", default="", help="free label, e.g. v1 or v2")
    ap.add_argument("--pid", type=int, help="PID of the service (RSS sampling)")
    ap.add_argument("--pid-file", help="file holding the service PID (read after health is up)")
    ap.add_argument("--start-cmd", help="shell command that starts the service; enables cold-start timing")
    ap.add_argument("--start-timeout", type=float, default=900.0)
    ap.add_argument("--health-timeout", type=float, default=60.0, help="wait for health when no --start-cmd")
    ap.add_argument("--release-link", default="~/team2/current", help="symlink recorded as the build; 'none' to skip")
    ap.add_argument("--build-note", default="", help="free text recorded with the build (e.g. repo commit of the harness)")
    args = ap.parse_args(argv)
    if httpx is None:
        raise SystemExit("httpx is required (use ~/py312/bin/python)")
    if args.duration is None and args.requests is None:
        args.requests = 60
    levels = [int(x) for x in args.concurrency.split(",") if x.strip()]
    queries = load_queries(args.queries)
    base = args.base_url.rstrip("/")
    url = base + args.endpoint

    result = {
        "schema_version": SCHEMA_VERSION,
        "label": args.label,
        "params": {k: getattr(args, k) for k in ("base_url", "endpoint", "concurrency", "duration", "requests",
                                                 "warmup", "repeat", "top_k", "timeout")},
        "environment": {},
        "cold_start": None,
        "memory": None,
        "levels": [],
        "records": [],
        "error": None,
    }
    env = result["environment"]
    env.update({
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "cpu_model": read_cpu_model(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "httpx": httpx.__version__,
        "queries_file": os.path.basename(args.queries),
        "query_count": len(queries),
        "load_at_start": read_loadavg(),
    })

    proc = None
    pid = args.pid
    try:
        # ---- cold start
        if args.start_cmd:
            t0 = time.perf_counter()
            proc = subprocess.Popen(args.start_cmd, shell=True, start_new_session=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            t_health = wait_health(base, args.start_timeout, proc)
            if t_health is None:
                result["error"] = "service did not become healthy within start timeout"
                raise RuntimeError(result["error"])
            t_h_abs = time.perf_counter() - t0
            with httpx.Client() as c:
                first = one_request(c, url, queries[0]["query"], args.top_k, args.timeout)
            t_q_abs = time.perf_counter() - t0
            result["cold_start"] = {
                "to_health_s": t_h_abs,
                "to_first_query_s": t_q_abs if first["status"] == 200 else None,
                "first_query_status": first["status"],
                "first_query_latency_ms": first["latency_ms"],
                "note": "measured from launching --start-cmd; health polled every 0.25 s",
            }
            if first["status"] != 200:
                result["error"] = f"first query failed: status {first['status']} {first['error']}"
                raise RuntimeError(result["error"])
            if pid is None and args.pid_file:
                for _ in range(20):
                    try:
                        pid = int(Path(os.path.expanduser(args.pid_file)).read_text().strip())
                        break
                    except (OSError, ValueError):
                        time.sleep(0.5)
            if pid is None:
                pid = proc.pid
        elif not wait_health(base, args.health_timeout):
            result["error"] = "service not healthy"
            raise RuntimeError(result["error"])

        health = fetch_health(base)
        env["health"] = health
        env["build"] = git_info(health, args.release_link)
        if args.build_note:
            env["build"]["note"] = args.build_note
        env["pid"] = pid

        sampler = None
        if pid:
            sampler = RssSampler(pid)
            sampler.start()
            time.sleep(1.2)
        idle = read_rss_kb(pid) if pid else None

        def factory():
            return httpx.Client(timeout=args.timeout, limits=httpx.Limits(max_connections=None,
                                                                          max_keepalive_connections=None))

        # ---- levels
        mem_levels = {}
        for level in levels:
            lvl = {"concurrency": level, "load_before": read_loadavg(), "reps": []}
            with factory() as wc:
                for i in range(args.warmup):
                    one_request(wc, url, queries[i % len(queries)]["query"], args.top_k, args.timeout)
            all_rss = []
            for rep in range(1, args.repeat + 1):
                load_b = read_loadavg()
                m0 = time.monotonic()
                recs, wall = run_rep(url, queries, level, args.duration, args.requests, args.top_k,
                                     args.timeout, level, rep, factory)
                m1 = time.monotonic()
                st = rep_stats(recs, wall)
                if sampler:
                    st["memory"] = sampler.window(m0, m1)
                    if st["memory"]:
                        all_rss.append(st["memory"])
                lvl["reps"].append({"rep": rep, "stats": st, "load_before": load_b, "load_after": read_loadavg()})
                result["records"].extend(recs)
                p = st["latency_ms"]
                print(f"c={level} rep={rep} n={st['requests']} ok={st['status_counts']['200']} "
                      f"p50={p['p50']} p95={p['p95']} rps={st['throughput_rps']}", flush=True)
            lvl["load_after"] = read_loadavg()
            lvl["median"] = median_of_reps([r["stats"] for r in lvl["reps"]])
            result["levels"].append(lvl)

        if sampler:
            sampler.stop()
            end = read_rss_kb(pid)
            result["memory"] = {
                "idle_rss_mb_before_load": idle[0] / 1024.0 if idle else None,
                "peak_rss_mb": max((s[1] for s in sampler.samples), default=0) / 1024.0,
                "peak_hwm_mb": (end[1] / 1024.0) if end else None,
                "final_rss_mb": (end[0] / 1024.0) if end else None,
                "sample_interval_s": 1.0,
                "samples_kb": [[round(s[0] - sampler.samples[0][0], 1), s[1]] for s in sampler.samples],
            }
        env["load_at_end"] = read_loadavg()
        env["health_after"] = fetch_health(base)
    except Exception as exc:
        if not result["error"]:
            result["error"] = f"{type(exc).__name__}: {exc}"
        print("ERROR:", result["error"], file=sys.stderr)
    finally:
        out = Path(os.path.expanduser(args.out))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=1), encoding="utf-8")
        print(f"wrote {out}", flush=True)
    return 0 if not result["error"] else 1


if __name__ == "__main__":
    sys.exit(main())
