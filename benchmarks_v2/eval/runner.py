"""Resumable runs: send each query to a variant and append one record per query to a run file.

Standard library only (runs on the server with ~/py312/bin/python).

* The run file is append-only. On start, completed qids are read back and skipped; a final line cut off by
  a crash is removed first. Every record is flushed and fsynced before the next query is sent.
* HTTP errors (including 504) and timeouts are recorded as errors with an empty ranking; they count as
  misses and are never dropped or retried.
* Transport failures (connection refused or reset) are retried by the adapter; if they persist the run
  stops with exit code 3 without recording the query, so a resumed run sends it again.
* A sidecar ``<run>.meta.json`` records the variant configuration and one entry per session (start, end,
  host, harness commit, service health response, load average, counts).
"""
from __future__ import annotations

import json
import os
import platform
import socket
import sys
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from . import HARNESS_VERSION, sealed
from .adapters import MappingError, RunfileAdapter, TransportError
from .schema import Query, ValidationError, parse_run_record


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_average() -> list[float] | None:
    try:
        return [float(x) for x in Path("/proc/loadavg").read_text().split()[:3]]
    except OSError:
        return None


def read_existing(path: Path, variant: str) -> set[str]:
    """Return qids already in the run file, repairing a truncated last line."""
    if not path.exists():
        return set()
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        cut = raw.rfind(b"\n") + 1
        print(f"[run] removing an incomplete last line ({len(raw) - cut} bytes) from {path}", file=sys.stderr)
        with open(path, "r+b") as fh:
            fh.truncate(cut)
        raw = raw[:cut]
    done: set[str] = set()
    problems: list[str] = []
    for lineno, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(f"{path.name}:{lineno}: not valid JSON ({exc.msg})")
            continue
        rec = parse_run_record(obj, f"{path.name}:{lineno}", problems)
        if rec is None:
            continue
        if rec.variant != variant:
            problems.append(f"{path.name}:{lineno}: variant {rec.variant!r} differs from {variant!r}")
        if rec.qid in done:
            problems.append(f"{path.name}:{lineno}: duplicate qid {rec.qid}")
        done.add(rec.qid)
    if problems:
        raise ValidationError(str(path), problems)
    return done


def update_meta(meta_path: Path, variant: str, describe: dict, session: dict) -> None:
    meta = {}
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta.setdefault("variant", variant)
    meta.setdefault("created_at", session["started_at"])
    meta["config"] = describe
    sessions = meta.setdefault("sessions", [])
    if sessions and sessions[-1].get("session_id") == session["session_id"]:
        sessions[-1] = session
    else:
        sessions.append(session)
    tmp = meta_path.with_suffix(meta_path.suffix + ".tmp")
    tmp.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, meta_path)


def run_variant(variant: str, adapter, queries: list[Query], out_path: Path, concurrency: int = 1,
                max_queries: int | None = None, harness_commit: str | None = None, progress=print,
                pause_after_error_s: float = 0.0) -> dict:
    """Run ``queries`` through ``adapter`` and append to ``out_path``. Returns the session summary.

    ``pause_after_error_s``: after a recorded error (e.g. HTTP 504) wait this long before the next query, so
    work the service keeps running after a timeout (plan 1.3 item 3) does not spill into the next query's
    measurement. The error itself is still recorded and counted as a miss."""
    sealed.check_query_splits({q.split for q in queries}, "running test-split queries")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path = Path(str(out_path) + ".meta.json")
    done = read_existing(out_path, variant)
    pending = [q for q in queries if q.qid not in done]
    if max_queries is not None:
        pending = pending[:max_queries]
    session = {
        "session_id": f"{now_iso()}-{os.getpid()}-{uuid.uuid4().hex[:8]}", "started_at": now_iso(), "ended_at": None,
        "host": socket.gethostname(), "platform": platform.platform(), "python": platform.python_version(),
        "harness_version": HARNESS_VERSION,
        "harness_commit": harness_commit or os.environ.get("TRE_HARNESS_COMMIT"),
        "load_average_start": load_average(), "load_average_end": None,
        "concurrency": concurrency, "pause_after_error_s": pause_after_error_s, "already_done": len(done), "selected": len(queries),
        "sent": 0, "errors": 0, "status": "running", "abort_reason": None,
        "service_info": adapter.service_info(),
    }
    update_meta(meta_path, variant, adapter.describe(), session)
    lock = threading.Lock()
    total = len(queries)
    counter = {"n": len(done)}

    def one(q: Query) -> dict:
        if isinstance(adapter, RunfileAdapter):
            r = adapter.record_for(q.qid)
        else:
            r = adapter.query(q.text)
        rec = {"qid": q.qid, "variant": variant, **r}
        problems: list[str] = []
        if parse_run_record(rec, q.qid, problems) is None:
            raise MappingError(f"{q.qid}: adapter produced an invalid record: {problems}")
        return rec

    def write(rec: dict) -> None:
        with lock:
            with open(out_path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            counter["n"] += 1
            session["sent"] += 1
            if rec["error"]:
                session["errors"] += 1
            status = rec.get("extra", {}).get("http_status", "-")
            progress(f"[run] {counter['n']}/{total} {rec['qid']} status={status} "
                     f"{rec['latency_ms'] / 1000:.2f}s docs={len(rec['ranked'])}"
                     + (f" error={rec['error'][:60]}" if rec["error"] else ""))

    try:
        if concurrency <= 1:
            for i, q in enumerate(pending):
                rec = one(q)
                write(rec)
                if rec["error"] and pause_after_error_s > 0 and i + 1 < len(pending):
                    time.sleep(pause_after_error_s)
        else:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                it = iter(pending)
                futs = set()
                for q in it:
                    futs.add(ex.submit(one, q))
                    if len(futs) >= concurrency:
                        break
                while futs:
                    fin, futs = wait(futs, return_when=FIRST_COMPLETED)
                    for f in fin:
                        write(f.result())
                        nxt = next(it, None)
                        if nxt is not None:
                            futs.add(ex.submit(one, nxt))
        session["status"] = "complete" if counter["n"] >= total else "partial"
    except TransportError as exc:
        session["status"], session["abort_reason"] = "aborted", f"transport: {exc}"
        raise
    except MappingError as exc:
        session["status"], session["abort_reason"] = "aborted", f"mapping: {exc}"
        raise
    except KeyboardInterrupt:
        session["status"], session["abort_reason"] = "aborted", "interrupted"
        raise
    finally:
        session["ended_at"] = now_iso()
        session["load_average_end"] = load_average()
        update_meta(meta_path, variant, adapter.describe(), session)
    return session
