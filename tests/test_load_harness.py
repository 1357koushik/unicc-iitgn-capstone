"""Tests for scripts/bench/load_harness.py (work package B5). No external network."""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import time

import pytest

_PATH = Path(__file__).resolve().parent.parent / "scripts" / "bench" / "load_harness.py"
_spec = importlib.util.spec_from_file_location("load_harness", _PATH)
lh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lh)


# ---------------------------------------------------------------- percentiles
def test_percentile_known_values():
    xs = list(range(1, 101))  # 1..100
    assert lh.percentile(xs, 50) == pytest.approx(50.5)
    assert lh.percentile(xs, 95) == pytest.approx(95.05)
    assert lh.percentile(xs, 99) == pytest.approx(99.01)
    assert lh.percentile(xs, 100) == 100
    assert lh.percentile(xs, 0) == 1
    assert lh.percentile([7], 99) == 7
    assert lh.percentile([], 50) is None
    assert lh.percentile([3, 1, 2], 50) == 2  # unsorted input


# ---------------------------------------------------------------- status counting
def _rec(status, lat=10.0, err=None, prof=None, ra=None):
    return {"status": status, "latency_ms": lat, "error": err, "profile": prof, "retry_after": ra}


def test_status_counting():
    recs = [_rec(200), _rec(200), _rec(503, ra="1"), _rec(504), _rec(500), _rec(None, err="ReadTimeout")]
    counts, errors = lh.count_statuses(recs)
    assert counts == {"200": 2, "503": 1, "504": 1, "other": 1}
    assert errors == 1


def test_rep_stats_synthetic():
    recs = [_rec(200, lat=float(i), prof={"a_ms": float(i), "total_ms": 2.0 * i}) for i in range(1, 101)]
    recs += [_rec(503, lat=5.0, ra="2"), _rec(None, lat=9.0, err="X")]
    st = lh.rep_stats(recs, wall_s=10.0)
    assert st["latency_ms"]["n"] == 100
    assert st["latency_ms"]["p50"] == pytest.approx(50.5)
    assert st["latency_ms"]["p95"] == pytest.approx(95.05)
    assert st["latency_ms"]["max"] == 100
    assert st["stage_ms"]["total_ms"]["p50"] == pytest.approx(101.0)
    assert st["stage_ms"]["a_ms"]["p95"] == pytest.approx(95.05)
    assert st["throughput_rps"] == pytest.approx(10.0)
    assert st["completed_rps"] == pytest.approx(10.1)
    assert st["status_counts"]["503"] == 1
    assert st["errors"] == 1
    assert st["retry_after_seen"] == 1


# ---------------------------------------------------------------- median of repeats
def test_median_of_reps():
    reps = [
        {"latency_ms": {"p50": 10.0, "p95": 30.0}, "status_counts": {"200": 5, "503": 0}, "x": None},
        {"latency_ms": {"p50": 20.0, "p95": 10.0}, "status_counts": {"200": 4, "503": 1}, "x": None},
        {"latency_ms": {"p50": 12.0, "p95": 20.0}, "status_counts": {"200": 5, "503": 2}, "x": None},
    ]
    m = lh.median_of_reps(reps)
    assert m["latency_ms"] == {"p50": 12.0, "p95": 20.0}
    assert m["status_counts"] == {"200": 5.0, "503": 1.0}
    assert m["x"] is None
    # missing/None values in a repetition are skipped, not treated as zero
    m2 = lh.median_of_reps([{"v": 4.0}, {"v": None}, {"v": 8.0}])
    assert m2["v"] == 6.0
    # even number of repetitions: mean of the two middle values
    assert lh.median_of_reps([{"v": 1.0}, {"v": 3.0}])["v"] == 2.0


# ---------------------------------------------------------------- fake server
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = 65536  # send headers and body in one segment (avoids Nagle/delayed-ACK stalls)
    delay = 0.05
    fail_every = 0  # every n-th POST returns 503
    counter = 0
    lock = threading.Lock()

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"status": "healthy", "build_id": "fake-1"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        with _Handler.lock:
            _Handler.counter += 1
            c = _Handler.counter
        time.sleep(_Handler.delay)
        if _Handler.fail_every and c % _Handler.fail_every == 0:
            self.send_response(503)
            self.send_header("Retry-After", "1")
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.flush()
            return
        body = json.dumps({"top_matches": [], "pipeline_profile": {"vector_database_ms": 42.0, "total_ms": 50.0}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


@pytest.fixture()
def fake_server():
    _Handler.counter = 0
    _Handler.fail_every = 0
    _Handler.delay = 0.05
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _queries(tmp_path):
    p = tmp_path / "q.jsonl"
    p.write_text("\n".join(json.dumps({"query": f"q{i}", "route": "r"}) for i in range(5)))
    return p


def test_harness_against_fake_server(fake_server, tmp_path):
    out = tmp_path / "res.json"
    _Handler.fail_every = 10
    rc = lh.main(["--base-url", fake_server, "--queries", str(_queries(tmp_path)), "--concurrency", "1,2",
                  "--requests", "20", "--warmup", "0", "--repeat", "3", "--out", str(out)])
    assert rc == 0
    res = json.loads(out.read_text())
    assert [l["concurrency"] for l in res["levels"]] == [1, 2]
    assert len(res["records"]) == 2 * 3 * 20
    lvl1 = res["levels"][0]
    med = lvl1["median"]
    # the fake server sleeps 50 ms; latency must be within 5 ms of that (plus tiny overhead)
    assert 0.05 * 1000 - 5 <= med["latency_ms"]["p50"] <= 0.05 * 1000 + 5
    assert med["latency_ms"]["p95"] <= 0.05 * 1000 + 15
    # stage values come from the fixed pipeline_profile exactly
    assert med["stage_ms"]["vector_database_ms"]["p50"] == 42.0
    assert med["stage_ms"]["total_ms"]["p95"] == 50.0
    # forced 503: the global counter makes every 10th request fail across both levels and all reps
    c503 = sum(1 for r in res["records"] if r["status"] == 503)
    assert c503 == 12  # 120 requests, every 10th
    assert all(r["retry_after"] == "1" for r in res["records"] if r["status"] == 503)
    for lv in res["levels"]:
        for rep in lv["reps"]:
            st = rep["stats"]
            n503 = sum(1 for r in res["records"] if r["concurrency"] == lv["concurrency"]
                       and r["rep"] == rep["rep"] and r["status"] == 503)
            assert st["status_counts"]["503"] == n503
            assert st["status_counts"]["200"] + n503 == 20
            assert st["retry_after_seen"] == n503
    # environment record
    assert res["environment"]["health"]["build_id"] == "fake-1"
    assert "date_utc" in res["environment"] and "hostname" in res["environment"]
    assert lvl1["reps"][0]["load_before"] is None or "1m" in lvl1["reps"][0]["load_before"]
    # medians are consistent with the raw records
    again = lh.recompute_from_records(res)
    for lv in res["levels"]:
        assert again[lv["concurrency"]]["latency_ms"]["p50"] == pytest.approx(lv["median"]["latency_ms"]["p50"])
        assert again[lv["concurrency"]]["status_counts"] == lv["median"]["status_counts"]


def test_concurrency_gives_throughput(fake_server, tmp_path):
    out = tmp_path / "res.json"
    rc = lh.main(["--base-url", fake_server, "--queries", str(_queries(tmp_path)), "--concurrency", "1,4",
                  "--requests", "24", "--warmup", "0", "--repeat", "1", "--out", str(out)])
    assert rc == 0
    res = json.loads(out.read_text())
    t1, t4 = (l["median"]["throughput_rps"] for l in res["levels"])
    assert t4 > 2.5 * t1


def test_transport_error_counted(tmp_path):
    # nothing listens on the port: health wait fails, error recorded, non-zero exit, file still written
    out = tmp_path / "res.json"
    rc = lh.main(["--base-url", "http://127.0.0.1:9", "--queries", str(_queries(tmp_path)),
                  "--requests", "2", "--health-timeout", "1", "--out", str(out)])
    assert rc != 0
    assert json.loads(out.read_text())["error"]
