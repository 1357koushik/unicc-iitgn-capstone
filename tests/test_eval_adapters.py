"""B4 adapters and the resumable runner against a local fake HTTP service (threads + http.server)."""
from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from benchmarks_v2.eval import cli
from benchmarks_v2.eval.adapters import HttpAdapter, MappingError, TransportError, get_path, transform_doc_id
from benchmarks_v2.eval.registry import get_variant, load_registry
from benchmarks_v2.eval.runner import run_variant
from benchmarks_v2.eval.schema import Query, load_run
from eval_helpers import make_dataset, q, qrel, write_jsonl

REPO = Path(__file__).resolve().parent.parent


def match_item(doc_id, tier, prob, chunk="c"):
    return {"rank": 1, "chunk_id": chunk, "composite_score": prob, "confidence_tier": tier,
            "citations": [{"doc_id": doc_id, "doc_title": "t", "source_org": "NVD", "text_snippet": "s"}]}


class FakeService(BaseHTTPRequestHandler):
    """v1-shaped responses chosen by the query text."""

    calls: list = []

    def log_message(self, *a):  # keep test output quiet
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/v1/health":
            self._send(200, {"status": "healthy", "build": "fake-1"})
        else:
            self._send(404, {"detail": "nf"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        FakeService.calls.append((self.path, body))
        text = body["query"]
        if self.path == "/api/v1/threats/match":
            if text == "slow":
                self._send(504, {"detail": "Threat match deadline exceeded (15.0s)"})
                return
            if text == "broken":
                self._send(200, {"top_matches": [{"composite_score": 0.5}]})
                return
            if text == "empty":
                self._send(200, {"query_threat_id": "x", "top_matches": []})
                return
            # Duplicate CVE rows (NVD, KEV, EPSS) must collapse to one document, keeping the first.
            self._send(200, {"query_threat_id": "x", "top_matches": [
                match_item("CVE-2021-44228", "STRONG", 0.97),
                match_item("CVE-2021-44228_KEV", "STRONG", 0.96),
                match_item("CVE-2014-0160", "PARTIAL", 0.71),
                match_item("cve-2021-44228_EPSS", "WEAK", 0.40),
                match_item("CVE-2019-0708", "UNSUPPORTED", 0.05),
            ]})
        elif self.path == "/api/v1/search/hybrid":
            self._send(200, {"query": text, "results": [
                {"chunk_id": "h1", "rrf_score": 0.03}, {"chunk_id": "h2", "rrf_score": 0.02},
                {"chunk_id": "h3", "rrf_score": 0.01}]})
        elif self.path == "/v2/match":
            self._send(200, {"answer": {"abstain": text == "nothing"},
                             "hits": [{"doc": "attack:G0016", "rank_score": 2.5, "tier": "EXACT", "p": None}]})
        else:
            self._send(404, {"detail": "nf"})


@pytest.fixture()
def fake():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeService)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    FakeService.calls = []
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def v1_match(base):
    cfg = get_variant("v1_match")
    return HttpAdapter("v1_match", cfg, base_url=base)


def test_registry_loads_and_has_required_variants():
    reg = load_registry()
    assert {"v1_match", "v1_hybrid", "v2_match"} <= set(reg)
    assert reg["v1_match"]["adapter"] == "http_v1" and reg["v2_match"]["adapter"] == "http_v2"
    assert reg["v2_match"]["base_url"].endswith(":8766")
    assert reg["v1_match"]["request"] == {"top_k": 10}


def test_field_paths_and_cve_prefix():
    assert get_path({"a": [{"b": 3}]}, "a.0.b") == 3
    assert transform_doc_id("CVE-2021-44228_EPSS", "cve_prefix") == "CVE-2021-44228"
    assert transform_doc_id("cve-2014-0160_KEV", "cve_prefix") == "CVE-2014-0160"
    assert transform_doc_id("CVE-2021-44228", "cve_prefix") == "CVE-2021-44228"
    assert transform_doc_id("0467b0eb504d22fe", "cve_prefix") is None


def test_v1_match_maps_dedups_and_carries_confidence(fake):
    out = v1_match(fake).query("log4j")
    assert FakeService.calls[-1] == ("/api/v1/threats/match", {"query": "log4j", "top_k": 10})
    assert out["error"] is None
    # CVE-2021-44228 appears three times (NVD, _KEV, _EPSS): first occurrence kept with its tier/score.
    assert [r["doc_id"] for r in out["ranked"]] == ["CVE-2021-44228", "CVE-2014-0160", "CVE-2019-0708"]
    assert out["ranked"][0] == {"doc_id": "CVE-2021-44228", "score": 0.97, "tier": "STRONG", "probability": 0.97}
    assert out["ranked"][1]["tier"] == "PARTIAL"
    assert out["extra"] == {"http_status": 200, "raw_results": 5, "duplicates_removed": 2}
    assert out["latency_ms"] > 0 and out["abstained"] is False


def test_504_is_an_error_with_empty_ranking(fake):
    out = v1_match(fake).query("slow")
    assert out["ranked"] == [] and out["error"].startswith("http_504")
    assert out["extra"]["http_status"] == 504 and out["latency_ms"] > 0


def test_empty_results_count_as_abstention_for_v1(fake):
    out = v1_match(fake).query("empty")
    assert out["ranked"] == [] and out["abstained"] is True and out["error"] is None


def test_wrong_response_shape_stops_the_run(fake):
    with pytest.raises(MappingError):
        v1_match(fake).query("broken")


def test_hybrid_resolves_chunk_ids_read_only(fake, tmp_path):
    db = tmp_path / "corpus.db"
    con = sqlite3.connect(db)
    con.execute("create table corpus (chunk_id text, doc_id text)")
    con.executemany("insert into corpus values (?, ?)",
                    [("h1", "CVE-2014-0160"), ("h2", "CVE-2014-0160_KEV"), ("h3", "CVE-2017-0144_EPSS")])
    con.commit()
    con.close()
    cfg = get_variant("v1_hybrid")
    cfg["mapping"] = dict(cfg["mapping"], doc_id_resolver={"kind": "sqlite", "path": str(db),
                                                           "sql": "select doc_id from corpus where chunk_id = ?"})
    out = HttpAdapter("v1_hybrid", cfg, base_url=fake).query("heartbleed")
    assert FakeService.calls[-1][0] == "/api/v1/search/hybrid"
    assert [(r["doc_id"], r["score"], r["tier"], r["probability"]) for r in out["ranked"]] == [
        ("CVE-2014-0160", 0.03, None, None), ("CVE-2017-0144", 0.01, None, None)]
    assert out["extra"]["duplicates_removed"] == 1


def test_v2_mapping_is_configuration(fake):
    cfg = {"adapter": "http_v2", "base_url": fake, "endpoint": "/v2/match", "request": {"top_k": 5},
           "mapping": {"results": "hits", "doc_id": "doc", "score": "rank_score", "tier": "tier",
                       "probability": "p", "abstained": "answer.abstain", "doc_id_transform": "identity"}}
    a = HttpAdapter("v2_test", cfg)
    out = a.query("APT29")
    assert out["ranked"] == [{"doc_id": "attack:G0016", "score": 2.5, "tier": "EXACT", "probability": None}]
    assert out["abstained"] is False
    assert a.query("nothing")["abstained"] is True
    assert FakeService.calls[-1][1] == {"query": "nothing", "top_k": 5}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_unreachable_service_raises_transport_error_without_recording(tmp_path):
    cfg = dict(get_variant("v1_match"), retries=1, retry_wait_s=0)
    a = HttpAdapter("v1_match", cfg, base_url=f"http://127.0.0.1:{free_port()}")
    out = tmp_path / "run.jsonl"
    with pytest.raises(TransportError):
        run_variant("v1_match", a, [Query("T1-1", "T1", "dev", "x", True, False, {"name": "generated"}, {})], out,
                    progress=lambda m: None)
    assert not out.exists() or out.read_text() == ""
    meta = json.loads(Path(str(out) + ".meta.json").read_text())
    assert meta["sessions"][-1]["status"] == "aborted"


def test_runner_is_resumable_and_never_drops_errors(fake, tmp_path):
    qs = [Query(f"T1-{i}", "T1", "dev", t, True, False, {"name": "generated"}, {})
          for i, t in enumerate(["log4j", "slow", "log4j", "empty"], 1)]
    out = tmp_path / "run.jsonl"
    a = v1_match(fake)
    s1 = run_variant("v1_match", a, qs, out, max_queries=2, progress=lambda m: None)
    assert s1["sent"] == 2 and s1["status"] == "partial"
    # Simulate a crash in the middle of writing a line: the partial line is removed on resume.
    with open(out, "a", encoding="utf-8") as fh:
        fh.write('{"qid": "T1-3", "vari')
    n_calls = len(FakeService.calls)
    s2 = run_variant("v1_match", a, qs, out, progress=lambda m: None)
    assert s2["already_done"] == 2 and s2["sent"] == 2 and s2["status"] == "complete"
    assert len(FakeService.calls) - n_calls == 2  # done qids were skipped
    run = load_run(out)
    assert sorted(run.records) == ["T1-1", "T1-2", "T1-3", "T1-4"]
    assert run.records["T1-2"].error.startswith("http_504") and run.records["T1-2"].ranked == ()
    assert run.records["T1-4"].abstained is True
    meta = json.loads(Path(str(out) + ".meta.json").read_text())
    assert len(meta["sessions"]) == 2 and meta["sessions"][0]["service_info"]["build"] == "fake-1"
    # A third invocation sends nothing.
    s3 = run_variant("v1_match", a, qs, out, progress=lambda m: None)
    assert s3["sent"] == 0


def test_concurrent_run_writes_every_query_once(fake, tmp_path):
    qs = [Query(f"T3-{i}", "T3", "dev", "log4j", True, False, {"name": "generated"}, {}) for i in range(1, 9)]
    out = tmp_path / "run.jsonl"
    run_variant("v1_match", v1_match(fake), qs, out, concurrency=3, progress=lambda m: None)
    assert sorted(load_run(out).records) == sorted(x.qid for x in qs)


def test_cli_run_and_score_counts_504_as_miss(fake, tmp_path):
    queries = [q("T1-1", "log4j"), q("T1-2", "slow")]
    root = make_dataset(tmp_path, queries, [qrel("T1-1", "CVE-2021-44228"), qrel("T1-2", "CVE-2021-44228"),
                                            qrel("T1-1", "CVE-2014-0160", 0, "known_item"),
                                            qrel("T1-1", "CVE-2019-0708", 0, "known_item")])
    out = tmp_path / "run.jsonl"
    assert cli.main(["run", "--variant", "v1_match", "--dataset", str(root), "--split", "dev",
                     "--base-url", fake, "--out", str(out)]) == 0
    rep_json = tmp_path / "rep.json"
    assert cli.main(["score", "--run", str(out), "--dataset", str(root), "--bootstrap", "200",
                     "--json-out", str(rep_json)]) == 0
    rep = json.loads(rep_json.read_text())
    t1 = rep["populations"]["T1"]
    assert t1["metrics"]["success@1"]["value"] == 0.5  # the 504 query is a miss, not dropped
    assert t1["metrics"]["success@1"]["n"] == 2
    assert t1["errors"] == {"count": 1, "http_504": 1, "rate": 0.5, "rate_ci": t1["errors"]["rate_ci"]}


def test_cli_run_exit_code_3_when_unreachable(tmp_path):
    qf = write_jsonl(tmp_path / "q.jsonl", [q("T1-1")])
    reg = tmp_path / "variants.yaml"
    reg.write_text(
        "variants:\n  dead:\n    adapter: http_v1\n    base_url: http://127.0.0.1:%d\n    endpoint: /x\n"
        "    retries: 0\n    mapping: {results: r, doc_id: d, score: s}\n" % free_port(), encoding="utf-8")
    assert cli.main(["run", "--variant", "dead", "--registry", str(reg), "--queries", str(qf),
                     "--out", str(tmp_path / "r.jsonl")]) == 3


def test_server_side_modules_need_only_stdlib_and_yaml(tmp_path):
    """The run path must work on the server without NumPy: block numpy and run a runfile variant."""
    src = write_jsonl(tmp_path / "src.jsonl", [{"qid": "T1-1", "variant": "x", "ranked": [], "abstained": False,
                                                "latency_ms": 1.0, "error": None}])
    qf = write_jsonl(tmp_path / "q.jsonl", [q("T1-1")])
    reg = tmp_path / "variants.yaml"
    reg.write_text(f"variants:\n  rf:\n    adapter: runfile\n    path: '{src.as_posix()}'\n", encoding="utf-8")
    code = ("import sys; sys.modules['numpy'] = None; sys.modules['scipy'] = None\n"
            "from benchmarks_v2.eval.cli import main\n"
            f"rc = main(['run', '--variant', 'rf', '--registry', r'{reg}', '--queries', r'{qf}', "
            f"'--out', r'{tmp_path / 'o.jsonl'}'])\n"
            "assert 'numpy' not in sys.modules or sys.modules['numpy'] is None\n"
            "sys.exit(rc)\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert load_run(tmp_path / "o.jsonl").records["T1-1"].variant == "rf"


def test_pause_after_error_waits_but_still_records(fake, tmp_path):
    import time
    qs = [Query(f"T1-{i}", "T1", "dev", t, True, False, {"name": "generated"}, {})
          for i, t in enumerate(["slow", "log4j", "slow"], 1)]
    out = tmp_path / "run.jsonl"
    t0 = time.perf_counter()
    s = run_variant("v1_match", v1_match(fake), qs, out, progress=lambda m: None, pause_after_error_s=0.5)
    # one pause after T1-1; none after the last query
    assert 0.5 <= time.perf_counter() - t0 < 0.95
    assert s["errors"] == 2 and s["pause_after_error_s"] == 0.5
    assert load_run(out).records["T1-3"].error.startswith("http_504")
