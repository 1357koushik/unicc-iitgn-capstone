"""Leakage tests for the built benchmark collection (work package B2).

Run against built data:

    TRE_BENCHMARK_DIR="<repo>/data/benchmark/v2.0" python -m pytest tests/test_benchmark_leakage.py -q

Optional: TRE_SOURCES_DIR (B1 sources) and TRE_FEEDS_DIR (raw CVE feeds); defaults follow the repository
layout. Every test skips cleanly when the data is absent, so CI without data still passes.

The sealed split is read through ``sealed.audit_sealed``; no test prints query text or per-query results.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path

import pytest

from benchmarks_v2.build import sealed
from benchmarks_v2.build.common import default_feeds_dir, default_sources_dir
from benchmarks_v2.build.leakage import TextIndex, attack_sentence_copied, attack_sentence_refs, expansion_refs
from benchmarks_v2.build.text import content_tokens, normalize, strip_cve_ids

BENCH = os.environ.get("TRE_BENCHMARK_DIR")


def _bench() -> Path:
    if not BENCH:
        pytest.skip("TRE_BENCHMARK_DIR not set (no built benchmark data)")
    p = Path(BENCH)
    if not (p / "queries.jsonl").is_file() or not (p / sealed.SEALED_DIR / "queries.jsonl").is_file():
        pytest.skip(f"no built benchmark at {p}")
    return p


def _jsonl(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


@pytest.fixture(scope="module")
def data():
    b = _bench()
    oq, oqr = _jsonl(b / "queries.jsonl"), _jsonl(b / "qrels.jsonl")
    sq, sqr = sealed.audit_sealed(b, "leakage_test")
    eq = _jsonl(b / "equivalence.jsonl")
    return {"dir": b, "open_q": oq, "open_qrels": oqr, "test_q": sq, "test_qrels": sqr, "eq": eq,
            "queries": oq + sq, "qrels": oqr + sqr}


@pytest.fixture(scope="module")
def srcs():
    from benchmarks_v2.build.sources import Sources
    d = default_sources_dir()
    if not d.is_dir():
        pytest.skip("B1 sources not available")
    return Sources(d)


def test_sealed_files_only_under_sealed(data):
    b = data["dir"]
    assert all(q["split"] in ("train", "dev") for q in data["open_q"]), "test-split query outside sealed/"
    assert all(q["split"] == "test" for q in data["test_q"]), "non-test query inside sealed/"
    open_ids = {q["qid"] for q in data["open_q"]}
    test_ids = {q["qid"] for q in data["test_q"]}
    assert not open_ids & test_ids
    assert {r["qid"] for r in data["open_qrels"]} <= open_ids, "open qrels reference a sealed query"
    assert {r["qid"] for r in data["test_qrels"]} <= test_ids
    # no other file anywhere in the version directory carries a test qid
    for p in sorted(b.rglob("*")):
        if p.is_file() and sealed.SEALED_DIR not in p.relative_to(b).parts and p.suffix in (".jsonl", ".json"):
            txt = p.read_text(encoding="utf-8")
            leaked = sum(1 for q in test_ids if f'"{q}"' in txt)
            assert leaked == 0, f"{p.name} mentions {leaked} sealed qids"
    for p in (b / sealed.SEALED_DIR).iterdir():
        assert sealed.is_read_only(p), f"sealed file {p.name} is writable"
    with pytest.raises(sealed.SealedAccessError):
        if os.environ.get(sealed.ENV) == sealed.VALUE:
            raise sealed.SealedAccessError("E1 environment: guard deliberately open")
        sealed.open_sealed(b)


def test_no_cve_or_equivalence_set_in_two_splits(data):
    split_of = {q["qid"]: q["split"] for q in data["queries"]}
    set_of = {m: s["set_id"] for s in data["eq"] for m in s["members"]}
    seen: dict[str, set] = defaultdict(set)
    for r in data["qrels"]:
        d = r["doc_id"]
        if d.startswith("CVE-"):
            seen[d].add(split_of[r["qid"]])
            if d in set_of:
                seen[set_of[d]].add(split_of[r["qid"]])
    bad = sorted(k for k, v in seen.items() if len(v) > 1)
    assert not bad, f"{len(bad)} CVEs / equivalence sets appear in more than one split (e.g. {bad[:3]})"


def test_t6_children_follow_parent(data):
    qs = {q["qid"]: q for q in data["queries"]}
    rel = defaultdict(set)
    for r in data["qrels"]:
        rel[r["qid"]].add((r["doc_id"], r["grade"]))
    for q in qs.values():
        if q["slice"] != "T6":
            continue
        p = qs.get(q["meta"].get("parent_qid"))
        assert p is not None and p["slice"] in ("T0", "T2", "T3"), q["qid"]
        assert p["split"] == q["split"], q["qid"]
        assert rel[p["qid"]] == rel[q["qid"]], q["qid"]


def test_no_query_text_in_expansion_sources(data, srcs):
    refs, used = expansion_refs(srcs)
    if not used:
        pytest.skip("expansion sources not available")
    index = TextIndex(refs)
    raw = {strip_cve_ids(t).strip() for _, t, _ in refs}
    norm = {normalize(strip_cve_ids(t)) for _, t, _ in refs}
    bad = []
    for q in data["queries"]:
        s = strip_cve_ids(q["text"]).strip()
        if not content_tokens(q["text"]):
            continue        # identifier-only text (e.g. "CVE-A and CVE-B"): nothing that could be copied
        if s in raw or normalize(s) in norm or index.collisions(q["text"]):
            bad.append(q["qid"])
    assert not bad, f"{len(bad)} queries collide with expansion-source text (e.g. {bad[:5]})"


def test_t9_does_not_copy_attack_descriptions(data, srcs):
    from benchmarks_v2.build.attack import load_attack
    kb = load_attack(srcs, "leakage_check")
    if not kb.available:
        pytest.skip("ATT&CK source not available")
    index = TextIndex(attack_sentence_refs(kb))
    bad = [q["qid"] for q in data["queries"] if q["slice"] == "T9" and attack_sentence_copied(index, q["text"])]
    assert not bad, f"{len(bad)} T9 queries copy ATT&CK description text (e.g. {bad[:5]})"


def test_qrels_doc_ids_exist_in_universe(data, srcs):
    from benchmarks_v2.build.universe import cvelist_file_exists, scan_universe_ids
    feeds = default_feeds_dir()
    if not (feeds / "nvd_cve_data").is_dir():
        pytest.skip("raw CVE feeds not available")
    ids = scan_universe_ids(feeds)
    att = srcs.get("attack_enterprise", "leakage_check")
    attack_ids = {r.get("attack_id") for r in att.records()} if att else set()
    missing = []
    for r in data["qrels"]:
        d = r["doc_id"]
        if d.startswith("CVE-"):
            if d not in ids and not cvelist_file_exists(feeds, d):
                missing.append(d)
        elif d.startswith("attack:"):
            if d[7:] not in attack_ids:
                missing.append(d)
        else:
            missing.append(d)
    for s in data["eq"]:
        missing += [m for m in s["members"] if m not in ids and not cvelist_file_exists(feeds, m)]
    assert not missing, f"{len(missing)} qrels/equivalence doc_ids not in the universe (e.g. {missing[:5]})"


def test_unanswerable_only_t7_and_without_qrels(data):
    with_qrels = {r["qid"] for r in data["qrels"]}
    for q in data["queries"]:
        assert q["answerable"] == (q["slice"] != "T7"), q["qid"]
        if q["slice"] == "T7":
            assert q["qid"] not in with_qrels
        else:
            assert q["qid"] in with_qrels
