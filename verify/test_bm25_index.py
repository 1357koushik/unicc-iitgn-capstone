"""
test_bm25_index.py
==================
Tests for bm25_index.py — the Okapi BM25 lexical index.

Run with: pytest verify/test_bm25_index.py -v
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bm25_index import BM25Index, build_from_sqlite


def _sample_index() -> BM25Index:
    idx = BM25Index()
    idx.add("d1", "Lateral movement using PsExec after SMB exploitation")
    idx.add("d2", "Phishing email delivering a malicious macro document")
    idx.add("d3", "Exploitation of CVE-2017-0144 EternalBlue via SMB")
    idx.finalize()
    return idx


# ---------------------------------------------------------------------------
# Ranking behaviour
# ---------------------------------------------------------------------------


def test_search_ranks_relevant_doc_first():
    idx = _sample_index()
    hits = idx.search("psexec lateral movement", top_k=3)
    assert hits
    assert hits[0].chunk_id == "d1"


def test_cve_exact_match_lands_on_right_doc():
    idx = _sample_index()
    hits = idx.search("CVE-2017-0144", top_k=3)
    assert hits[0].chunk_id == "d3"


def test_unknown_terms_return_nothing():
    idx = _sample_index()
    hits = idx.search("kubernetes helm chart", top_k=3)
    assert hits == []


def test_scores_are_descending():
    idx = _sample_index()
    hits = idx.search("SMB exploitation", top_k=3)
    scores = [h.score for h in hits]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# allowed_ids metadata-filter hook
# ---------------------------------------------------------------------------


def test_allowed_ids_restricts_results():
    idx = _sample_index()
    hits = idx.search("SMB exploitation", top_k=5, allowed_ids={"d3"})
    assert {h.chunk_id for h in hits} <= {"d3"}


def test_empty_allowed_ids_returns_nothing():
    idx = _sample_index()
    hits = idx.search("SMB", top_k=5, allowed_ids=set())
    assert hits == []


# ---------------------------------------------------------------------------
# Index maintenance
# ---------------------------------------------------------------------------


def test_replacing_document_updates_postings():
    idx = BM25Index()
    idx.add("d1", "original text about firewalls")
    idx.add("d1", "replacement text about ransomware")  # same id, new content
    idx.finalize()
    assert idx.size == 1
    assert idx.search("firewalls") == []
    assert idx.search("ransomware")[0].chunk_id == "d1"


def test_empty_index_search_is_safe():
    idx = BM25Index()
    idx.finalize()
    assert idx.search("anything") == []


# ---------------------------------------------------------------------------
# build_from_sqlite
# ---------------------------------------------------------------------------


def test_build_from_sqlite(tmp_path):
    db = sqlite3.connect(":memory:")
    db.execute(
        "CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, text TEXT, enriched_text TEXT)"
    )
    db.executemany(
        "INSERT INTO corpus (chunk_id, text, enriched_text) VALUES (?, ?, ?)",
        [
            ("c1", "raw one", "enriched EternalBlue SMB CVE-2017-0144"),
            ("c2", "raw two", "enriched phishing macro"),
        ],
    )
    db.commit()

    idx = build_from_sqlite(db, text_column="enriched_text")
    assert idx.size == 2
    hits = idx.search("CVE-2017-0144", top_k=2)
    assert hits[0].chunk_id == "c1"
