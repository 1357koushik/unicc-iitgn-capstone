"""
test_hybrid_search.py
=====================
Tests for hybrid_search.py — RRF fusion of BM25 + dense, with metadata filtering.

Storage is a real embedded Qdrant + SQLite. The dense query-encoder is stubbed
so we control exactly what the dense side returns (no model download).

Run with: pytest verify/test_hybrid_search.py -v
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from bm25_index import build_from_sqlite
from hybrid_search import (
    HybridSearcher,
    build_qdrant_filter,
    reciprocal_rank_fusion,
    resolve_filter_to_ids,
)
from validator import CyberEntities, ThreatChunk
from vector_database import setup_databases, store_chunks
from vectorizer import VectorResult


# ---------------------------------------------------------------------------
# Pure RRF unit tests
# ---------------------------------------------------------------------------


def test_rrf_rewards_agreement():
    # doc "a" is top of both lists -> should win
    fused = reciprocal_rank_fusion([["a", "b", "c"], ["a", "c", "b"]], k=60)
    ranked = sorted(fused, key=lambda d: fused[d], reverse=True)
    assert ranked[0] == "a"


def test_rrf_single_list():
    fused = reciprocal_rank_fusion([["x", "y"]], k=60)
    assert fused["x"] > fused["y"]


# ---------------------------------------------------------------------------
# Integration: dense + lexical fusion over real storage
# ---------------------------------------------------------------------------


@pytest.fixture
def populated(tmp_path):
    qdrant, sqlite = setup_databases(
        str(tmp_path / "qdrant"), str(tmp_path / "sqlite" / "corpus.db")
    )

    # Distinct dense vectors so we can steer the dense side deterministically.
    vectors = {}

    def _store(cid, text, org, dense):
        dense = (np.array(dense, dtype=float) / np.linalg.norm(dense)).tolist()
        vectors[cid] = dense
        chunk = ThreatChunk(
            chunk_id=cid, doc_id=f"doc-{cid}", doc_title=f"Title {cid}",
            source_org=org, published_date=datetime(2023, 1, 1, tzinfo=timezone.utc),
            text=text, entities=CyberEntities(severity="HIGH"),
        )
        vr = VectorResult(cid, dense, {101: 0.5}, text)
        store_chunks([vr], [chunk], qdrant, sqlite)

    base = np.zeros(1024)
    va = base.copy(); va[0] = 1.0
    vb = base.copy(); vb[1] = 1.0
    vc = base.copy(); vc[2] = 1.0

    _store("A", "PsExec lateral movement across SMB shares", "CISA", va)
    _store("B", "phishing macro dropper campaign", "ENISA", vb)
    _store("C", "EternalBlue SMB remote code execution", "CISA", vc)

    bm25 = build_from_sqlite(sqlite, text_column="text")
    yield qdrant, sqlite, bm25, vectors
    sqlite.close()


def test_hybrid_returns_fused_results(populated):
    qdrant, sqlite, bm25, vectors = populated
    # Dense encoder points at chunk C; lexical query mentions "SMB" (A and C).
    searcher = HybridSearcher(qdrant, sqlite, bm25, query_encoder=lambda q: vectors["C"])
    results = searcher.search("SMB remote code execution", top_k=5)
    ids = [r.chunk_id for r in results]
    assert "C" in ids
    # C is favoured by both retrievers -> ranked first
    assert ids[0] == "C"


def test_hybrid_result_carries_ranks(populated):
    qdrant, sqlite, bm25, vectors = populated
    searcher = HybridSearcher(qdrant, sqlite, bm25, query_encoder=lambda q: vectors["A"])
    results = searcher.search("PsExec lateral movement", top_k=5)
    top = next(r for r in results if r.chunk_id == "A")
    assert top.dense_rank is not None
    assert top.lexical_rank is not None


def test_metadata_filter_restricts_to_source(populated):
    qdrant, sqlite, bm25, vectors = populated
    searcher = HybridSearcher(qdrant, sqlite, bm25, query_encoder=lambda q: vectors["C"])
    results = searcher.search("SMB", top_k=5, filters={"source_org": "ENISA"})
    # Only B is ENISA; A and C are CISA and must be excluded.
    assert all(r.chunk_id == "B" for r in results) or results == []


def test_filter_with_zero_matches_returns_empty(populated):
    qdrant, sqlite, bm25, vectors = populated
    searcher = HybridSearcher(qdrant, sqlite, bm25, query_encoder=lambda q: vectors["A"])
    results = searcher.search("SMB", top_k=5, filters={"source_org": "NOBODY"})
    assert results == []


# ---------------------------------------------------------------------------
# Filter construction / resolution
# ---------------------------------------------------------------------------


def test_build_qdrant_filter_scalar_and_list():
    assert build_qdrant_filter(None) is None
    f = build_qdrant_filter({"source_org": "CISA", "cves": ["CVE-1", "CVE-2"]})
    assert f is not None
    assert len(f.must) == 2


def test_resolve_filter_to_ids(populated):
    qdrant, sqlite, bm25, vectors = populated
    f = build_qdrant_filter({"source_org": "CISA"})
    ids = resolve_filter_to_ids(qdrant, f)
    assert ids == {"A", "C"}
