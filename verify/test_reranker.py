"""
test_reranker.py
================
Tests for reranker.py — the cross-encoder reranking layer.

The heavy BGE reranker model is replaced with a deterministic stub scorer, so
these run instantly with no download.

Run with: pytest verify/test_reranker.py -v
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hybrid_search import HybridResult
from reranker import CrossEncoderReranker, rerank_hybrid_results
from validator import CyberEntities, ThreatChunk
from vector_database import setup_databases, store_chunks
from vectorizer import VectorResult


class StubScorer:
    """Scores a pair by how many query words appear in the passage."""

    def compute_score(self, sentence_pairs, **kwargs):
        scores = []
        for query, passage in sentence_pairs:
            q = set(query.lower().split())
            p = set(passage.lower().split())
            scores.append(len(q & p) / (len(q) or 1))
        return scores


def test_rerank_orders_by_relevance():
    reranker = CrossEncoderReranker(scorer=StubScorer())
    candidates = [
        ("c1", "completely unrelated content here"),
        ("c2", "lateral movement using psexec over smb"),
        ("c3", "psexec lateral movement observed"),
    ]
    out = reranker.rerank("psexec lateral movement", candidates, top_k=2)
    assert len(out) == 2
    assert out[0].chunk_id in {"c2", "c3"}
    assert out[0].rerank_score >= out[1].rerank_score


def test_rerank_empty_candidates():
    reranker = CrossEncoderReranker(scorer=StubScorer())
    assert reranker.rerank("q", [], top_k=5) == []


def test_rerank_single_pair_scalar_score():
    class ScalarScorer:
        def compute_score(self, pairs, **kwargs):
            return 0.7  # a bare float, as FlagReranker does for one pair

    reranker = CrossEncoderReranker(scorer=ScalarScorer())
    out = reranker.rerank("q", [("c1", "text")], top_k=1)
    assert out[0].rerank_score == pytest.approx(0.7)


def test_rerank_hybrid_results_bridge(tmp_path):
    qdrant, sqlite = setup_databases(
        str(tmp_path / "qdrant"), str(tmp_path / "sqlite" / "corpus.db")
    )
    try:
        for cid, text in [
            ("c1", "unrelated kubernetes helm content about clusters"),
            ("c2", "psexec lateral movement over smb shares detected"),
        ]:
            dense = np.random.rand(1024)
            dense = (dense / np.linalg.norm(dense)).tolist()
            chunk = ThreatChunk(
                chunk_id=cid, doc_id="d", doc_title="t", source_org="CISA",
                published_date=datetime(2023, 1, 1, tzinfo=timezone.utc),
                text=text, entities=CyberEntities(),
            )
            store_chunks([VectorResult(cid, dense, {1: 0.1}, text)], [chunk], qdrant, sqlite)

        hybrid = [HybridResult(chunk_id="c1", rrf_score=0.5),
                  HybridResult(chunk_id="c2", rrf_score=0.4)]
        reranker = CrossEncoderReranker(scorer=StubScorer())
        out = rerank_hybrid_results(reranker, "psexec lateral movement", hybrid, sqlite, top_k=2)

        assert out[0].chunk_id == "c2"          # more relevant despite lower RRF
        assert out[0].metadata.get("doc_title") == "t"
    finally:
        sqlite.close()
