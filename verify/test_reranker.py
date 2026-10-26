from __future__ import annotations

import tempfile
import sqlite3
from pathlib import Path
import pytest
from threat_retrieval_engine.search_engine.reranker import (
    CrossEncoderReranker,
    RerankedResult,
)
from threat_retrieval_engine.search_engine.hybrid_search import HybridResult
from threat_retrieval_engine.search_engine.vector_database import setup_sqlite


class StubScorer:
    """Mock scorer that returns deterministic scores based on query token count."""

    def compute_score(self, sentence_pairs: list[list[str]], **kwargs) -> list[float]:
        scores = []
        for query, text in sentence_pairs:
            # Simple heuristic score for test determinism
            score = 1.0 if "PAN-OS" in text else 0.2
            scores.append(score)
        return scores


def test_cross_encoder_reranker_with_stub():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_corpus.db"
        conn = setup_sqlite(str(db_path))

        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO corpus (chunk_id, doc_id, doc_title, source_org, published_date, text, enriched_text, entities_json)
                    VALUES ('c1', 'CVE-2024-3400_NVD', 'PAN-OS Title', 'NVD', '2024-04-12T00:00:00Z', 'Palo Alto PAN-OS vulnerability', 'Palo Alto PAN-OS vulnerability', '{}')
                    """
                )
                conn.execute(
                    """
                    INSERT INTO corpus (chunk_id, doc_id, doc_title, source_org, published_date, text, enriched_text, entities_json)
                    VALUES ('c2', 'CVE-2021-44228_NVD', 'Log4j Title', 'NVD', '2021-12-10T00:00:00Z', 'Apache Log4j vulnerability', 'Apache Log4j vulnerability', '{}')
                    """
                )

            reranker = CrossEncoderReranker(scorer=StubScorer())

            candidates = [
                ("c2", "Apache Log4j vulnerability"),
                ("c1", "Palo Alto PAN-OS vulnerability"),
            ]

            reranked = reranker.rerank(
                query="PAN-OS exploit",
                candidates=candidates,
                top_k=2,
            )

            assert len(reranked) == 2
            # c1 should now be top-1 because StubScorer gave it 1.0
            assert reranked[0].chunk_id == "c1"
            assert reranked[0].rerank_score == 1.0
            assert reranked[1].chunk_id == "c2"
            assert reranked[1].rerank_score == 0.2
        finally:
            conn.close()
