from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from threat_retrieval_engine.search_engine.hybrid_search import (
    reciprocal_rank_fusion,
    HybridSearcher,
    HybridResult,
)
from threat_retrieval_engine.search_engine.bm25_index import BM25Index, BM25Result


def test_reciprocal_rank_fusion_math():
    dense_ranks = ["docA", "docB", "docC"]
    lexical_ranks = ["docB", "docA", "docD"]

    scores = reciprocal_rank_fusion([dense_ranks, lexical_ranks], k=60)

    assert len(scores) == 4
    assert scores["docA"] > scores["docC"]
    assert scores["docB"] > scores["docD"]


def test_reciprocal_rank_fusion_with_alpha():
    dense_ranks = ["docA"]
    lexical_ranks = ["docB"]

    # When alpha is heavily dense (0.9), docA should rank higher than docB
    fused_dense = reciprocal_rank_fusion([dense_ranks, lexical_ranks], k=60, weights=[0.9, 0.1])
    assert fused_dense["docA"] > fused_dense["docB"]

    # When alpha is heavily lexical (0.1), docB should rank higher than docA
    fused_lex = reciprocal_rank_fusion([dense_ranks, lexical_ranks], k=60, weights=[0.1, 0.9])
    assert fused_lex["docB"] > fused_lex["docA"]
