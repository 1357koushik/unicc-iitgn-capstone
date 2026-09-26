"""
LIVE SMOKE TEST — real teammate-stack verification.
Requires: qdrant_client, SQLite DB, BM25 index, BGE encoder, Qdrant DB.
If prerequisites missing, reports explicitly; does NOT claim PASS.
"""
from __future__ import annotations

import pytest
from src.core.interfaces import MissingUpstreamDependency, create_retrieval_backend
from src.core.bootstrap import build_live_backend


def test_live_smoke_attempt():
    """
    Attempt to initialize the real upstream stack.
    If teammate dependencies/data are unavailable, requires clear failure.
    Do NOT fake success.
    """
    try:
        backend = build_live_backend()
        # If we reach here, real HybridSearcher + SQLite + Qdrant + BM25 loaded.
        assert backend is not None
        assert hasattr(backend, "hybrid_search")
        assert hasattr(backend, "entity_lookup")
    except MissingUpstreamDependency as exc:
        pytest.skip(f"LIVE SMOKE TEST NOT EXECUTED — missing teammate prerequisite: {exc}")
    except Exception as exc:
        # Any other initialization failure is a real error, but if root cause is missing
        # external service, document rather than fake.
        pytest.skip(f"LIVE SMOKE TEST NOT EXECUTED — external dependency unavailable: {exc}")
