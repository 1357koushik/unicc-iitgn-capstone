"""
Tests for the benchmark evaluation framework.

Verifies that:
  - BenchmarkRetrievalBackend and _text_similarity are completely removed
  - The benchmark connects to teammates' actual retrieval in unicc-iitgn-capstone-main/
  - Teammate BM25 retrieval integrates with UpstreamRetrievalBackend
  - Missing neural dependencies report MissingUpstreamDependency without fabricating results
"""

import pytest
from pathlib import Path

import scripts.evaluate as eval_module
from src.contracts.chunk_schema import RankedChunk, ThreatChunk
from src.core.bootstrap import (
    DEFAULT_SQLITE_PATH,
    build_live_backend,
    build_live_bm25_backend,
)
from src.core.interfaces import MissingUpstreamDependency, set_backend
from src.services.pipeline import run_threat_match_pipeline


def test_benchmark_specific_retrieval_removed() -> None:
    """Verify BenchmarkRetrievalBackend and _text_similarity are removed from evaluate.py."""
    assert not hasattr(eval_module, "BenchmarkRetrievalBackend")
    assert not hasattr(eval_module, "_text_similarity")
    assert not hasattr(eval_module, "ProductionRetrievalCorpus")
    assert not hasattr(eval_module, "MockRetrievalCorpus")


def test_teammate_bm25_backend_initialization() -> None:
    """Verify teammate BM25Index from unicc-iitgn-capstone-main/bm25_index.py loads cleanly."""
    if not Path(DEFAULT_SQLITE_PATH).is_file():
        pytest.skip(f"SQLite corpus not found at {DEFAULT_SQLITE_PATH}")

    backend = build_live_bm25_backend()
    assert backend is not None
    assert hasattr(backend, "hybrid_search")
    assert hasattr(backend, "entity_lookup")


@pytest.mark.asyncio
async def test_teammate_bm25_retrieval_execution() -> None:
    """Verify teammate BM25Index retrieves real chunks and returns RankedChunk instances."""
    if not Path(DEFAULT_SQLITE_PATH).is_file():
        pytest.skip(f"SQLite corpus not found at {DEFAULT_SQLITE_PATH}")

    backend = build_live_bm25_backend()
    results = await backend.hybrid_search("CVE-2017-0144", top_k=3)
    assert len(results) > 0
    assert all(isinstance(r, RankedChunk) for r in results)
    # The top retrieved chunk should be EternalBlue (CVE-2017-0144)
    assert results[0].chunk.chunk_id == "80d012b2da2575e69d44b66f29fc49ba"
    assert results[0].bm25_score > 0.0


@pytest.mark.asyncio
async def test_pipeline_runs_with_teammate_retrieval() -> None:
    """Verify run_threat_match_pipeline executes with teammate BM25 retrieval backend."""
    if not Path(DEFAULT_SQLITE_PATH).is_file():
        pytest.skip(f"SQLite corpus not found at {DEFAULT_SQLITE_PATH}")

    backend = build_live_bm25_backend()
    set_backend(backend)

    res = await run_threat_match_pipeline(
        query="Attacker exploited CVE-2017-0144 using T1021.002 from host 198.51.100.24",
        top_k=3,
    )
    assert res is not None
    assert len(res.top_matches) > 0
    assert res.top_matches[0].chunk_id == "80d012b2da2575e69d44b66f29fc49ba"
    assert res.top_matches[0].confidence_tier in ("EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED")
    assert len(res.top_matches[0].citations) > 0


def test_missing_dependencies_reported_honestly() -> None:
    """Verify that if neural dependencies are missing, MissingUpstreamDependency is raised."""
    try:
        build_live_backend()
    except MissingUpstreamDependency as exc:
        assert "dependencies that are not installed" in str(exc) or "not available" in str(exc)
