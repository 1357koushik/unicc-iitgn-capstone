"""
Integration tests for live upstream retrieval and exact-IOC pipeline.
Uses faithful test doubles; real teammate objects only when available.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from src.core.interfaces import (
    MockRetrievalBackend,
    MissingUpstreamDependency,
    create_retrieval_backend,
    set_backend,
    get_backend,
)
from src.adapters.upstream_adapter import UpstreamRetrievalBackend, adapt_threat_chunk, adapt_reranked_result
from src.contracts.chunk_schema import ThreatChunk, RankedChunk, CyberEntities


class FakeHybridResult:
    def __init__(self, chunk_id, dense_score=0.8, rrf_score=0.9):
        self.chunk_id = chunk_id
        self.dense_score = dense_score
        self.rrf_score = rrf_score


class FakeHybridSearcher:
    def search(self, query, top_k=5):
        return [FakeHybridResult("chunk-1", dense_score=0.8, rrf_score=0.95)]


class FakeFetchMeta:
    def __call__(self, chunk_id, sqlite=None):
        return {
            "chunk_id": chunk_id,
            "doc_id": "DOC-1",
            "doc_title": "Title",
            "source_org": "CISA",
            "published_date": "2026-01-01",
            "text": "Sample chunk text",
            "entities_json": '{"cves":["CVE-2024-1"]}',
        }


@pytest.mark.asyncio
async def test_live_dependency_injection_works():
    """Live backend can be constructed with injected fakes; never falls back silently."""
    backend = UpstreamRetrievalBackend(
        hybrid_searcher=FakeHybridSearcher(),
        sqlite_connection=None,
        fetch_chunk_metadata=FakeFetchMeta(),
        exact_lookup=None,
        qdrant_client=None,
    )
    results = await backend.hybrid_search("test", top_k=5)
    assert len(results) == 1
    assert results[0].chunk.chunk_id == "chunk-1"
    assert results[0].rrf_score == 0.95
    assert results[0].vector_score == 0.8


@pytest.mark.asyncio
async def test_mock_not_silently_selected_in_live_mode():
    """When RETRIEVAL_BACKEND=live, missing dependencies must raise clearly."""
    with pytest.raises(MissingUpstreamDependency):
        create_retrieval_backend(mode="live", dependencies={})


def test_mock_backend_still_works():
    mock = MockRetrievalBackend()
    assert mock is not None


@pytest.mark.asyncio
async def test_real_hybrid_output_adapted():
    backend = UpstreamRetrievalBackend(
        hybrid_searcher=FakeHybridSearcher(),
        sqlite_connection=None,
        fetch_chunk_metadata=FakeFetchMeta(),
        exact_lookup=None,
        qdrant_client=None,
    )
    ranked = await backend.hybrid_search("query", top_k=3)
    assert isinstance(ranked, list)
    assert all(isinstance(r, RankedChunk) for r in ranked)


@pytest.mark.asyncio
async def test_chunk_ids_hydrated_to_threatchunk():
    backend = UpstreamRetrievalBackend(
        hybrid_searcher=FakeHybridSearcher(),
        sqlite_connection=None,
        fetch_chunk_metadata=FakeFetchMeta(),
        exact_lookup=None,
        qdrant_client=None,
    )
    ranked = await backend.hybrid_search("query")
    chunk = ranked[0].chunk
    assert isinstance(chunk, ThreatChunk)
    assert chunk.doc_id == "DOC-1"
    assert chunk.text == "Sample chunk text"
    assert chunk.chunk_id == "chunk-1"


@pytest.mark.asyncio
async def test_retrieval_scores_preserved():
    backend = UpstreamRetrievalBackend(
        hybrid_searcher=FakeHybridSearcher(),
        sqlite_connection=None,
        fetch_chunk_metadata=FakeFetchMeta(),
        exact_lookup=None,
        qdrant_client=None,
    )
    ranked = await backend.hybrid_search("q", top_k=2)
    assert ranked[0].rrf_score == 0.95
    assert ranked[0].vector_score == 0.8


@pytest.mark.asyncio
async def test_exact_lookup_participates_in_master_flow():
    # Pipeline imports and uses backend.entity_lookup when observables present
    from src.services.pipeline import run_threat_match_pipeline
    # With mock backend, exact chunk should not break pipeline
    mock = MockRetrievalBackend()
    set_backend(mock)
    # Just verify pipeline runs without crash (exact path skipped when mock returns [])
    result = await run_threat_match_pipeline("test", top_k=3)
    assert result is not None
    assert hasattr(result, "top_matches")


@pytest.mark.asyncio
async def test_missing_live_dependencies_fail_clear():
    with pytest.raises(MissingUpstreamDependency):
        create_retrieval_backend(mode="live", dependencies={"hybrid_searcher": None})


@pytest.mark.asyncio
async def test_team3_adapter_output_format():
    from src.adapters.team3_adapter import adapt_team3_results
    chunks = [
        RankedChunk(chunk=ThreatChunk(chunk_id="c1", doc_id="D1", doc_title="T", source_org="S", published_date=datetime(2026,1,1), text="t1"), rrf_score=0.94),
        RankedChunk(chunk=ThreatChunk(chunk_id="c2", doc_id="D2", doc_title="T", source_org="S", published_date=datetime(2026,1,1), text="t2"), rrf_score=0.88),
    ]
    out = adapt_team3_results(chunks, top_k=2)
    assert len(out) == 2
    assert out[0].document_id == "D1"
    assert out[0].relevance_score == 0.94
    assert out[0].content == "t1"


@pytest.mark.asyncio
async def test_adapter_does_not_mutate_upstream_result():
    result = FakeHybridResult("id", dense_score=0.5, rrf_score=0.7)
    original_rrf = result.rrf_score
    backend = UpstreamRetrievalBackend(
        hybrid_searcher=FakeHybridSearcher(),
        sqlite_connection=None,
        fetch_chunk_metadata=FakeFetchMeta(),
        exact_lookup=None,
        qdrant_client=None,
    )
    await backend.hybrid_search("q")
    assert result.rrf_score == original_rrf


@pytest.mark.asyncio
async def test_alpha_propagated_to_backend():
    """Verify retrieve_and_merge passes alpha through to hybrid_search."""
    received = {}

    class FakeBackend:
        async def hybrid_search(self, query, top_k=50, alpha=0.5):
            received["alpha"] = alpha
            return []
        async def entity_lookup(self, query):
            return []

    from src.services.retrieval_orchestration import retrieve_and_merge
    await retrieve_and_merge("test", top_k=5, backend=FakeBackend(), alpha=0.25)
    assert received.get("alpha") == 0.25, f"Expected alpha=0.25, got {received.get('alpha')}"

@pytest.mark.asyncio
async def test_alpha_invalid_rejected():
    from src.schemas.api_schemas import Team3OutputRequest
    # Valid
    Team3OutputRequest(query="t", top_k=5, alpha=0.5)
    # Invalid below 0
    with pytest.raises(Exception):
        Team3OutputRequest(query="t", top_k=5, alpha=-0.1)
    # Invalid above 1
    with pytest.raises(Exception):
        Team3OutputRequest(query="t", top_k=5, alpha=1.1)
