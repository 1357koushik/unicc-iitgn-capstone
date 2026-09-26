"""
Tests for end-to-end API integration with teammates' live retrieval.

Verifies that:
  - All 5 API endpoints function correctly with live teammate retrieval
  - Candidate chunks from teammate SQLite corpus reach the API response
  - Multi-factor scoring, 5-tier classification, and evidence citations are populated
  - Team 3 handoff format adapts pipeline results accurately
"""

import pytest
from pathlib import Path
from httpx import ASGITransport, AsyncClient

from src.main import app
from src.core.bootstrap import DEFAULT_SQLITE_PATH, build_live_bm25_backend
from src.core.interfaces import set_backend


@pytest.fixture(autouse=True)
def setup_live_retrieval():
    if not Path(DEFAULT_SQLITE_PATH).is_file():
        pytest.skip(f"Teammate corpus not found at {DEFAULT_SQLITE_PATH}")
    backend = build_live_bm25_backend()
    set_backend(backend)
    yield


@pytest.mark.asyncio
async def test_live_api_health_endpoint() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert "x-process-time-ms" in res.headers


@pytest.mark.asyncio
async def test_live_api_search_hybrid_endpoint() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/search/hybrid",
            json={"query": "CVE-2017-0144 EternalBlue SMB remote code execution", "top_k": 3},
        )
        assert res.status_code == 200
        hits = res.json()
        assert isinstance(hits, list)
        assert len(hits) > 0
        # The top hit should be EternalBlue
        top_chunk = hits[0]["chunk"]
        assert top_chunk["chunk_id"] == "80d012b2da2575e69d44b66f29fc49ba"
        assert hits[0]["bm25_score"] > 0.0


@pytest.mark.asyncio
async def test_live_api_entity_lookup_endpoint() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/entities/lookup",
            json={"ioc": "CVE-2017-0144", "ioc_type": "cve"},
        )
        assert res.status_code == 200
        chunks = res.json()
        assert isinstance(chunks, list)
        assert len(chunks) == 1
        assert chunks[0]["chunk_id"] == "80d012b2da2575e69d44b66f29fc49ba"
        assert "CVE-2017-0144" in chunks[0]["entities"]["cves"]


@pytest.mark.asyncio
async def test_live_api_threat_matching_endpoint() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/threats/match",
            json={
                "query": "Attacker exploited CVE-2017-0144 using T1021.002 from host 198.51.100.24",
                "alpha": 0.5,
                "top_k": 3,
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert "query_threat_id" in data
        assert len(data["top_matches"]) > 0

        match = data["top_matches"][0]
        assert match["chunk_id"] == "80d012b2da2575e69d44b66f29fc49ba"
        assert match["confidence_tier"] in ("EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED")
        assert match["composite_score"] > 0.0

        # Multi-factor evidence breakdown
        bd = match["evidence_breakdown"]
        assert "ioc_similarity" in bd
        assert "cve_similarity" in bd
        assert "ttp_similarity" in bd
        assert "semantic_similarity" in bd

        # Attribution
        attr = match["attribution"]
        assert "198.51.100.24" in attr["matching_iocs"]
        assert "CVE-2017-0144" in attr["matching_cves"]
        assert "T1021.002" in attr["matching_mitre_techniques"]

        # Citations with provenance and matched character spans
        assert len(match["citations"]) > 0
        cit = match["citations"][0]
        assert cit["doc_id"] == "CVE-2017-0144"
        assert len(cit["matched_spans"]) > 0
        span = cit["matched_spans"][0]
        assert span["start"] >= 0
        assert span["end"] > span["start"]


@pytest.mark.asyncio
async def test_live_api_team3_format_endpoint() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/team3/format",
            json={
                "query": "Attacker exploited CVE-2017-0144 using T1021.002 from host 198.51.100.24",
                "top_k": 3,
                "alpha": 0.5,
            },
        )
        assert res.status_code == 200
        data = res.json()

        # Standard ThreatMatchResponse format -- identical to /threats/match
        assert "query_threat_id" in data
        assert "top_matches" in data
        assert "pipeline_profile" in data
        assert len(data["top_matches"]) > 0

        match = data["top_matches"][0]
        assert match["rank"] == 1
        assert match["chunk_id"] == "80d012b2da2575e69d44b66f29fc49ba"
        assert match["confidence_tier"] in ("EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED")
        assert match["composite_score"] > 0.0

        # Evidence breakdown (standard fields)
        bd = match["evidence_breakdown"]
        assert "ioc_similarity" in bd
        assert "cve_similarity" in bd
        assert "ttp_similarity" in bd
        assert "semantic_similarity" in bd

        # Attribution
        attr = match["attribution"]
        assert "198.51.100.24" in attr["matching_iocs"]
        assert "CVE-2017-0144" in attr["matching_cves"]
        assert "T1021.002" in attr["matching_mitre_techniques"]

        # Citations with provenance and matched spans
        assert len(match["citations"]) > 0
        cit = match["citations"][0]
        assert "doc_id" in cit
        assert "text_snippet" in cit
