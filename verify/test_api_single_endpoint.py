from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from threat_retrieval_engine.api.main import app
from threat_retrieval_engine.api.schemas import MatchResponse, PoCFindResponse, PipelineProfileSchema


@pytest.fixture
def client():
    return TestClient(app)


def test_api_health_and_ready(client):
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] in ("ok", "healthy")

    r_ready = client.get("/ready")
    assert r_ready.status_code in (200, 503)


def test_api_match_validation(client):
    # Oversized query should be rejected (max_length=4096)
    huge_query = "A" * 5000
    r_bad = client.post("/match", json={"query": huge_query})
    assert r_bad.status_code == 422

    # Query with top_k > 50 should be rejected
    r_bad_k = client.post("/match", json={"query": "test query", "top_k": 100})
    assert r_bad_k.status_code == 422


def test_api_match_success(client):
    mock_response = MatchResponse(
        query_threat_id="test_query",
        top_matches=[],
        stix_bundle={},
        latency_ms=15.0,
        pipeline_profile=PipelineProfileSchema(
            dense_search_ms=1.0,
            bm25_search_ms=1.0,
            rrf_ms=1.0,
            rerank_ms=1.0,
            confidence_ms=1.0,
            stix_ms=1.0,
            total_retrieval_ms=6.0,
        ),
    )
    with patch("threat_retrieval_engine.api.main.get_orchestrator") as mock_get:
        mock_get.return_value.run_query.return_value = mock_response
        res = client.post("/match", json={"query": "CVE-2024-3400 PAN-OS", "top_k": 5})
        assert res.status_code == 200
        data = res.json()
        assert data["query_threat_id"] == "test_query"
        assert "pipeline_profile" in data
        assert "top_matches" in data


def test_api_poc_endpoint(client):
    mock_poc_resp = PoCFindResponse(
        cve_id="CVE-2024-3400",
        total_found=0,
        precision_score=0.0,
        sources_queried=["github"],
        results=[],
        latency_ms=2.0,
        cached=False,
    )
    with patch("threat_retrieval_engine.poc_intelligence.poc_finder.PoCFinderEngine.find_pocs", return_value=mock_poc_resp):
        res = client.post("/api/v1/pocs/find", json={"cve_id": "CVE-2024-3400"})
        assert res.status_code == 200
        data = res.json()
        assert data["cve_id"] == "CVE-2024-3400"
