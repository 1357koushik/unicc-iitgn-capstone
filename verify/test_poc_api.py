from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
from threat_retrieval_engine.api.main import app
from threat_retrieval_engine.api.schemas import PoCFindResponse, PoCResultSchema


@pytest.mark.asyncio
async def test_api_poc_find_endpoint():
    mock_response = PoCFindResponse(
        cve_id="CVE-2024-3400",
        total_found=1,
        precision_score=1.0,
        sources_queried=["github"],
        results=[
            PoCResultSchema(
                url="https://github.com/test/poc",
                title="PAN-OS RCE PoC",
                source="github",
                author="researcher",
                published_at="2024-04-15T00:00:00Z",
                confidence_score=0.88,
                confidence_label="VERIFIED_CODE",
                stars=100,
            )
        ],
        latency_ms=45.2,
        cached=False,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("threat_retrieval_engine.poc_intelligence.poc_finder.PoCFinderEngine.find_pocs", new_callable=AsyncMock) as mock_find:
            mock_find.return_value = mock_response

            payload = {
                "cve_id": "CVE-2024-3400",
                "max_results": 10,
                "sources": ["github"],
            }
            res = await client.post("/api/v1/pocs/find", json=payload)
            assert res.status_code == 200
            data = res.json()
            assert data["cve_id"] == "CVE-2024-3400"
            assert data["total_found"] == 1
            assert data["precision_score"] == 1.0
            assert len(data["results"]) == 1
            assert data["results"][0]["url"] == "https://github.com/test/poc"
            assert data["results"][0]["confidence_label"] == "VERIFIED_CODE"


@pytest.mark.asyncio
async def test_api_poc_find_invalid_cve_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/pocs/find", json={"cve_id": "INVALID-ID"})
        assert res.status_code == 422  # Pydantic regex validation rejection
