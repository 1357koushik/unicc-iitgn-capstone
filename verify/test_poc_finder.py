from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
from unittest.mock import AsyncMock
from threat_retrieval_engine.poc_intelligence.poc_finder import PoCFinderEngine
from threat_retrieval_engine.poc_intelligence.poc_cache import PoCCache
from threat_retrieval_engine.poc_intelligence.sources.base import BasePoCSource, RawCandidate


class MockPoCSource(BasePoCSource):
    source_name = "mock_source"

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        return [
            RawCandidate(
                url=f"https://github.com/mock/{cve_id}-exploit",
                title=f"{cve_id} Exploit Script",
                source="mock_source",
                author="researcher",
                stars=50,
                language="Python",
                description="Functional proof of concept exploit code",
            )
        ]


@pytest.mark.asyncio
async def test_poc_finder_orchestration():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_corpus.db"
        cache = PoCCache(db_path=db_path)
        sources = {"mock_source": MockPoCSource()}

        engine = PoCFinderEngine(cache=cache, sources=sources)
        resp = await engine.find_pocs("CVE-2024-3400", max_results=5)

        assert resp.cve_id == "CVE-2024-3400"
        assert resp.total_found == 1
        assert resp.precision_score >= 0.70  # Meets precision benchmark target
        assert resp.results[0].confidence_label in ("HIGH_RELEVANCE_POC_CANDIDATE", "VERIFIED_CODE")
        assert resp.cached is False

        # Second call should be a cache hit
        cached_resp = await engine.find_pocs("CVE-2024-3400")
        assert cached_resp.cached is True
        assert cached_resp.total_found == 1


@pytest.mark.asyncio
async def test_poc_finder_invalid_cve_raises():
    engine = PoCFinderEngine()
    with pytest.raises(ValueError, match="Invalid CVE identifier format"):
        await engine.find_pocs("NOT-A-CVE")
