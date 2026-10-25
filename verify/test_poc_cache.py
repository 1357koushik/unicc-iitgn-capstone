from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
from threat_retrieval_engine.api.schemas import PoCFindResponse, PoCResultSchema
from threat_retrieval_engine.poc_intelligence.poc_cache import PoCCache


def test_poc_cache_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_corpus.db"
        cache = PoCCache(db_path=db_path)

        # Initially empty
        assert cache.get("CVE-2024-3400") is None

        # Store response
        sample_resp = PoCFindResponse(
            cve_id="CVE-2024-3400",
            total_found=1,
            precision_score=1.0,
            sources_queried=["github"],
            results=[
                PoCResultSchema(
                    url="https://github.com/test/repo",
                    title="Test PoC",
                    source="github",
                    author="test",
                    published_at="2024-04-15T00:00:00Z",
                    confidence_score=0.9,
                    confidence_label="VERIFIED_CODE",
                )
            ],
            latency_ms=12.5,
            cached=False,
        )
        cache.set("CVE-2024-3400", sample_resp, ttl_seconds=100)

        # Retrieve
        hit = cache.get("CVE-2024-3400")
        assert hit is not None
        assert hit.cached is True
        assert hit.cve_id == "CVE-2024-3400"
        assert len(hit.results) == 1
        assert hit.results[0].url == "https://github.com/test/repo"


def test_poc_cache_ttl_expiry():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_corpus.db"
        cache = PoCCache(db_path=db_path)

        sample_resp = PoCFindResponse(
            cve_id="CVE-2021-44228",
            total_found=0,
            precision_score=0.0,
            sources_queried=["github"],
            results=[],
            latency_ms=5.0,
        )
        # Store with negative/expired TTL
        cache.set("CVE-2021-44228", sample_resp, ttl_seconds=-10)
        assert cache.get("CVE-2021-44228") is None
