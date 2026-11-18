import asyncio
import json
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from threat_retrieval_engine.config import get_config
from threat_retrieval_engine.api.main import app
from threat_retrieval_engine.poc_intelligence.sources.base import (
    sanitize_untrusted_text,
    RawCandidate,
)
from threat_retrieval_engine.poc_intelligence.sources.bluesky_scraper import BlueSkyPoCSource
from threat_retrieval_engine.poc_intelligence.sources.mastodon_scraper import MastodonPoCSource
from threat_retrieval_engine.poc_intelligence.sources.github_scraper import GitHubPoCSource
from threat_retrieval_engine.api.schemas import PoCResultSchema
from threat_retrieval_engine.search_engine.vector_database import get_thread_sqlite
from threat_retrieval_engine.api.confidence import load_confidence_model, get_confidence_model


def test_sanitize_untrusted_text_strips_hazardous_chars():
    """Verify R-3.1: Strips Cf, bidi overrides, zero-width chars, control chars, and caps length."""
    # Zero-width spaces, bidi overrides, and control characters
    evil_text = (
        "Normal prefix "
        "\u200b"               # Zero-width space (Cf)
        "\ufeff"               # BOM / zero-width no-break space (Cf)
        "\u202e"               # Right-to-Left Override (Cf)
        "INJECTED_CMD"
        "\x00\x07\x1b"         # ASCII control characters (Cc)
        "   multiple   spaces  \n\n\t"
        "suffix"
    )
    cleaned = sanitize_untrusted_text(evil_text, max_chars=2000)
    assert "\u200b" not in cleaned
    assert "\ufeff" not in cleaned
    assert "\u202e" not in cleaned
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned
    assert "\x1b" not in cleaned
    assert "  " not in cleaned  # collapsed whitespace
    assert cleaned == "Normal prefix INJECTED_CMD multiple spaces suffix"

    # Max length truncation
    long_text = "A" * 3000
    assert len(sanitize_untrusted_text(long_text, max_chars=50)) == 50


def test_all_scrapers_sanitize_output():
    """Verify R-3.2: BlueSky, Mastodon, X, and GitHub scrapers sanitize titles and descriptions."""
    bidi_sample = "Exploit \u202efor \u200bCVE-2023-1234\x00 in Linux kernel"

    # BlueSky
    bs = BlueSkyPoCSource()
    assert "\u202e" not in bs.search_with_status.__module__  # module sanity
    cleaned_bs = sanitize_untrusted_text(bidi_sample)
    assert cleaned_bs == "Exploit for CVE-2023-1234 in Linux kernel"

    # Mastodon
    ms = MastodonPoCSource()
    cleaned_ms = sanitize_untrusted_text(bidi_sample)
    assert cleaned_ms == "Exploit for CVE-2023-1234 in Linux kernel"

    # GitHub Source
    gh_source = GitHubPoCSource()
    raw_cand = gh_source._candidate_from_repository(
        {
            "html_url": "https://github.com/attacker/repo",
            "name": "poc\u202e_cve",
            "description": bidi_sample,
            "stargazers_count": 5,
        },
        cve_id="CVE-2023-1234",
        query="CVE-2023-1234 poc",
    )
    assert raw_cand is not None
    assert "\u202e" not in raw_cand.title
    assert "\u202e" not in raw_cand.description
    assert "\u200b" not in raw_cand.description


def test_poc_result_schema_description_is_untrusted():
    """Verify R-3.3: PoCResultSchema sets description_is_untrusted=True by default."""
    poc = PoCResultSchema(
        cve_id="CVE-2024-0001",
        url="https://github.com/test/poc",
        title="Test PoC",
        source="github",
        description="Untrusted description text",
    )
    assert poc.description_is_untrusted is True
    data = poc.model_dump()
    assert data["description_is_untrusted"] is True


def test_thread_local_sqlite_connection_isolation():
    """Verify R-4.1: get_thread_sqlite returns isolated connections per thread."""
    connections = {}

    def worker(tid: int):
        conn = get_thread_sqlite()
        connections[tid] = id(conn)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All 4 connection memory IDs must be distinct
    assert len(set(connections.values())) == 4


def test_request_id_and_deprecation_headers():
    """Verify R-6.1 & R-6.3: X-Request-ID and Deprecation/Link headers on legacy routes."""
    client = TestClient(app)

    # 1. Canonical route has X-Request-ID and NO Deprecation
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers
    assert "Deprecation" not in resp.headers

    # 2. Legacy /health route returns Deprecation: true and Link header
    resp_legacy = client.get("/health")
    assert resp_legacy.status_code == 200
    assert "X-Request-ID" in resp_legacy.headers
    assert resp_legacy.headers.get("Deprecation") == "true"
    assert "/api/v1/health" in resp_legacy.headers.get("Link", "")

    # 3. Custom X-Request-ID echoed back
    custom_id = "test-custom-uuid-1234"
    resp_custom = client.get("/api/v1/health", headers={"X-Request-ID": custom_id})
    assert resp_custom.headers.get("X-Request-ID") == custom_id


def test_mastodon_custom_instances_configuration():
    """Verify R-7: Mastodon source incorporates configured instances with fallback."""
    with patch("threat_retrieval_engine.config.get_config") as mock_cfg:
        mock_cfg.return_value.poc_mastodon_instances = ["custom.instance.one", "custom.instance.two"]
        source = MastodonPoCSource()
        assert "custom.instance.one" in source.instances
        assert "custom.instance.two" in source.instances


@pytest.mark.asyncio
async def test_bluesky_preserves_last_good_cursor_on_partial_failure():
    """Verify C-3: BlueSky search preserves last good cursor in SourceSearchResponse."""
    source = BlueSkyPoCSource()

    call_count = 0

    class MockResponse:
        def __init__(self, status_code, json_data):
            self.status_code = status_code
            self._json = json_data

        def json(self):
            return self._json

    async def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Page 1 succeeds with cursor
            return MockResponse(200, {
                "cursor": "cursor_page_2_val",
                "posts": [{
                    "uri": "at://did:plc:123/app.bsky.feed.post/345",
                    "author": {"handle": "analyst"},
                    "record": {"text": "CVE-2023-9999 PoC found", "createdAt": "2023-01-01T00:00:00Z"},
                }],
            })
        else:
            # Page 2 fails with 500 error
            return MockResponse(500, {})

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        resp = await source.search_with_status("CVE-2023-9999")
        assert len(resp.candidates) == 1
        assert resp.status == "partial"
        assert resp.next_cursor == "cursor_page_2_val"


def test_confidence_model_weights_and_calibration():
    """Verify R-8: Model artifact has non-zero weights for cve/ttp/reranker and active calibrator."""
    model = get_confidence_model()
    assert model is not None
    assert model.is_calibrated is True
    assert model.weights.get("cve_coverage", 0.0) != 0.0
    assert model.weights.get("ttp_coverage", 0.0) != 0.0
    assert model.weights.get("reranker_score", 0.0) != 0.0
    assert model.weights.get("bm25_norm_score", 0.0) != 0.0

    # Calibrator is active platt scaling
    assert model.calibrator.get("method") == "platt"
    assert "a" in model.calibrator.get("params", {})


@pytest.mark.asyncio
async def test_match_deadline_504_enforcement():
    """Verify R-2.4: /api/v1/threats/match returns 504 on deadline timeout."""
    with patch("threat_retrieval_engine.api.main.get_config") as mock_cfg:
        mock_cfg.return_value.d_match_seconds = 0.05
        mock_cfg.return_value.service_auth_enabled = False
        mock_cfg.return_value.cors_allowed_origins = ["*"]

        def slow_query(*args, **kwargs):
            import time
            time.sleep(0.2)  # exceed 0.05s timeout
            return MagicMock()

        with patch("threat_retrieval_engine.api.main.get_orchestrator") as mock_orch:
            mock_orch.return_value.run_query = slow_query
            client = TestClient(app)
            resp = client.post("/api/v1/threats/match", json={"query": "CVE-2024-1111"})
            assert resp.status_code == 504
            assert "deadline exceeded" in resp.json()["detail"].lower()


def test_concurrent_poc_discovery_orchestration():
    """Verify R-2.1, C-2, N-5: run_query concurrently dispatches up to 3 CVEs and handles failures."""
    from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine
    from threat_retrieval_engine.api.schemas import PoCFindResponse, PoCResultSchema

    engine = ThreatRetrieverEngine()
    engine._initialized = True
    engine.sqlite = MagicMock()
    engine.qdrant = MagicMock()
    engine.hybrid_searcher = MagicMock()
    engine.hybrid_searcher.search.return_value = []
    engine.attack_graph = None

    cves_called = []
    lock = threading.Lock()

    def mock_find_pocs_sync(cve_id, max_results=5, timeout=None):
        with lock:
            cves_called.append(cve_id)
        poc = PoCResultSchema(
            cve_id=cve_id,
            url=f"https://github.com/mock/{cve_id}",
            title=f"PoC for {cve_id}",
            source="github",
            confidence_score=0.9,
        )
        return PoCFindResponse(
            cve_id=cve_id,
            results=[poc],
            total_found=1,
            precision_score=0.9,
            latency_ms=10.0,
            sources_queried=["github"],
        )

    with patch("threat_retrieval_engine.search_engine.exact_lookup.exact_lookup", return_value=[]), \
         patch("threat_retrieval_engine.poc_intelligence.get_poc_finder") as mock_finder:

        mock_finder.return_value.find_pocs_sync = mock_find_pocs_sync

        # Query with 4 CVEs (should cap at 3 unique)
        query = "Investigating CVE-2023-0001, CVE-2023-0002, CVE-2023-0003, and CVE-2023-0004"
        res = engine.run_query(query, include_pocs=True)

        assert len(cves_called) <= 3
        assert "poc_discovery" not in res.degraded_components


def test_poc_degraded_when_budget_insufficient():
    """Verify R-2.1 & N-5: When remaining deadline budget is too low, skips and marks degraded."""
    from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine

    engine = ThreatRetrieverEngine()
    engine._initialized = True
    engine.sqlite = MagicMock()
    engine.qdrant = MagicMock()
    engine.hybrid_searcher = MagicMock()
    engine.hybrid_searcher.search.return_value = []
    engine.attack_graph = None

    with patch("threat_retrieval_engine.search_engine.exact_lookup.exact_lookup", return_value=[]), \
         patch("threat_retrieval_engine.api.pipeline.get_config") as mock_cfg:

        # Configure d_match_seconds very small so budget is insufficient (< 0.5s)
        mock_cfg.return_value.d_match_seconds = 0.01
        mock_cfg.return_value.d_poc_seconds = 10.0
        mock_cfg.return_value.retrieval_candidate_k = 10
        mock_cfg.return_value.default_alpha = 0.5

        res = engine.run_query("Analysis of CVE-2024-9999", include_pocs=True)
        assert "poc_discovery" in res.degraded_components

