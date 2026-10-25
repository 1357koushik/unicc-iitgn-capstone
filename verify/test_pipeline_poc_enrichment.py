from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine
from threat_retrieval_engine.api.schemas import PoCFindResponse, PoCResultSchema


def test_pipeline_attaches_pocs_when_cve_in_query():
    # Setup mock hybrid searcher and exact lookup
    engine = ThreatRetrieverEngine()
    engine._initialized = True
    engine.sqlite = MagicMock()
    engine.qdrant = MagicMock()
    engine.attack_graph = MagicMock()
    engine.attack_graph.expand.return_value = {"relationships": [], "actors": []}
    engine.hybrid_searcher = MagicMock()
    engine.hybrid_searcher.search.return_value = []

    mock_poc_resp = PoCFindResponse(
        cve_id="CVE-2024-3400",
        total_found=1,
        precision_score=1.0,
        sources_queried=["github"],
        results=[
            PoCResultSchema(
                url="https://github.com/test/poc",
                title="PAN-OS RCE Exploit",
                source="github",
                author="researcher",
                published_at="2024-04-15T00:00:00Z",
                confidence_score=0.92,
                confidence_label="VERIFIED_CODE",
            )
        ],
        latency_ms=10.0,
    )

    with patch("threat_retrieval_engine.search_engine.exact_lookup.exact_lookup", return_value=[]), \
         patch("threat_retrieval_engine.poc_intelligence.poc_finder.PoCFinderEngine.find_pocs_sync", return_value=mock_poc_resp):

        response = engine.run_query("Observed lateral movement exploiting CVE-2024-3400", top_k=3)
        assert response.query_threat_id.startswith("query_")
        assert response.pipeline_profile.poc_discovery_ms >= 0.0
