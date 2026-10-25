from __future__ import annotations

import pytest
from threat_retrieval_engine.poc_intelligence.result_aggregator import ResultAggregator, canonicalize_url
from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate


def test_canonicalize_url():
    u1 = "https://github.com/someone/cve-poc/tree/main?utm_source=twitter&ref=cti"
    assert canonicalize_url(u1) == "https://github.com/someone/cve-poc"

    u2 = "https://infosec.exchange/@user/12345/"
    assert canonicalize_url(u2) == "https://infosec.exchange/@user/12345"


def test_aggregator_merges_cross_platform_duplicates():
    agg = ResultAggregator()
    cands = [
        RawCandidate(
            url="https://github.com/example/CVE-2024-3400-poc",
            title="CVE-2024-3400 exploit",
            source="github",
            author="example",
            stars=25,
            language="Python",
        ),
        RawCandidate(
            url="https://github.com/example/CVE-2024-3400-poc?utm_source=x",
            title="Shared on X",
            source="x",
            author="analyst_x",
            description="Working PoC for CVE-2024-3400",
        ),
        RawCandidate(
            url="https://github.com/example/CVE-2024-3400-poc/tree/master",
            title="Referenced on Mastodon",
            source="mastodon",
            author="@analyst@infosec.exchange",
        ),
    ]

    results = agg.aggregate_and_validate(cands, cve_id="CVE-2024-3400")
    # All 3 point to the same repo, so they should deduplicate into 1 result
    assert len(results) == 1
    assert results[0].url == "https://github.com/example/CVE-2024-3400-poc"
    # Benefited from cross-source corroboration (3 sources)
    assert results[0].confidence_score >= 0.75
    assert results[0].confidence_label in ("HIGH_RELEVANCE_POC_CANDIDATE", "VERIFIED_CODE")
