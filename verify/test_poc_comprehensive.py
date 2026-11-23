from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from threat_retrieval_engine.api.main import app
from threat_retrieval_engine.api.schemas import (
    PoCFindRequest,
    PoCFindResponse,
    PoCResultSchema,
    SourceStatusSchema,
)
from threat_retrieval_engine.poc_intelligence.poc_cache import PoCCache
from threat_retrieval_engine.poc_intelligence.poc_finder import PoCFinderEngine
from threat_retrieval_engine.poc_intelligence.poc_validator import PoCValidator
from threat_retrieval_engine.poc_intelligence.result_aggregator import ResultAggregator, canonicalize_url
from threat_retrieval_engine.poc_intelligence.sources.base import (
    BasePoCSource,
    RawCandidate,
    SearchConfig,
    SourceSearchResponse,
)
from threat_retrieval_engine.poc_intelligence.sources.bluesky_scraper import BlueSkyPoCSource
from threat_retrieval_engine.poc_intelligence.sources.mastodon_scraper import MastodonPoCSource


class DummySource(BasePoCSource):
    def __init__(self, name: str, response: SourceSearchResponse):
        self.source_name = name
        self._resp = response

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        return self._resp.candidates

    async def search_with_status(self, cve_id: str, config: SearchConfig | None = None) -> SourceSearchResponse:
        return self._resp


@pytest.mark.asyncio
async def test_invalid_cve_rejection_format():
    engine = PoCFinderEngine()
    for bad in ["not-a-cve", "CVE-2024", "CVE-2024-", "CVE-99-1234"]:
        with pytest.raises(ValueError, match="Invalid CVE identifier format"):
            await engine.find_pocs(bad)


@pytest.mark.asyncio
async def test_partial_source_failure_preserves_other_sources():
    github_resp = SourceSearchResponse(
        source="github",
        status="success",
        candidates=[
            RawCandidate(
                url="https://github.com/sec/cve-2024-3400-poc",
                title="CVE-2024-3400 exploit",
                source="github",
                author="sec",
                stars=50,
                language="Python",
            )
        ],
    )
    x_resp = SourceSearchResponse(
        source="x",
        status="access_restricted",
        errors=["HTTP 403: Project does not have access to recent search endpoint."],
    )
    mastodon_resp = SourceSearchResponse(
        source="mastodon",
        status="timeout",
        errors=["Request timed out after 10.0s."],
    )
    bluesky_resp = SourceSearchResponse(
        source="bluesky",
        status="success",
        candidates=[
            RawCandidate(
                url="https://bsky.app/profile/analyst.bsky.social/post/123",
                title="Analysis of CVE-2024-3400",
                source="bluesky",
                author="@analyst.bsky.social",
                linked_urls=["https://github.com/sec/cve-2024-3400-poc"],
            )
        ],
    )

    sources = {
        "github": DummySource("github", github_resp),
        "x": DummySource("x", x_resp),
        "mastodon": DummySource("mastodon", mastodon_resp),
        "bluesky": DummySource("bluesky", bluesky_resp),
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        cache = PoCCache(db_path=Path(tmpdir) / "test.db")
        engine = PoCFinderEngine(cache=cache, sources=sources)
        resp = await engine.find_pocs("CVE-2024-3400")

        # GitHub and Bluesky succeeded and merged; X and Mastodon recorded their statuses
        assert resp.total_found == 1
        assert len(resp.source_statuses) == 4
        statuses = {s.source: s.status for s in resp.source_statuses}
        assert statuses["github"] == "success"
        assert statuses["x"] == "access_restricted"
        assert statuses["mastodon"] == "timeout"
        assert statuses["bluesky"] == "success"

        # Result retains provenance from both github and bluesky
        poc = resp.results[0]
        assert poc.url == "https://github.com/sec/cve-2024-3400-poc"
        assert len(poc.source_references) == 2
        ref_sources = {r["source"] for r in poc.source_references}
        assert ref_sources == {"github", "bluesky"}


@pytest.mark.asyncio
async def test_all_source_failure_handles_gracefully():
    sources = {
        "github": DummySource("github", SourceSearchResponse(source="github", status="rate_limited", errors=["429"])),
        "x": DummySource("x", SourceSearchResponse(source="x", status="unauthorized", errors=["401"])),
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = PoCCache(db_path=Path(tmpdir) / "test.db")
        engine = PoCFinderEngine(cache=cache, sources=sources)
        resp = await engine.find_pocs("CVE-2024-3400")
        assert resp.total_found == 0
        assert resp.results == []
        assert len(resp.source_statuses) == 2


@pytest.mark.asyncio
async def test_deduplication_and_provenance_preservation():
    aggregator = ResultAggregator()
    candidates = [
        RawCandidate(
            url="https://github.com/org/repo/tree/master/poc",
            title="Repo with master branch",
            source="github",
            author="org",
            stars=10,
            language="Python",
        ),
        RawCandidate(
            url="https://infosec.exchange/@user/post1",
            title="Shared repo on Mastodon",
            source="mastodon",
            author="@user@infosec.exchange",
            linked_urls=["https://github.com/org/repo?utm_source=mastodon"],
        ),
    ]

    results = aggregator.aggregate_and_validate(candidates, cve_id="CVE-2024-3400")
    assert len(results) == 1
    assert results[0].url == "https://github.com/org/repo"
    assert len(results[0].source_references) == 2
    sources = [r["source"] for r in results[0].source_references]
    assert "github" in sources and "mastodon" in sources


def test_score_reasons_and_evidence_tracking():
    validator = PoCValidator()
    cand = RawCandidate(
        url="https://github.com/team/cve-2024-3400-exploit",
        title="Working exploit for CVE-2024-3400",
        source="github",
        author="team",
        stars=30,
        language="Python",
    )
    result = validator.validate_candidate(cand, "CVE-2024-3400", cross_source_count=2)
    assert result.confidence_score >= 0.70
    assert result.match_type == "HIGH_RELEVANCE_POC_CANDIDATE"
    assert any("exact requested CVE" in r for r in result.score_reasons)
    assert any("explicit PoC/exploit terminology" in r for r in result.score_reasons)
    assert any("implementation or code evidence" in r for r in result.score_reasons)
    assert any("community validation" in r for r in result.score_reasons)
    assert any("cross-source corroboration" in r for r in result.score_reasons)


def test_missing_dates_remain_null():
    validator = PoCValidator()
    cand = RawCandidate(
        url="https://github.com/user/CVE-2024-1111-poc",
        title="CVE-2024-1111 PoC",
        source="github",
        author="user",
        published_at=None,
    )
    result = validator.validate_candidate(cand, "CVE-2024-1111")
    assert result.published_at is None
    assert result.created_at is None


@pytest.mark.asyncio
async def test_cache_isolation_and_parameter_independence():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        cache = PoCCache(db_path=db_path)
        mock_source = DummySource(
            "mock",
            SourceSearchResponse(
                source="mock",
                status="success",
                candidates=[
                    RawCandidate(
                        url="https://github.com/a/CVE-2024-3400-high",
                        title="Exploit CVE-2024-3400",
                        source="mock",
                        stars=50,
                        language="Python",
                    ),
                    RawCandidate(
                        url="https://github.com/b/CVE-2024-3400-low",
                        title="Discussion CVE-2024-3400",
                        source="mock",
                        stars=0,
                    ),
                ],
            ),
        )
        engine = PoCFinderEngine(cache=cache, sources={"mock": mock_source})

        # Call 1: min_confidence=0.0 -> returns both
        res1 = await engine.find_pocs("CVE-2024-3400", min_confidence=0.0)
        assert len(res1.results) == 2
        assert res1.cached is False

        # Call 2: min_confidence=0.70 -> returns only high confidence
        res2 = await engine.find_pocs("CVE-2024-3400", min_confidence=0.70)
        assert len(res2.results) == 1
        assert res2.cached is True

        # Call 3: min_confidence=0.0 again -> still returns both (unmutated cache)
        res3 = await engine.find_pocs("CVE-2024-3400", min_confidence=0.0)
        assert len(res3.results) == 2
        assert res3.cached is True


@pytest.mark.asyncio
async def test_cache_answers_only_the_same_sources_and_size():
    def source(name):
        return DummySource(name, SourceSearchResponse(source=name, status="success", candidates=[
            RawCandidate(url=f"https://github.com/{name}/CVE-2024-3400-poc", title="Exploit CVE-2024-3400", source=name,
                         stars=50, language="Python")]))

    with tempfile.TemporaryDirectory() as tmpdir:
        engine = PoCFinderEngine(cache=PoCCache(db_path=Path(tmpdir) / "test.db"), sources={"a": source("a"), "b": source("b")})
        both = await engine.find_pocs("CVE-2024-3400", sources=["a", "b"])
        assert sorted(both.sources_queried) == ["a", "b"] and both.cached is False
        one = await engine.find_pocs("CVE-2024-3400", sources=["a"])
        assert one.sources_queried == ["a"] and one.cached is False
        assert (await engine.find_pocs("CVE-2024-3400", sources=["b", "a"])).cached is True
        small = await engine.find_pocs("CVE-2024-3400", sources=["b"], max_results=1)
        assert len(small.results) == 1 and small.cached is False
        assert (await engine.find_pocs("CVE-2024-3400", sources=["b"], max_results=50)).cached is False
        strict = await engine.find_pocs("CVE-2024-3400", sources=["a"], max_results=7, min_confidence=1.01)
        assert strict.results == []
        assert len((await engine.find_pocs("CVE-2024-3400", sources=["a"], max_results=7)).results) == 1


@pytest.mark.asyncio
async def test_mastodon_status_error_handling():
    source = MastodonPoCSource(instances=["failing.instance.local"])
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await source.search_with_status("CVE-2024-3400")
        assert res.status == "rate_limited"
        assert len(res.warnings) > 0


@pytest.mark.asyncio
async def test_bluesky_status_error_handling():
    source = BlueSkyPoCSource()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await source.search_with_status("CVE-2024-3400")
        assert res.status == "access_restricted"
        assert any("403" in err for err in res.errors)


@pytest.mark.asyncio
async def test_api_poc_find_route_full():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Invalid payload
        bad = await client.post("/api/v1/pocs/find", json={"cve_id": "malformed"})
        assert bad.status_code == 422

        # Valid payload with mock
        mock_resp = PoCFindResponse(
            cve_id="CVE-2024-3400",
            total_found=1,
            precision_score=0.85,
            sources_queried=["github"],
            results=[
                PoCResultSchema(
                    cve_id="CVE-2024-3400",
                    url="https://github.com/valid/poc",
                    title="PAN-OS PoC",
                    source="github",
                    author="valid",
                    published_at="2024-04-15T00:00:00Z",
                    confidence_score=0.85,
                    confidence_label="HIGH_RELEVANCE_POC_CANDIDATE",
                    match_type="HIGH_RELEVANCE_POC_CANDIDATE",
                    stars=10,
                    language="Python",
                    warning_flags=[],
                    evidence=["Exact CVE match: CVE-2024-3400"],
                    score_reasons=["+0.35 exact requested CVE"],
                    source_verification_status="repository_metadata_and_search_evidence",
                )
            ],
            latency_ms=25.0,
            cached=False,
            source_statuses=[
                SourceStatusSchema(
                    source="github",
                    status="success",
                    retrieved_at="2026-10-24T00:00:00Z",
                    result_count=1,
                )
            ],
        )
        with patch("threat_retrieval_engine.poc_intelligence.poc_finder.PoCFinderEngine.find_pocs", new_callable=AsyncMock, return_value=mock_resp):
            res = await client.post("/api/v1/pocs/find", json={"cve_id": "CVE-2024-3400"})
            assert res.status_code == 200
            data = res.json()
            assert data["cve_id"] == "CVE-2024-3400"
            assert data["total_found"] == 1
            assert len(data["source_statuses"]) == 1
            assert data["results"][0]["match_type"] == "HIGH_RELEVANCE_POC_CANDIDATE"
