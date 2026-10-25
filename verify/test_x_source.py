"""Synthetic fixture tests for the official X API connector.

These tests never call X and must not be mistaken for live X evidence.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threat_retrieval_engine.poc_intelligence.sources.base import SearchConfig
from threat_retrieval_engine.poc_intelligence.sources.x_scraper import XPoCSource


def _response(status_code: int, payload: object, headers: dict[str, str] | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.headers = headers or {}
    return response


@pytest.fixture(autouse=True)
def enable_paid_requests_for_synthetic_tests(monkeypatch):
    """Enable paid requests and connector for synthetic mocking tests while preserving explicit overrides."""
    monkeypatch.setenv("X_ALLOW_PAID_REQUESTS", "true")
    monkeypatch.setenv("X_ENABLED", "true")


@pytest.mark.asyncio
async def test_x_search_parses_post_provenance_and_linked_artifact_from_synthetic_response():
    source = XPoCSource(bearer_token="synthetic-token", max_results=10, max_requests=2)
    synthetic = {
        "data": [{
            "id": "123", "author_id": "42", "created_at": "2026-10-01T12:00:00.000Z",
            "text": "CVE-2021-44228 PoC write-up https://t.co/abc",
            "entities": {"urls": [{"url": "https://t.co/abc", "expanded_url": "https://github.com/example/log4j-poc"}]},
            "public_metrics": {"like_count": 4, "repost_count": 1, "reply_count": 0, "quote_count": 0},
        }],
        "includes": {"users": [{"id": "42", "username": "researcher", "name": "Researcher"}]},
        "meta": {"result_count": 1},
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=_response(200, synthetic)) as get:
        result = await source.search_with_status("cve-2021-44228", SearchConfig(result_limit=5))

    assert result.status == "success"
    assert result.pages_fetched == 1
    assert result.query == 'CVE-2021-44228 (poc OR exploit OR "proof of concept") -is:retweet lang:en'
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.url == "https://x.com/researcher/status/123"
    assert candidate.author == "@researcher"
    assert candidate.linked_urls == ["https://github.com/example/log4j-poc"]
    assert candidate.raw_metadata["public_metrics"]["like_count"] == 4
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer synthetic-token"
    assert "synthetic-token" not in str(result)
    assert "complete historical" in result.coverage_limitations[0]


@pytest.mark.asyncio
async def test_x_search_follows_pagination_only_within_configured_request_budget():
    source = XPoCSource(bearer_token="test", max_results=20, max_requests=2)
    first = {"data": [{"id": "1", "author_id": "a", "text": "CVE-2024-3400 poc"}], "meta": {"next_token": "cursor-2"}}
    second = {"data": [{"id": "2", "author_id": "a", "text": "CVE-2024-3400 exploit"}], "meta": {}}
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=[_response(200, first), _response(200, second)]) as get:
        result = await source.search_with_status("CVE-2024-3400", SearchConfig(result_limit=20, page_limit=2, request_limit=2))

    assert result.status == "success"
    assert result.pages_fetched == 2
    assert [item.raw_metadata["post_id"] for item in result.candidates] == ["1", "2"]
    assert get.call_count == 2
    assert get.call_args_list[1].kwargs["params"]["next_token"] == "cursor-2"


@pytest.mark.asyncio
async def test_x_reports_missing_credentials_without_a_network_request():
    source = XPoCSource(bearer_token="", enabled=True)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as get:
        result = await source.search_with_status("CVE-2024-3400")

    assert result.status == "not_configured"
    assert result.candidates == []
    assert get.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(("code", "expected"), [(401, "unauthorized"), (403, "access_restricted")])
async def test_x_reports_auth_and_access_failures(code: int, expected: str):
    source = XPoCSource(bearer_token="test")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=_response(code, {"detail": "synthetic failure"})):
        result = await source.search_with_status("CVE-2024-3400")

    assert result.status == expected
    assert result.errors == ["synthetic failure"]


@pytest.mark.asyncio
async def test_x_retries_rate_limit_once_respecting_bounded_retry_after():
    source = XPoCSource(bearer_token="test", max_requests=2, max_retries=1, max_retry_after_seconds=0)
    limited = _response(429, {"detail": "synthetic rate limit"}, {"Retry-After": "120"})
    success = _response(200, {"data": [], "meta": {}})
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=[limited, success]) as get, patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
        result = await source.search_with_status("CVE-2024-3400", SearchConfig(request_limit=2, page_limit=2))

    assert result.status == "success"
    assert get.call_count == 2
    sleep.assert_awaited_once_with(0)
    assert any("bounded retry" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_x_cost_protection_and_legacy_search_wrapper_are_safe():
    source = XPoCSource(bearer_token="test", allow_paid_requests=False)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as get:
        status = await source.search_with_status("CVE-2024-3400")
        candidates = await source.search("CVE-2024-3400", limit=3)

    assert status.status == "cost_protection"
    assert candidates == []
    assert get.call_count == 0


@pytest.mark.asyncio
async def test_x_malformed_response_and_invalid_cve_are_explicit():
    source = XPoCSource(bearer_token="test")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=_response(200, ["not", "an", "object"])):
        malformed = await source.search_with_status("CVE-2024-3400")
    invalid = await source.search_with_status("not a cve")

    assert malformed.status == "malformed_response"
    assert invalid.status == "invalid_input"


@pytest.mark.asyncio
async def test_x_live_smoke_is_explicitly_opt_in_and_bounded(monkeypatch):
    """A live X request is skipped unless both credential and explicit opt-in exist."""
    if not (os.getenv("RUN_LIVE_X_TESTS") == "1" and os.getenv("X_BEARER_TOKEN")):
        pytest.skip("Live X smoke test requires RUN_LIVE_X_TESTS=1 and X_BEARER_TOKEN.")
    source = XPoCSource(max_results=10, max_requests=1, max_retries=0)
    result = await source.search_with_status("CVE-2021-44228", SearchConfig(result_limit=10, page_limit=1, request_limit=1))
    assert result.source == "x"
