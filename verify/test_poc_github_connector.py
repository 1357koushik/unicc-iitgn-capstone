"""Synthetic, offline tests for the GitHub REST connector."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from threat_retrieval_engine.poc_intelligence.sources.base import SearchConfig
from threat_retrieval_engine.poc_intelligence.sources.github_scraper import GitHubPoCSource


def _response(status: int, payload: object, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        json=payload,
        headers=headers or {},
        request=httpx.Request("GET", "https://api.github.com/search/repositories"),
    )


def _repository(name: str = "CVE-2024-3400-poc") -> dict[str, object]:
    return {
        "html_url": f"https://github.com/researcher/{name}",
        "url": f"https://api.github.com/repos/researcher/{name}",
        "full_name": f"researcher/{name}",
        "name": name,
        "description": "Proof of concept for CVE-2024-3400",
        "owner": {"login": "researcher", "html_url": "https://github.com/researcher"},
        "stargazers_count": 9999,
        "forks_count": 4,
        "language": "Python",
        "fork": False,
        "archived": False,
        "created_at": "2024-04-15T10:00:00Z",
        "updated_at": "2024-04-16T10:00:00Z",
        "default_branch": "main",
        "topics": ["security"],
    }


@pytest.mark.asyncio
async def test_repository_results_are_normalized_with_evidence_and_metadata() -> None:
    """Fixtures are synthetic; no GitHub request is made in this test."""
    mock_get = AsyncMock(return_value=_response(200, {"items": [_repository()]}))
    connector = GitHubPoCSource(enable_code_search=False)
    with patch("httpx.AsyncClient.get", mock_get):
        outcome = await connector.search_with_status(
            "cve-2024-3400", SearchConfig(result_limit=5, page_limit=1, request_limit=3)
        )

    assert outcome.status == "success"
    assert outcome.result_count == 1
    finding = outcome.candidates[0]
    assert finding.url == "https://github.com/researcher/CVE-2024-3400-poc"
    assert finding.author == "researcher"
    assert finding.raw_metadata["repository_metadata"]["archived"] is False
    assert finding.raw_metadata["repository_metadata"]["updated_at"] == "2024-04-16T10:00:00Z"
    assert any("Exact CVE identifier" in item for item in finding.evidence)
    assert any("not evidence" in item for item in finding.evidence)
    assert mock_get.call_count == 3
    assert all(call.kwargs["headers"].get("Authorization") is None for call in mock_get.call_args_list)


@pytest.mark.asyncio
async def test_authenticated_code_search_adds_file_evidence_without_claiming_validation() -> None:
    repo = _repository()
    responses = [
        _response(200, {"items": [repo]}),
        _response(200, {"items": []}),
        _response(200, {"items": []}),
        _response(200, {"items": [{"path": "poc.py", "repository": repo}]}),
    ]
    mock_get = AsyncMock(side_effect=responses)
    connector = GitHubPoCSource(token="synthetic-token")
    with patch("httpx.AsyncClient.get", mock_get):
        outcome = await connector.search_with_status(
            "CVE-2024-3400", SearchConfig(result_limit=5, page_limit=1, request_limit=4)
        )

    assert outcome.status == "success"
    assert outcome.pages_fetched == 4
    assert any("matching file: poc.py" in item for item in outcome.candidates[0].evidence)
    assert all(call.kwargs["headers"]["Authorization"] == "Bearer synthetic-token" for call in mock_get.call_args_list)
    assert mock_get.call_args_list[-1].args[0].endswith("/search/code")


@pytest.mark.asyncio
async def test_rate_limit_is_reported_without_retries_when_budget_is_one() -> None:
    connector = GitHubPoCSource(retry_attempts=2)
    with patch(
        "httpx.AsyncClient.get",
        AsyncMock(return_value=_response(429, {"message": "synthetic"}, {"Retry-After": "0"})),
    ) as mock_get:
        outcome = await connector.search_with_status(
            "CVE-2024-3400", SearchConfig(result_limit=5, page_limit=1, request_limit=1)
        )

    assert outcome.status == "rate_limited"
    assert outcome.candidates == []
    assert "rate_limited" in outcome.errors[0]
    assert mock_get.call_count == 1


@pytest.mark.asyncio
async def test_partial_outage_preserves_successful_repository_results() -> None:
    mock_get = AsyncMock(
        side_effect=[
            _response(200, {"items": [_repository()]}),
            _response(503, {"message": "synthetic transient failure"}),
            _response(503, {"message": "synthetic transient failure"}),
            _response(200, {"items": []}),
        ]
    )
    connector = GitHubPoCSource(enable_code_search=False, retry_backoff_seconds=0)
    with patch("httpx.AsyncClient.get", mock_get):
        outcome = await connector.search_with_status(
            "CVE-2024-3400", SearchConfig(result_limit=5, page_limit=1, request_limit=4)
        )

    assert outcome.status == "partial"
    assert outcome.result_count == 1
    assert any("http_503" in message for message in outcome.errors)


@pytest.mark.asyncio
async def test_invalid_identifier_does_not_make_a_network_request() -> None:
    connector = GitHubPoCSource()
    with patch("httpx.AsyncClient.get", AsyncMock()) as mock_get:
        outcome = await connector.search_with_status("not-a-cve", SearchConfig())

    assert outcome.status == "invalid_input"
    assert outcome.candidates == []
    mock_get.assert_not_called()
