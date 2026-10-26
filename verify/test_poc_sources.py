from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate
from threat_retrieval_engine.poc_intelligence.sources.github_scraper import GitHubPoCSource
from threat_retrieval_engine.poc_intelligence.sources.x_scraper import XPoCSource
from threat_retrieval_engine.poc_intelligence.sources.mastodon_scraper import MastodonPoCSource
from threat_retrieval_engine.poc_intelligence.sources.bluesky_scraper import BlueSkyPoCSource


@pytest.mark.asyncio
async def test_github_scraper_parses_items():
    scraper = GitHubPoCSource()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "items": [
            {
                "html_url": "https://github.com/hacker/cve-2024-3400-poc",
                "name": "cve-2024-3400-poc",
                "owner": {"login": "hacker"},
                "created_at": "2024-04-15T10:00:00Z",
                "description": "Exploit script for CVE-2024-3400",
                "stargazers_count": 42,
                "forks_count": 5,
                "language": "Python",
                "fork": False,
            }
        ]
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        results = await scraper.search("CVE-2024-3400", limit=5)
        assert len(results) == 1
        assert results[0].url == "https://github.com/hacker/cve-2024-3400-poc"
        assert results[0].stars == 42
        assert results[0].source == "github"


@pytest.mark.asyncio
async def test_bluesky_scraper_parses_posts():
    scraper = BlueSkyPoCSource()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "posts": [
            {
                "uri": "at://did:plc:123/app.bsky.feed.post/3kqj",
                "author": {"handle": "infosec_researcher.bsky.social"},
                "record": {
                    "text": "Tested CVE-2024-3400 exploit code against lab environment. Works reliably.",
                    "createdAt": "2024-04-16T12:00:00Z",
                },
            }
        ]
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        results = await scraper.search("CVE-2024-3400", limit=5)
        assert len(results) == 1
        assert "infosec_researcher.bsky.social" in results[0].author
        assert results[0].source == "bluesky"


@pytest.mark.asyncio
async def test_mastodon_scraper_parses_statuses():
    scraper = MastodonPoCSource(instances=["infosec.exchange"])
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "statuses": [
            {
                "url": "https://infosec.exchange/@analyst/11223344",
                "content": "<p>New PoC released for <strong>CVE-2024-3400</strong>: https://github.com/target/poc</p>",
                "created_at": "2024-04-16T14:00:00Z",
                "account": {"acct": "analyst"},
            }
        ]
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        results = await scraper.search("CVE-2024-3400", limit=5)
        assert len(results) == 1
        assert results[0].source == "mastodon"
        assert "CVE-2024-3400" in results[0].description
