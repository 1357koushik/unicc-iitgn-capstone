from __future__ import annotations

import logging
import os
from typing import Any
import httpx

try:
    from threat_retrieval_engine.poc_intelligence.sources.base import BasePoCSource, RawCandidate
except ImportError:
    from sources.base import BasePoCSource, RawCandidate

logger = logging.getLogger(__name__)


class GitHubPoCSource(BasePoCSource):
    """Scrapes public GitHub repositories for CVE-specific PoCs or exploits."""

    source_name: str = "github"

    def __init__(self, token: str | None = None, timeout_seconds: float = 10.0) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_PAT")
        self.timeout_seconds = timeout_seconds

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "UNICC-Team2-PoC-Harvester/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        cve_clean = cve_id.strip().upper()
        candidates: list[RawCandidate] = []
        seen_urls: set[str] = set()

        # Target queries: specific CVE and CVE+poc
        queries = [
            f"{cve_clean} in:name,description,readme",
            f"{cve_clean} poc",
        ]

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            for q in queries:
                if len(candidates) >= limit:
                    break
                url = "https://api.github.com/search/repositories"
                params = {
                    "q": q,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": min(limit, 30),
                }

                try:
                    response = await client.get(url, params=params, headers=self._get_headers())
                    if response.status_code == 200:
                        data = response.json()
                        items = data.get("items", [])
                        for item in items:
                            html_url = item.get("html_url", "")
                            if not html_url or html_url in seen_urls:
                                continue
                            seen_urls.add(html_url)

                            cand = RawCandidate(
                                url=html_url,
                                title=item.get("name") or item.get("full_name") or html_url,
                                source=self.source_name,
                                author=item.get("owner", {}).get("login", "unknown"),
                                published_at=item.get("created_at") or item.get("updated_at") or "",
                                description=item.get("description") or "",
                                stars=item.get("stargazers_count", 0),
                                forks=item.get("forks_count", 0),
                                language=item.get("language"),
                                is_fork=item.get("fork", False),
                                raw_metadata={
                                    "topics": item.get("topics", []),
                                    "default_branch": item.get("default_branch", "main"),
                                },
                            )
                            candidates.append(cand)
                            if len(candidates) >= limit:
                                break
                    elif response.status_code in (403, 429):
                        logger.warning(
                            "GitHub API rate limit exceeded or access forbidden (status %d). "
                            "Consider providing GITHUB_TOKEN.",
                            response.status_code,
                        )
                        break
                    else:
                        logger.warning("GitHub API returned unexpected status %d for query %s", response.status_code, q)
                except httpx.RequestError as exc:
                    logger.warning("GitHub request error for %s: %s", cve_clean, exc)
                except Exception as exc:
                    logger.warning("Unexpected error during GitHub search for %s: %s", cve_clean, exc)

        return candidates
