from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup

try:
    from threat_retrieval_engine.poc_intelligence.sources.base import (
        BasePoCSource,
        RawCandidate,
        SearchConfig,
        SourceSearchResponse,
    )
except ImportError:
    from sources.base import BasePoCSource, RawCandidate, SearchConfig, SourceSearchResponse

logger = logging.getLogger(__name__)

_CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


def _strip_html(html_str: str) -> str:
    """Strip HTML markup and return clean text."""
    if not html_str:
        return ""
    try:
        soup = BeautifulSoup(html_str, "html.parser")
        return soup.get_text(separator=" ").strip()
    except Exception:
        return re.sub(r"<[^>]+>", "", html_str).strip()


class MastodonPoCSource(BasePoCSource):
    """Searches Mastodon federated infosec instances for PoC discussions and releases."""

    source_name: str = "mastodon"

    def __init__(
        self,
        instances: list[str] | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.instances = instances or ["infosec.exchange", "defcon.social"]
        self.timeout_seconds = timeout_seconds

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        """Compatibility wrapper returning candidates directly."""
        response = await self.search_with_status(cve_id, SearchConfig(result_limit=limit, timeout_seconds=self.timeout_seconds))
        return response.candidates

    async def search_with_status(
        self, cve_id: str, config: SearchConfig | None = None
    ) -> SourceSearchResponse:
        cve_clean = cve_id.strip().upper()
        if not _CVE_REGEX.match(cve_clean):
            return SourceSearchResponse(
                source=self.source_name,
                status="error",
                query=cve_id,
                errors=[f"Invalid CVE identifier format: '{cve_id}'"],
            )

        cfg = config or SearchConfig(timeout_seconds=self.timeout_seconds)
        limit = cfg.result_limit
        timeout = cfg.timeout_seconds or self.timeout_seconds

        candidates: list[RawCandidate] = []
        seen_urls: set[str] = set()
        errors: list[str] = []
        warnings: list[str] = []
        coverage: list[str] = [
            f"Searched federated instances: {', '.join(self.instances)}.",
            "Public Mastodon /api/v2/search returns statuses only when full-text search is permitted without authentication on that instance.",
        ]
        pages_fetched = 0
        success_instances = 0

        headers = {
            "Accept": "application/json",
            "User-Agent": "UNICC-Team2-PoC-Harvester/1.0",
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            for instance in self.instances:
                if len(candidates) >= limit:
                    break
                url = f"https://{instance}/api/v2/search"
                params = {
                    "q": f"{cve_clean} poc",
                    "type": "statuses",
                    "limit": min(limit, 20),
                    "resolve": "false",
                }

                try:
                    pages_fetched += 1
                    response = await client.get(url, params=params, headers=headers)
                    if response.status_code == 200:
                        success_instances += 1
                        data = response.json()
                        statuses = data.get("statuses", [])
                        for st in statuses:
                            post_url = st.get("url") or ""
                            raw_content = st.get("content", "")
                            clean_text = _strip_html(raw_content)
                            created_at = st.get("created_at")
                            account = st.get("account", {}).get("acct", "unknown")

                            # Check for card URL (link preview) or URLs in text
                            card_url = st.get("card", {}).get("url") if st.get("card") else None
                            embedded_urls = _URL_REGEX.findall(clean_text)
                            if card_url and card_url not in embedded_urls:
                                embedded_urls.insert(0, card_url)

                            # Retain post_url as candidate URL, with embedded links in linked_urls
                            primary_url = post_url or (embedded_urls[0] if embedded_urls else f"https://{instance}/")
                            if primary_url in seen_urls:
                                continue
                            seen_urls.add(primary_url)

                            cand = RawCandidate(
                                url=primary_url,
                                title=f"Mastodon post by @{account}: {clean_text[:80]}..." if clean_text else f"Mastodon status on {instance}",
                                source=self.source_name,
                                author=f"@{account}@{instance}",
                                published_at=created_at,
                                description=clean_text,
                                linked_urls=embedded_urls,
                                evidence=["Exact requested CVE query", f"Public status on {instance}"],
                                raw_metadata={
                                    "instance": instance,
                                    "post_url": post_url,
                                    "embedded_urls": embedded_urls,
                                },
                            )
                            candidates.append(cand)
                            if len(candidates) >= limit:
                                break
                    elif response.status_code in {401, 403}:
                        warnings.append(f"{instance}: Search requires authentication or is restricted (HTTP {response.status_code}).")
                    elif response.status_code == 429:
                        warnings.append(f"{instance}: Rate limit exceeded (HTTP 429).")
                    else:
                        errors.append(f"{instance} returned HTTP {response.status_code}")
                except httpx.TimeoutException:
                    errors.append(f"{instance}: Request timed out after {timeout}s.")
                except httpx.RequestError as exc:
                    errors.append(f"{instance}: Connection failed ({type(exc).__name__}).")
                except Exception as exc:
                    errors.append(f"{instance}: Unexpected error ({str(exc)[:120]}).")

        if success_instances > 0:
            terminal_status = "success" if not errors else "partial"
        elif any("Rate limit" in w for w in warnings):
            terminal_status = "rate_limited"
        elif any("requires authentication" in w for w in warnings) and not errors:
            terminal_status = "access_restricted"
        elif errors:
            terminal_status = "error"
        else:
            terminal_status = "success"

        if terminal_status == "success" and not candidates:
            warnings.append("No matching public statuses found on queried instances.")

        return SourceSearchResponse(
            source=self.source_name,
            status=terminal_status,
            query=f"{cve_clean} poc",
            candidates=candidates,
            pages_fetched=pages_fetched,
            errors=errors,
            warnings=warnings,
            coverage_limitations=coverage,
        )
