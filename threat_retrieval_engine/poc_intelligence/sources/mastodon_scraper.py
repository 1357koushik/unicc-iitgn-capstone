from __future__ import annotations

import logging
import re
from typing import Any
import httpx
from bs4 import BeautifulSoup

try:
    from threat_retrieval_engine.poc_intelligence.sources.base import BasePoCSource, RawCandidate
except ImportError:
    from sources.base import BasePoCSource, RawCandidate

logger = logging.getLogger(__name__)

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
        cve_clean = cve_id.strip().upper()
        candidates: list[RawCandidate] = []
        seen_urls: set[str] = set()

        headers = {
            "Accept": "application/json",
            "User-Agent": "UNICC-Team2-PoC-Harvester/1.0",
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
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
                    response = await client.get(url, params=params, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        statuses = data.get("statuses", [])
                        for st in statuses:
                            post_url = st.get("url") or ""
                            raw_content = st.get("content", "")
                            clean_text = _strip_html(raw_content)
                            created_at = st.get("created_at", "")
                            account = st.get("account", {}).get("acct", "unknown")

                            # Check for card URL (link preview) or URLs in text
                            card_url = st.get("card", {}).get("url") if st.get("card") else None
                            embedded_urls = _URL_REGEX.findall(clean_text)
                            if card_url and card_url not in embedded_urls:
                                embedded_urls.insert(0, card_url)

                            # Determine target url
                            target_url = card_url or (embedded_urls[0] if embedded_urls else post_url)
                            if not target_url or target_url in seen_urls:
                                continue
                            seen_urls.add(target_url)

                            cand = RawCandidate(
                                url=target_url,
                                title=f"Mastodon post by @{account}: {clean_text[:80]}...",
                                source=self.source_name,
                                author=f"@{account}@{instance}",
                                published_at=created_at,
                                description=clean_text,
                                raw_metadata={
                                    "instance": instance,
                                    "post_url": post_url,
                                    "embedded_urls": embedded_urls,
                                },
                            )
                            candidates.append(cand)
                            if len(candidates) >= limit:
                                break
                    else:
                        logger.warning("Mastodon search on %s returned status %d", instance, response.status_code)
                except httpx.RequestError as exc:
                    logger.warning("Mastodon search request failed for %s: %s", instance, exc)
                except Exception as exc:
                    logger.warning("Unexpected error during Mastodon search on %s: %s", instance, exc)

        return candidates
