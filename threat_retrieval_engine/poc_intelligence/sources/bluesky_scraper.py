from __future__ import annotations

import logging
import re
from typing import Any
import httpx

try:
    from threat_retrieval_engine.poc_intelligence.sources.base import BasePoCSource, RawCandidate
except ImportError:
    from sources.base import BasePoCSource, RawCandidate

logger = logging.getLogger(__name__)

_URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


class BlueSkyPoCSource(BasePoCSource):
    """Searches BlueSky public AT Protocol firehose for PoC discussions and releases."""

    source_name: str = "bluesky"

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds
        self.api_endpoint = "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        cve_clean = cve_id.strip().upper()
        candidates: list[RawCandidate] = []
        seen_urls: set[str] = set()

        headers = {
            "Accept": "application/json",
            "User-Agent": "UNICC-Team2-PoC-Harvester/1.0",
        }
        params = {
            "q": f"{cve_clean} poc",
            "limit": min(limit, 25),
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            try:
                response = await client.get(self.api_endpoint, params=params, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    posts = data.get("posts", [])
                    for post in posts:
                        author_info = post.get("author", {})
                        handle = author_info.get("handle", "anonymous")
                        record = post.get("record", {})
                        text = record.get("text", "")
                        created_at = record.get("createdAt", "")

                        # Construct web URL from AT-URI
                        at_uri = post.get("uri", "")
                        rkey = at_uri.split("/")[-1] if "/" in at_uri else ""
                        post_web_url = f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey else at_uri

                        # Check external embed URL
                        external_embed = record.get("embed", {}).get("external", {})
                        external_url = external_embed.get("uri")
                        text_urls = _URL_REGEX.findall(text)
                        if external_url and external_url not in text_urls:
                            text_urls.insert(0, external_url)

                        target_url = external_url or (text_urls[0] if text_urls else post_web_url)
                        if not target_url or target_url in seen_urls:
                            continue
                        seen_urls.add(target_url)

                        cand = RawCandidate(
                            url=target_url,
                            title=f"BlueSky post by @{handle}: {text[:80]}...",
                            source=self.source_name,
                            author=f"@{handle}",
                            published_at=created_at,
                            description=text,
                            raw_metadata={
                                "at_uri": at_uri,
                                "post_web_url": post_web_url,
                                "external_urls": text_urls,
                            },
                        )
                        candidates.append(cand)
                        if len(candidates) >= limit:
                            break
                else:
                    logger.warning("BlueSky API search returned status %d for %s", response.status_code, cve_clean)
            except httpx.RequestError as exc:
                logger.warning("BlueSky request error for %s: %s", cve_clean, exc)
            except Exception as exc:
                logger.warning("Unexpected error during BlueSky search for %s: %s", cve_clean, exc)

        return candidates
