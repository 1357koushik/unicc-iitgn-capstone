from __future__ import annotations

import logging
import os
import re
from typing import Any
import httpx

try:
    from threat_retrieval_engine.poc_intelligence.sources.base import BasePoCSource, RawCandidate
except ImportError:
    from sources.base import BasePoCSource, RawCandidate

logger = logging.getLogger(__name__)

_URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


class XPoCSource(BasePoCSource):
    """Searches X (formerly Twitter) v2 API for real-time PoC announcements."""

    source_name: str = "x"

    def __init__(self, bearer_token: str | None = None, timeout_seconds: float = 10.0) -> None:
        self.bearer_token = (
            bearer_token
            or os.environ.get("X_BEARER_TOKEN")
            or os.environ.get("TWITTER_BEARER_TOKEN")
        )
        self.timeout_seconds = timeout_seconds

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        cve_clean = cve_id.strip().upper()
        if not self.bearer_token:
            logger.info("X/Twitter bearer token not set; skipping live X API search for %s.", cve_clean)
            return []

        candidates: list[RawCandidate] = []
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "User-Agent": "UNICC-Team2-PoC-Harvester/1.0",
        }
        query = f"{cve_clean} (poc OR exploit OR \"proof of concept\") -is:retweet lang:en"
        url = "https://api.twitter.com/2/tweets/search/recent"
        params = {
            "query": query,
            "max_results": max(10, min(limit, 50)),
            "tweet.fields": "created_at,entities,author_id,text",
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            try:
                response = await client.get(url, params=params, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    tweets = data.get("data", [])
                    for tweet in tweets:
                        tweet_id = tweet.get("id")
                        text = tweet.get("text", "")
                        created_at = tweet.get("created_at", "")
                        author_id = tweet.get("author_id", "unknown")

                        # Extract embedded URLs from entities or regex
                        entities_urls = tweet.get("entities", {}).get("urls", [])
                        extracted_urls = [u.get("expanded_url") for u in entities_urls if u.get("expanded_url")]
                        if not extracted_urls:
                            extracted_urls = _URL_REGEX.findall(text)

                        primary_url = extracted_urls[0] if extracted_urls else f"https://x.com/i/status/{tweet_id}"

                        cand = RawCandidate(
                            url=primary_url,
                            title=f"X Post regarding {cve_clean}: {text[:80]}...",
                            source=self.source_name,
                            author=author_id,
                            published_at=created_at,
                            description=text,
                            raw_metadata={
                                "tweet_id": tweet_id,
                                "all_urls": extracted_urls,
                            },
                        )
                        candidates.append(cand)
                        if len(candidates) >= limit:
                            break
                elif response.status_code in (401, 403):
                    logger.warning("X API authentication failure (status %d).", response.status_code)
                elif response.status_code == 429:
                    logger.warning("X API rate limit exceeded.")
                else:
                    logger.warning("X API returned unexpected status %d for %s", response.status_code, cve_clean)
            except httpx.RequestError as exc:
                logger.warning("X API request error for %s: %s", cve_clean, exc)
            except Exception as exc:
                logger.warning("Unexpected error during X API search for %s: %s", cve_clean, exc)

        return candidates
