from __future__ import annotations

import logging
import os
import re
from typing import Any
try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

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


class BlueSkyPoCSource(BasePoCSource):
    """Searches BlueSky public AT Protocol firehose for PoC discussions and releases."""

    source_name: str = "bluesky"

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        handle: str | None = None,
        app_password: str | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.handle = handle or os.environ.get("BLUESKY_HANDLE", "").strip()
        self.app_password = app_password or os.environ.get("BLUESKY_APP_PASSWORD", "").strip()
        self.api_endpoint = "https://bsky.social/xrpc/app.bsky.feed.searchPosts" if (self.handle and self.app_password) else "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"
        self.session_endpoint = "https://bsky.social/xrpc/com.atproto.server.createSession"
        self._access_jwt: str | None = None

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
        page_limit = max(1, cfg.page_limit)
        request_limit = max(1, cfg.request_limit)
        timeout = cfg.timeout_seconds or self.timeout_seconds

        candidates: list[RawCandidate] = []
        seen_uris: set[str] = set()
        errors: list[str] = []
        warnings: list[str] = []
        coverage: list[str] = [
            "Queries public AT Protocol searchPosts endpoint (public.api.bsky.app).",
            "Returns recent indexed posts matching the CVE query; Subject to public API rate limits.",
        ]

        if httpx is None:
            return SourceSearchResponse(
                source=self.source_name,
                status="not_configured",
                query=f"{cve_clean} poc",
                errors=["httpx library is not installed"],
            )

        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

        cursor: str | None = None
        pages_fetched = 0
        requests_made = 0
        terminal_status = "success"

        async with httpx.AsyncClient(timeout=timeout) as client:
            # If app password is provided, authenticate session to avoid Cloudflare challenge
            if self.handle and self.app_password and not self._access_jwt:
                try:
                    auth_resp = await client.post(
                        self.session_endpoint,
                        json={"identifier": self.handle, "password": self.app_password},
                        headers={"Content-Type": "application/json"},
                    )
                    if auth_resp.status_code == 200:
                        self._access_jwt = auth_resp.json().get("accessJwt")
                except Exception as auth_err:
                    warnings.append(f"BlueSky auth session failed: {auth_err}")

            if self._access_jwt:
                headers["Authorization"] = f"Bearer {self._access_jwt}"
            while len(candidates) < limit and pages_fetched < page_limit and requests_made < request_limit:
                params: dict[str, Any] = {
                    "q": f"{cve_clean} poc",
                    "limit": min(limit - len(candidates), 25),
                }
                if cursor:
                    params["cursor"] = cursor

                requests_made += 1
                try:
                    response = await client.get(self.api_endpoint, params=params, headers=headers)
                except httpx.TimeoutException:
                    terminal_status = "timeout"
                    errors.append(f"BlueSky API request timed out after {timeout}s.")
                    break
                except httpx.RequestError as exc:
                    terminal_status = "error"
                    errors.append(f"BlueSky connection failed: {type(exc).__name__}")
                    break

                pages_fetched += 1

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except Exception as exc:
                        terminal_status = "error"
                        errors.append(f"BlueSky API returned malformed JSON: {exc}")
                        break

                    if not isinstance(data, dict):
                        terminal_status = "error"
                        errors.append("BlueSky API returned non-object JSON payload.")
                        break

                    posts = data.get("posts", [])
                    cursor = data.get("cursor")
                    for post in posts:
                        if not isinstance(post, dict):
                            continue
                        at_uri = post.get("uri", "")
                        if at_uri in seen_uris:
                            continue
                        seen_uris.add(at_uri)

                        author_info = post.get("author") if isinstance(post.get("author"), dict) else {}
                        handle = author_info.get("handle", "anonymous")
                        record = post.get("record") if isinstance(post.get("record"), dict) else {}
                        text = record.get("text", "")
                        created_at = record.get("createdAt")

                        rkey = at_uri.split("/")[-1] if "/" in at_uri else ""
                        post_web_url = f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey else at_uri

                        embed_val = record.get("embed")
                        external_embed = embed_val.get("external") if isinstance(embed_val, dict) else {}
                        external_url = external_embed.get("uri") if isinstance(external_embed, dict) else None

                        text_urls = _URL_REGEX.findall(text)
                        if external_url and external_url not in text_urls:
                            text_urls.insert(0, external_url)

                        cand = RawCandidate(
                            url=post_web_url,
                            title=f"BlueSky post by @{handle}: {text[:80]}..." if text else f"BlueSky post by @{handle}",
                            source=self.source_name,
                            author=f"@{handle}",
                            published_at=created_at,
                            description=text,
                            linked_urls=text_urls,
                            evidence=["Exact requested CVE query", "Public AT Protocol searchPosts metadata"],
                            raw_metadata={
                                "at_uri": at_uri,
                                "post_web_url": post_web_url,
                                "external_urls": text_urls,
                                "cid": post.get("cid"),
                            },
                        )
                        candidates.append(cand)
                        if len(candidates) >= limit:
                            break

                    if not cursor or not posts:
                        break
                elif response.status_code == 401:
                    terminal_status = "unauthorized"
                    errors.append("BlueSky AT Protocol search returned HTTP 401 (unauthorized).")
                    break
                elif response.status_code == 403:
                    terminal_status = "access_restricted"
                    errors.append("BlueSky AT Protocol search returned HTTP 403 (access restricted).")
                    break
                elif response.status_code == 429:
                    terminal_status = "rate_limited"
                    errors.append("BlueSky AT Protocol search returned HTTP 429 (rate limited).")
                    break
                else:
                    terminal_status = "error"
                    errors.append(f"BlueSky API returned HTTP {response.status_code}")
                    break

        if terminal_status == "success" and not candidates:
            warnings.append("No matching public posts found on BlueSky.")

        return SourceSearchResponse(
            source=self.source_name,
            status=terminal_status,
            query=f"{cve_clean} poc",
            candidates=candidates,
            next_cursor=cursor,
            pages_fetched=pages_fetched,
            errors=errors,
            warnings=warnings,
            coverage_limitations=coverage,
        )
