"""Bounded X API v2 recent-search connector.

This module deliberately uses the documented X API rather than scraping X. A
recent-search response is evidence of a public post, not that linked code is
safe or functional. The canonical post URL is retained; artifacts are separate.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
import re
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from threat_retrieval_engine.poc_intelligence.sources.base import (
    BasePoCSource, RawCandidate, SearchConfig, SourceSearchResponse, sanitize_untrusted_text,
)


logger = logging.getLogger(__name__)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_RECENT_SEARCH_URL = "https://api.x.com/2/tweets/search/recent"
_COVERAGE_LIMITATION = (
    "Uses X API v2 recent search only; coverage is limited to the API's recent-search "
    "window and the credential's endpoint access. It is not a complete historical X search."
)


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    """Read a bounded integer without letting invalid environment values crash search."""
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _error_detail(response: httpx.Response | Any) -> str:
    """Return a short safe API error description (never includes request headers)."""
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return "X API returned no parseable error body."
    if not isinstance(payload, dict):
        return "X API returned an unexpected error body."
    detail = payload.get("detail") or payload.get("title") or "X API request failed."
    return str(detail)[:240]


def _retry_after_seconds(headers: Any, default_seconds: float, maximum_seconds: float) -> float:
    """Respect Retry-After while retaining an explicit bounded retry policy."""
    value = headers.get("Retry-After") if headers else None
    if value:
        try:
            return min(maximum_seconds, max(0.0, float(value)))
        except (TypeError, ValueError):
            try:
                delay = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
                return min(maximum_seconds, max(0.0, delay))
            except (TypeError, ValueError, IndexError, OverflowError):
                pass
    return min(maximum_seconds, default_seconds)


class XPoCSource(BasePoCSource):
    """Discover CVE posts through the official X API v2 recent-search endpoint.

    X post reads can be consumption-billed. Defaults intentionally keep each
    search small (10 returned posts, two requests). Callers can disable it with
    ``X_ENABLED=false`` or block requests with ``X_ALLOW_PAID_REQUESTS=false``.
    """

    source_name = "x"

    def __init__(
        self,
        bearer_token: str | None = None,
        timeout_seconds: float | None = None,
        *,
        enabled: bool | None = None,
        allow_paid_requests: bool | None = None,
        max_results: int | None = None,
        max_requests: int | None = None,
        max_retries: int | None = None,
        max_retry_after_seconds: float | None = None,
        endpoint: str = _RECENT_SEARCH_URL,
    ) -> None:
        self.bearer_token = bearer_token or os.environ.get("X_BEARER_TOKEN") or os.environ.get("TWITTER_BEARER_TOKEN")
        self.timeout_seconds = timeout_seconds if timeout_seconds is not None else _env_float("X_TIMEOUT_SECONDS", 10.0, 1.0, 60.0)
        self.enabled = _env_bool("X_ENABLED", False) if enabled is None else enabled
        self.allow_paid_requests = _env_bool("X_ALLOW_PAID_REQUESTS", False) if allow_paid_requests is None else allow_paid_requests
        self.max_results = max_results if max_results is not None else _env_int("X_MAX_RESULTS", 10, 1, 100)
        self.max_requests = max_requests if max_requests is not None else _env_int("X_MAX_REQUESTS", 2, 1, 10)
        self.max_retries = max_retries if max_retries is not None else _env_int("X_MAX_RETRIES", 1, 0, 3)
        self.max_retry_after_seconds = max_retry_after_seconds if max_retry_after_seconds is not None else _env_float("X_MAX_RETRY_AFTER_SECONDS", 5.0, 0.0, 60.0)
        self.endpoint = endpoint

    @staticmethod
    def build_query(cve_id: str) -> str:
        """Return a narrow, testable query centred on the exact requested CVE."""
        return f'{cve_id} (poc OR exploit OR "proof of concept") -is:retweet lang:en'

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        """Legacy list-only entry point; orchestration should use ``search_with_status``."""
        response = await self.search_with_status(cve_id, SearchConfig(result_limit=limit))
        return response.candidates

    async def search_with_status(self, cve_id: str, config: SearchConfig | None = None) -> SourceSearchResponse:
        config = config or SearchConfig()
        cve_clean = cve_id.strip().upper()
        query = self.build_query(cve_clean) if _CVE_RE.fullmatch(cve_clean) else cve_clean
        coverage = [_COVERAGE_LIMITATION]

        if not _CVE_RE.fullmatch(cve_clean):
            return SourceSearchResponse(source=self.source_name, status="invalid_input", query=query,
                errors=["CVE identifier must match CVE-YYYY-NNNN (with a 4-7 digit suffix)."], coverage_limitations=coverage)
        if not self.enabled:
            return SourceSearchResponse(source=self.source_name, status="disabled", query=query,
                warnings=["X connector is disabled by X_ENABLED."], coverage_limitations=coverage)
        if not self.bearer_token:
            return SourceSearchResponse(source=self.source_name, status="not_configured", query=query,
                errors=["Set X_BEARER_TOKEN to enable official X API v2 recent search."], coverage_limitations=coverage)
        if not self.allow_paid_requests:
            return SourceSearchResponse(source=self.source_name, status="cost_protection", query=query,
                warnings=["X API requests are blocked by X_ALLOW_PAID_REQUESTS=false."], coverage_limitations=coverage)

        # SearchConfig can only narrow these per-source cost safeguards.
        requested_results = max(1, min(config.result_limit, self.max_results, 100))
        request_budget = max(1, min(config.request_limit, config.page_limit, self.max_requests))
        timeout = max(1.0, min(config.timeout_seconds, self.timeout_seconds, 60.0))
        # X recent search accepts 10--100 per request. Results are sliced locally.
        per_page = max(10, min(100, requested_results))
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Accept": "application/json",
            "User-Agent": "UNICC-CVE-PoC-Discovery/1.0",
        }
        candidates: list[RawCandidate] = []
        warnings: list[str] = []
        errors: list[str] = []
        seen_post_ids: set[str] = set()
        next_token: str | None = None
        pages_fetched = 0
        requests_made = 0
        retries_used = 0
        terminal_status = "success"

        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            while len(candidates) < requested_results and requests_made < request_budget:
                params: dict[str, str | int] = {
                    "query": query, "max_results": per_page,
                    "tweet.fields": "created_at,author_id,entities,public_metrics",
                    "expansions": "author_id", "user.fields": "username,name",
                }
                if next_token:
                    params["next_token"] = next_token
                try:
                    response = await client.get(self.endpoint, params=params, headers=headers)
                    requests_made += 1
                except (httpx.TimeoutException, httpx.RequestError) as exc:
                    if retries_used < self.max_retries and requests_made < request_budget:
                        retries_used += 1
                        await asyncio.sleep(min(self.max_retry_after_seconds, 0.5 * (2 ** (retries_used - 1))))
                        continue
                    terminal_status = "timeout" if isinstance(exc, httpx.TimeoutException) else "unavailable"
                    errors.append(f"{type(exc).__name__}: {str(exc)[:200]}")
                    break

                if response.status_code == 200:
                    try:
                        payload = response.json()
                    except (ValueError, TypeError):
                        terminal_status, errors = "malformed_response", ["X API returned invalid JSON."]
                        break
                    if not isinstance(payload, dict):
                        terminal_status, errors = "malformed_response", ["X API returned an unexpected JSON object."]
                        break
                    pages_fetched += 1
                    self._append_candidates(payload, cve_clean, candidates, seen_post_ids, requested_results)
                    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
                    received_next = meta.get("next_token") if isinstance(meta.get("next_token"), str) else None
                    if not received_next or len(candidates) >= requested_results:
                        next_token = received_next
                        break
                    next_token = received_next
                    continue

                detail = _error_detail(response)
                if response.status_code == 401:
                    terminal_status, errors = "unauthorized", [detail]
                    break
                if response.status_code == 403:
                    terminal_status, errors = "access_restricted", [detail]
                    break
                if response.status_code == 429:
                    terminal_status, errors = "rate_limited", [detail]
                    if retries_used < self.max_retries and requests_made < request_budget:
                        retries_used += 1
                        await asyncio.sleep(_retry_after_seconds(response.headers, 1.0, self.max_retry_after_seconds))
                        terminal_status, errors = "success", []
                        continue
                    break
                if response.status_code in {500, 502, 503, 504} and retries_used < self.max_retries and requests_made < request_budget:
                    retries_used += 1
                    await asyncio.sleep(min(self.max_retry_after_seconds, 0.5 * (2 ** (retries_used - 1))))
                    continue
                terminal_status, errors = "error", [f"HTTP {response.status_code}: {detail}"]
                break

        if requests_made >= request_budget and next_token and len(candidates) < requested_results:
            warnings.append("Stopped at the configured X request/page budget; additional recent results may exist.")
        if retries_used:
            warnings.append(f"Used {retries_used} bounded retry attempt(s).")
        if terminal_status == "success" and not candidates:
            warnings.append("X API returned no matching posts within the accessible recent-search window.")
        return SourceSearchResponse(source=self.source_name, status=terminal_status, query=query,
            candidates=candidates, next_cursor=next_token, pages_fetched=pages_fetched,
            errors=errors, warnings=warnings, coverage_limitations=coverage)

    @staticmethod
    def _append_candidates(payload: dict[str, Any], cve_id: str, candidates: list[RawCandidate], seen_post_ids: set[str], result_limit: int) -> None:
        posts = payload.get("data")
        if not isinstance(posts, list):
            return
        includes = payload.get("includes") if isinstance(payload.get("includes"), dict) else {}
        users = includes.get("users") if isinstance(includes.get("users"), list) else []
        users_by_id = {str(u.get("id")): u for u in users if isinstance(u, dict) and u.get("id") is not None}
        for post in posts:
            if len(candidates) >= result_limit or not isinstance(post, dict):
                break
            post_id = str(post.get("id") or "")
            if not post_id or post_id in seen_post_ids:
                continue
            seen_post_ids.add(post_id)
            text = str(post.get("text") or "")
            author_id = str(post.get("author_id") or "")
            user = users_by_id.get(author_id, {})
            username = str(user.get("username") or "")
            author = f"@{username}" if username else (author_id or "unknown")
            post_url = f"https://x.com/{username}/status/{post_id}" if username else f"https://x.com/i/web/status/{post_id}"
            entities = post.get("entities") if isinstance(post.get("entities"), dict) else {}
            entity_urls = entities.get("urls") if isinstance(entities.get("urls"), list) else []
            linked_urls: list[str] = []
            short_to_expanded: dict[str, str] = {}
            for entity in entity_urls:
                if isinstance(entity, dict):
                    short_val = entity.get("url")
                    expanded_val = entity.get("expanded_url") or short_val
                    if isinstance(expanded_val, str) and expanded_val not in linked_urls:
                        linked_urls.append(expanded_val)
                    if isinstance(short_val, str) and isinstance(expanded_val, str):
                        short_to_expanded[short_val] = expanded_val
            for value in _URL_RE.findall(text):
                cleaned = value.rstrip(".,);]}")
                mapped = short_to_expanded.get(cleaned, cleaned)
                if mapped not in linked_urls:
                    linked_urls.append(mapped)
            metrics = post.get("public_metrics") if isinstance(post.get("public_metrics"), dict) else {}
            sanitized_text = sanitize_untrusted_text(text, max_chars=2000)
            candidates.append(RawCandidate(
                url=post_url,
                title=sanitize_untrusted_text(f"X post by {author} about {cve_id}: {sanitized_text[:120]}", max_chars=200),
                source="x",
                author=author,
                published_at=post.get("created_at") if isinstance(post.get("created_at"), str) else None,
                description=sanitized_text,
                linked_urls=linked_urls,
                evidence=["Exact requested CVE query", "Public X API v2 post metadata"],
                raw_metadata={"post_id": post_id, "post_url": post_url, "author_id": author_id or None,
                    "author_username": username or None, "author_name": user.get("name") if isinstance(user.get("name"), str) else None,
                    "public_metrics": metrics, "linked_urls": linked_urls},
            ))
