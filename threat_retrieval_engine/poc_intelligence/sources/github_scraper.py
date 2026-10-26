"""Bounded GitHub REST API discovery for CVE-related public repositories.

GitHub search is discovery, not proof that an exploit works. Repository search
only establishes an indexed match; authenticated code search can add a matching
file path. Both facts are retained as evidence for the ranking layer.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from collections.abc import Mapping
from typing import Any

import httpx

try:
    from threat_retrieval_engine.poc_intelligence.sources.base import (
        BasePoCSource,
        RawCandidate,
        SearchConfig,
        SourceSearchResponse,
    )
except ImportError:  # pragma: no cover - permits running this module directly
    from sources.base import BasePoCSource, RawCandidate, SearchConfig, SourceSearchResponse


logger = logging.getLogger(__name__)

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_POC_TERMS = re.compile(r"\b(?:poc|proof[ _-]?of[ _-]?concept|exploit|rce)\b", re.IGNORECASE)
_GITHUB_API = "https://api.github.com"


class GitHubPoCSource(BasePoCSource):
    """Discover public GitHub repositories using GitHub's supported REST API.

    ``GITHUB_TOKEN`` (or legacy ``GITHUB_PAT``) is optional for repository
    search. A token is required before code search is attempted, so the
    connector does not waste anonymous request budget on inaccessible calls.
    """

    source_name = "github"

    def __init__(
        self,
        token: str | None = None,
        timeout_seconds: float = 10.0,
        *,
        enable_code_search: bool = True,
        retry_attempts: int = 2,
        retry_backoff_seconds: float = 0.25,
    ) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_PAT")
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self.enable_code_search = enable_code_search
        self.retry_attempts = max(1, int(retry_attempts))
        self.retry_backoff_seconds = max(0.0, float(retry_backoff_seconds))

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "UNICC-CVE-PoC-Discovery/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @staticmethod
    def _queries(cve_id: str) -> list[str]:
        """Keep precision-oriented queries explicit, bounded, and testable."""
        return [
            f"{cve_id} in:name,description,readme",
            f"{cve_id} poc in:name,description,readme",
            f"{cve_id} exploit in:name,description,readme",
        ]

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int, fallback: float) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), 30.0))
            except ValueError:
                pass
        return fallback * (2**attempt)

    async def _get_json(
        self,
        client: httpx.AsyncClient,
        path: str,
        *,
        params: dict[str, Any],
        remaining_requests: int,
    ) -> tuple[Mapping[str, Any] | None, httpx.Response | None, str | None, int]:
        """Perform one bounded API request with transient retry handling.

        Error text deliberately excludes response bodies because external content
        is untrusted and must not become an accidental log or UI payload.
        """
        attempts = min(self.retry_attempts, max(0, remaining_requests))
        used = 0
        last_response: httpx.Response | None = None
        for attempt in range(attempts):
            try:
                response = await client.get(
                    f"{_GITHUB_API}{path}", params=params, headers=self._get_headers()
                )
                used += 1
                last_response = response
            except httpx.TimeoutException:
                return None, None, "timeout", used
            except httpx.RequestError:
                if attempt + 1 < attempts:
                    await asyncio.sleep(self.retry_backoff_seconds * (2**attempt))
                    continue
                return None, None, "network_error", used

            if response.status_code == 200:
                try:
                    payload = response.json()
                except ValueError:
                    return None, response, "malformed_response", used
                if not isinstance(payload, Mapping):
                    return None, response, "malformed_response", used
                return payload, response, None, used

            transient = response.status_code == 429 or response.status_code >= 500
            if transient and attempt + 1 < attempts:
                await asyncio.sleep(self._retry_delay(response, attempt, self.retry_backoff_seconds))
                continue
            if response.status_code in (401, 403):
                if response.headers.get("X-RateLimit-Remaining") == "0":
                    return None, response, "rate_limited", used
                return None, response, "unauthorized", used
            if response.status_code == 429:
                return None, response, "rate_limited", used
            return None, response, f"http_{response.status_code}", used
        return None, last_response, "request_budget_exhausted", used

    @staticmethod
    def _repository_url(item: Mapping[str, Any]) -> str:
        value = item.get("html_url")
        return value if isinstance(value, str) and value.startswith("https://github.com/") else ""

    @staticmethod
    def _repository_metadata(item: Mapping[str, Any]) -> dict[str, Any]:
        owner = item.get("owner") if isinstance(item.get("owner"), Mapping) else {}
        license_info = item.get("license") if isinstance(item.get("license"), Mapping) else {}
        return {
            "full_name": item.get("full_name"),
            "api_url": item.get("url"),
            "owner": owner.get("login"),
            "owner_url": owner.get("html_url"),
            "description": item.get("description"),
            "stars": item.get("stargazers_count"),
            "forks": item.get("forks_count"),
            "language": item.get("language"),
            "is_fork": item.get("fork"),
            "archived": item.get("archived"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "pushed_at": item.get("pushed_at"),
            "default_branch": item.get("default_branch"),
            "topics": item.get("topics") if isinstance(item.get("topics"), list) else [],
            "license": license_info.get("spdx_id") or license_info.get("key"),
        }

    def _candidate_from_repository(
        self,
        item: Mapping[str, Any],
        *,
        cve_id: str,
        query: str,
        code_path: str | None = None,
    ) -> RawCandidate | None:
        url = self._repository_url(item)
        if not url:
            return None
        name = item.get("name") or item.get("full_name") or url
        title = str(name)
        description = item.get("description") if isinstance(item.get("description"), str) else ""
        corpus = f"{title} {description}"
        evidence = [
            f"GitHub repository search returned this repository for query: {query}",
            "Repository existence/accessibility is not evidence that exploit code is functional.",
        ]
        if cve_id.lower() in corpus.lower():
            evidence.append(f"Exact CVE identifier appears in repository name or description: {cve_id}.")
        if _POC_TERMS.search(corpus):
            evidence.append("Repository name or description contains PoC/exploit terminology.")
        if code_path:
            evidence.append(f"Authenticated GitHub code search returned a matching file: {code_path}.")

        owner = item.get("owner") if isinstance(item.get("owner"), Mapping) else {}
        metadata = self._repository_metadata(item)
        search_evidence: list[dict[str, str]] = [{"kind": "repository_search", "query": query}]
        if code_path:
            search_evidence.append({"kind": "code_search", "path": code_path})
        metadata["search_evidence"] = search_evidence
        return RawCandidate(
            url=url,
            title=title,
            source=self.source_name,
            author=str(owner.get("login") or "unknown"),
            published_at=item.get("created_at") if isinstance(item.get("created_at"), str) else None,
            description=description,
            stars=item.get("stargazers_count") if isinstance(item.get("stargazers_count"), int) else None,
            forks=item.get("forks_count") if isinstance(item.get("forks_count"), int) else None,
            language=item.get("language") if isinstance(item.get("language"), str) else None,
            is_fork=item.get("fork") if isinstance(item.get("fork"), bool) else None,
            evidence=evidence,
            raw_metadata={"repository_metadata": metadata},
        )

    @staticmethod
    def _merge_candidate(existing: RawCandidate, incoming: RawCandidate) -> None:
        for item in incoming.evidence:
            if item not in existing.evidence:
                existing.evidence.append(item)
        existing_meta = existing.raw_metadata.setdefault("repository_metadata", {})
        incoming_meta = incoming.raw_metadata.get("repository_metadata", {})
        current_evidence = existing_meta.setdefault("search_evidence", [])
        for item in incoming_meta.get("search_evidence", []):
            if item not in current_evidence:
                current_evidence.append(item)

    async def search_with_status(
        self, cve_id: str, config: SearchConfig | None = None
    ) -> SourceSearchResponse:
        config = config or SearchConfig(timeout_seconds=self.timeout_seconds)
        clean_cve = cve_id.strip().upper()
        if not _CVE_PATTERN.fullmatch(clean_cve):
            return SourceSearchResponse(
                source=self.source_name,
                status="invalid_input",
                query=clean_cve,
                errors=["CVE identifier must match CVE-YYYY-NNNN (4 to 7 digits after the second hyphen)."],
            )

        result_limit = max(1, min(int(config.result_limit), 100))
        page_limit = max(1, min(int(config.page_limit), 10))
        request_limit = max(1, min(int(config.request_limit), 30))
        queries = self._queries(clean_cve)
        response = SourceSearchResponse(
            source=self.source_name,
            status="success",
            query="; ".join(queries),
            coverage_limitations=[
                "GitHub repository search is limited to GitHub-indexed public content and does not validate exploit functionality.",
                "Only the bounded exact-CVE, PoC, and exploit query set was searched.",
            ],
        )
        if not self.token:
            response.coverage_limitations.append(
                "No GitHub token configured: code search was not attempted and repository-search rate limits are lower."
            )

        candidates_by_url: dict[str, RawCandidate] = {}
        used_requests = 0
        had_success = False
        terminal_error: str | None = None
        timeout = httpx.Timeout(max(0.1, min(float(config.timeout_seconds), self.timeout_seconds)))
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for query in queries:
                if used_requests >= request_limit:
                    response.warnings.append("GitHub request budget reached before all configured queries completed.")
                    break
                for page in range(1, page_limit + 1):
                    if used_requests >= request_limit:
                        response.warnings.append("GitHub request budget reached during pagination.")
                        break
                    payload, _http_response, error, used = await self._get_json(
                        client,
                        "/search/repositories",
                        params={"q": query, "sort": "updated", "order": "desc", "per_page": min(100, max(result_limit, 10)), "page": page},
                        remaining_requests=request_limit - used_requests,
                    )
                    used_requests += used
                    if error:
                        terminal_error = error
                        response.errors.append(f"repository search ({query}): {error}")
                        break
                    had_success = True
                    response.pages_fetched += 1
                    items = payload.get("items", []) if payload else []
                    if not isinstance(items, list):
                        response.errors.append(f"repository search ({query}): malformed_response")
                        break
                    for item in items:
                        if not isinstance(item, Mapping):
                            continue
                        candidate = self._candidate_from_repository(item, cve_id=clean_cve, query=query)
                        if not candidate:
                            continue
                        if candidate.url in candidates_by_url:
                            self._merge_candidate(candidates_by_url[candidate.url], candidate)
                        else:
                            candidates_by_url[candidate.url] = candidate
                    if len(items) < min(100, max(result_limit, 10)):
                        break

            # Code search is authenticated and only contributes a file reference,
            # never a claim that a discovered file is executable exploit code.
            if self.enable_code_search and self.token and used_requests < request_limit:
                code_query = f"{clean_cve} (poc OR exploit)"
                payload, _http_response, error, used = await self._get_json(
                    client,
                    "/search/code",
                    params={"q": code_query, "per_page": min(result_limit, 100), "page": 1},
                    remaining_requests=request_limit - used_requests,
                )
                used_requests += used
                if error:
                    response.warnings.append(f"authenticated code search unavailable: {error}")
                else:
                    had_success = True
                    response.pages_fetched += 1
                    items = payload.get("items", []) if payload else []
                    if isinstance(items, list):
                        for item in items:
                            if not isinstance(item, Mapping) or not isinstance(item.get("repository"), Mapping):
                                continue
                            path = item.get("path") if isinstance(item.get("path"), str) else None
                            candidate = self._candidate_from_repository(
                                item["repository"], cve_id=clean_cve, query=code_query, code_path=path
                            )
                            if candidate:
                                if candidate.url in candidates_by_url:
                                    self._merge_candidate(candidates_by_url[candidate.url], candidate)
                                else:
                                    candidates_by_url[candidate.url] = candidate
                    else:
                        response.warnings.append("authenticated code search returned malformed items.")

        # Local ordering promotes only direct textual/file evidence. Popularity is
        # retained as metadata and intentionally does not affect this ordering.
        def evidence_rank(candidate: RawCandidate) -> tuple[int, str]:
            text = f"{candidate.title} {candidate.description}".lower()
            return (
                (4 if clean_cve.lower() in text else 0)
                + (2 if _POC_TERMS.search(text) else 0)
                + sum(1 for evidence in candidate.evidence if "matching file" in evidence),
                candidate.url,
            )

        response.candidates = sorted(candidates_by_url.values(), key=evidence_rank, reverse=True)[:result_limit]
        if not had_success:
            response.status = terminal_error or "error"
        elif response.errors or response.warnings:
            response.status = "partial"
        return response

    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        """Legacy list-only wrapper used by older orchestration callers."""
        status = await self.search_with_status(
            cve_id,
            SearchConfig(
                result_limit=limit,
                timeout_seconds=self.timeout_seconds,
                request_limit=4,
                page_limit=1,
            ),
        )
        return status.candidates
