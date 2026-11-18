from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from threat_retrieval_engine.api.schemas import PoCResultSchema
from threat_retrieval_engine.poc_intelligence.poc_validator import PoCValidator
from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate

logger = logging.getLogger(__name__)

_TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "s"}


def canonicalize_url(url: str) -> str:
    """Normalize URL by stripping tracking parameters, trailing slashes, and git branch subpaths."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return url.strip().rstrip("/")
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")

        # Clean GitHub repository root URLs (e.g., github.com/user/repo/tree/main -> github.com/user/repo)
        if "github.com" in netloc:
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 2:
                path = f"/{parts[0]}/{parts[1]}"

        # Remove tracking query parameters
        query = urlencode([(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() not in _TRACKING_PARAMS])
        return urlunparse((parsed.scheme.lower(), netloc, path, "", query, ""))
    except Exception:
        return url.strip().rstrip("/")


def _group_identity(candidate: RawCandidate) -> str:
    """Prefer an explicit verified repository/artifact identity over text similarity."""
    explicit = candidate.raw_metadata.get("artifact_identity")
    if isinstance(explicit, str) and explicit:
        return explicit.lower()
    for linked in candidate.linked_urls:
        normal = canonicalize_url(linked)
        if normal and ("github.com" in normal or "exploit-db.com" in normal or "packetstormsecurity.com" in normal):
            return normal.lower()
    return canonicalize_url(candidate.url).lower()


class ResultAggregator:
    """Group identical artifacts across sources and retain provenance."""

    def __init__(self, validator: PoCValidator | None = None) -> None:
        self.validator = validator or PoCValidator()

    def aggregate_and_validate(
        self,
        raw_candidates: list[RawCandidate],
        cve_id: str,
        min_confidence: float = 0.0,
        max_results: int = 20,
    ) -> list[PoCResultSchema]:
        if not raw_candidates:
            return []

        groups: dict[str, list[RawCandidate]] = {}
        for candidate in raw_candidates:
            identity = _group_identity(candidate)
            if identity:
                groups.setdefault(identity, []).append(candidate)

        results: list[PoCResultSchema] = []
        for identity, candidates in groups.items():
            # A GitHub repository contains direct metadata; otherwise retain earliest/richest source record
            primary = next(
                (item for item in candidates if item.source == "github" and (item.stars or 0) > 0),
                next((item for item in candidates if item.source == "github"), candidates[0]),
            )
            distinct_sources = {item.source for item in candidates}
            result = self.validator.validate_candidate(
                candidate=primary,
                cve_id=cve_id,
                cross_source_count=len(distinct_sources),
                duplicate_group=identity,
            )

            # Preserve canonical clean URL on output
            result.url = canonicalize_url(primary.url)

            # Retain all original source references with provenance
            result.source_references = [
                {
                    "source": item.source,
                    "url": item.url,
                    "author": item.author or "unknown",
                    "published_at": item.published_at,
                }
                for item in candidates
            ]

            # Merge evidence from all grouped records
            for item in candidates:
                for ev in item.evidence:
                    if ev not in result.evidence:
                        result.evidence.append(ev)

            if result.confidence_score >= min_confidence:
                results.append(result)

        results.sort(key=lambda item: (-item.confidence_score, -(item.stars or 0), item.url))
        return results[:max_results]
