from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

try:
    from threat_retrieval_engine.api.schemas import PoCResultSchema
    from threat_retrieval_engine.poc_intelligence.poc_validator import PoCValidator
    from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate
except ImportError:
    from api.schemas import PoCResultSchema
    from poc_validator import PoCValidator
    from sources.base import RawCandidate

logger = logging.getLogger(__name__)

_TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "s"}


def canonicalize_url(url: str) -> str:
    """Normalize URL by stripping tracking parameters, trailing slashes, and anchor tags."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")

        # Clean GitHub repository root URLs (e.g., github.com/user/repo/tree/main -> github.com/user/repo)
        if "github.com" in netloc:
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 2:
                # Keep user/repo
                path = f"/{parts[0]}/{parts[1]}"

        # Remove tracking query parameters
        query = "&".join(
            q for q in parsed.query.split("&")
            if q and not any(q.startswith(f"{tp}=") for tp in _TRACKING_PARAMS)
        )
        return urlunparse((parsed.scheme or "https", netloc, path, "", query, ""))
    except Exception:
        return url.strip().rstrip("/")


class ResultAggregator:
    """Aggregates, deduplicates, and validates PoC candidates across multiple OSINT sources."""

    def __init__(self, validator: PoCValidator | None = None) -> None:
        self.validator = validator or PoCValidator()

    def aggregate_and_validate(
        self,
        raw_candidates: list[RawCandidate],
        cve_id: str,
        min_confidence: float = 0.0,
        max_results: int = 20,
    ) -> list[PoCResultSchema]:
        """
        Merge duplicate URLs across platforms, apply cross-source corroboration,
        validate each candidate, and sort by confidence score.
        """
        if not raw_candidates:
            return []

        # Map canonical URL -> list of candidate records
        grouped: dict[str, list[RawCandidate]] = {}
        for cand in raw_candidates:
            clean_url = canonicalize_url(cand.url)
            if not clean_url:
                continue
            grouped.setdefault(clean_url, []).append(cand)

        validated_results: list[PoCResultSchema] = []

        for clean_url, cand_list in grouped.items():
            # Pick the best primary candidate representation (prefer github with stars, or first)
            primary_cand = next(
                (c for c in cand_list if c.source == "github" and (c.stars or 0) > 0),
                cand_list[0],
            )
            # Distinct sources that mentioned this exact canonical URL
            distinct_sources = {c.source for c in cand_list}
            cross_count = len(distinct_sources)

            validated = self.validator.validate_candidate(
                candidate=primary_cand,
                cve_id=cve_id,
                cross_source_count=cross_count,
            )

            # Enforce canonical URL on output
            validated.url = clean_url

            if validated.confidence_score >= min_confidence:
                validated_results.append(validated)

        # Sort descending by confidence score, then stars if available
        validated_results.sort(
            key=lambda r: (r.confidence_score, r.stars or 0),
            reverse=True,
        )

        return validated_results[:max_results]
