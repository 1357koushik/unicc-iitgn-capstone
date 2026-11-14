from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threat_retrieval_engine.api.schemas import (
    PoCFindRequest,
    PoCFindResponse,
    PoCResultSchema,
    SourceStatusSchema,
)
from threat_retrieval_engine.poc_intelligence.poc_cache import PoCCache
from threat_retrieval_engine.poc_intelligence.poc_validator import PoCValidator
from threat_retrieval_engine.poc_intelligence.result_aggregator import ResultAggregator
from threat_retrieval_engine.poc_intelligence.sources.base import (
    BasePoCSource,
    RawCandidate,
    SearchConfig,
    SourceSearchResponse,
)
from threat_retrieval_engine.poc_intelligence.sources.bluesky_scraper import BlueSkyPoCSource
from threat_retrieval_engine.poc_intelligence.sources.github_scraper import GitHubPoCSource
from threat_retrieval_engine.poc_intelligence.sources.mastodon_scraper import MastodonPoCSource
from threat_retrieval_engine.poc_intelligence.sources.x_scraper import XPoCSource
from threat_retrieval_engine.config import get_config

logger = logging.getLogger(__name__)

_CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PoCFinderEngine:
    """
    Unified Orchestrator for PoC / Exploit Discovery across OSINT sources.
    Executes concurrent scraping across GitHub, X, Mastodon, and BlueSky,
    tracks per-source status and evidence, and manages caching.
    """

    def __init__(
        self,
        cache: PoCCache | None = None,
        validator: PoCValidator | None = None,
        aggregator: ResultAggregator | None = None,
        sources: dict[str, BasePoCSource] | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.validator = validator or PoCValidator()
        self.aggregator = aggregator or ResultAggregator(validator=self.validator)
        self.cache = cache or PoCCache()
        if timeout_seconds is None:
            try:
                cfg = get_config()
                timeout_seconds = getattr(cfg, "d_poc_seconds", 10.0)
            except Exception:
                timeout_seconds = 10.0
        self.timeout_seconds = float(timeout_seconds)
        self.sources: dict[str, BasePoCSource] = sources or {
            "github": GitHubPoCSource(timeout_seconds=timeout_seconds),
            "x": XPoCSource(timeout_seconds=timeout_seconds),
            "mastodon": MastodonPoCSource(timeout_seconds=timeout_seconds),
            "bluesky": BlueSkyPoCSource(timeout_seconds=timeout_seconds),
        }

    async def find_pocs(
        self,
        cve_id: str,
        max_results: int = 20,
        sources: list[str] | None = None,
        min_confidence: float = 0.0,
        bypass_cache: bool = False,
    ) -> PoCFindResponse:
        """
        Main async discovery method.
        """
        t_start = time.perf_counter()
        cve_clean = cve_id.strip().upper()

        if not _CVE_REGEX.match(cve_clean):
            raise ValueError(f"Invalid CVE identifier format: '{cve_id}'. Expected format 'CVE-YYYY-NNNN'.")

        # 1. Check cache (without mutating the cached payload)
        if not bypass_cache and self.cache:
            cached_resp = self.cache.get(
                cve_clean,
                sources=sources,
                max_results=max_results,
                min_confidence=min_confidence,
            )
            if cached_resp is not None:
                # Deep copy to prevent mutating the cached instance
                cached_copy = cached_resp.model_copy(deep=True)
                filtered_results = [
                    r for r in cached_copy.results if r.confidence_score >= min_confidence
                ][:max_results]
                cached_copy.results = filtered_results
                cached_copy.total_found = len(filtered_results)
                cached_copy.latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
                cached_copy.cached = True
                return cached_copy

        # 2. Determine target sources
        active_source_names = [s.lower() for s in (sources or list(self.sources.keys()))]
        active_sources: list[tuple[str, BasePoCSource]] = [
            (name, self.sources[name]) for name in active_source_names if name in self.sources
        ]

        # 3. Concurrently query all selected sources with bounded configuration
        async def _query_source(name: str, src: BasePoCSource) -> SourceSearchResponse:
            try:
                cfg = SearchConfig(result_limit=max_results, timeout_seconds=self.timeout_seconds)
                return await src.search_with_status(cve_clean, cfg)
            except Exception as exc:
                logger.warning("Scraper source '%s' encountered an error for %s: %s", name, cve_clean, exc)
                return SourceSearchResponse(
                    source=name,
                    status="error",
                    query=cve_clean,
                    errors=[f"{type(exc).__name__}: {str(exc)[:240]}"],
                )

        tasks = [_query_source(name, src) for name, src in active_sources]
        source_responses: list[SourceSearchResponse] = await asyncio.gather(*tasks, return_exceptions=False)

        raw_candidates: list[RawCandidate] = []
        source_statuses: list[SourceStatusSchema] = []
        coverage_limitations: list[str] = []

        for resp in source_responses:
            raw_candidates.extend(resp.candidates)
            source_statuses.append(
                SourceStatusSchema(
                    source=resp.source,
                    status=resp.status,
                    retrieved_at=resp.retrieved_at,
                    query=resp.query,
                    result_count=resp.result_count,
                    pages_fetched=resp.pages_fetched,
                    next_cursor=resp.next_cursor,
                    errors=resp.errors,
                    warnings=resp.warnings,
                    coverage_limitations=resp.coverage_limitations,
                )
            )
            for cov in resp.coverage_limitations:
                if cov not in coverage_limitations:
                    coverage_limitations.append(cov)

        # 4. Aggregate, deduplicate, validate, and score candidates
        validated_results = self.aggregator.aggregate_and_validate(
            raw_candidates=raw_candidates,
            cve_id=cve_clean,
            min_confidence=min_confidence,
            max_results=max_results,
        )

        # 5. Compute relevance yield (not ground-truth production precision)
        precision = self.validator.calculate_precision(validated_results)
        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

        response = PoCFindResponse(
            cve_id=cve_clean,
            total_found=len(validated_results),
            precision_score=precision,
            sources_queried=[name for name, _ in active_sources],
            results=validated_results,
            latency_ms=latency_ms,
            cached=False,
            source_statuses=source_statuses,
            retrieved_at=_utc_now(),
            coverage_limitations=coverage_limitations,
        )

        # 6. Save in cache (composite keying, R5)
        if self.cache:
            self.cache.set(
                cve_clean,
                response,
                sources=sources,
                max_results=max_results,
                min_confidence=min_confidence,
            )

        return response

    def find_pocs_sync(
        self,
        cve_id: str,
        max_results: int = 20,
        sources: list[str] | None = None,
        min_confidence: float = 0.0,
        bypass_cache: bool = False,
        timeout: float | None = None,
    ) -> PoCFindResponse:
        """Synchronous wrapper for thread/blocking contexts with unblocked timeout shutdown."""
        effective_timeout = timeout if timeout is not None else self.timeout_seconds
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                try:
                    future = pool.submit(
                        asyncio.run,
                        self.find_pocs(
                            cve_id=cve_id,
                            max_results=max_results,
                            sources=sources,
                            min_confidence=min_confidence,
                            bypass_cache=bypass_cache,
                        ),
                    )
                    return future.result(timeout=effective_timeout)
                except (concurrent.futures.TimeoutError, TimeoutError):
                    pool.shutdown(wait=False, cancel_futures=True)
                    logger.warning("find_pocs_sync timed out after %.2fs for %s", effective_timeout, cve_id)
                    raise TimeoutError(f"PoC search for {cve_id} timed out after {effective_timeout}s")
                finally:
                    pool.shutdown(wait=False, cancel_futures=True)
            else:
                return loop.run_until_complete(
                    asyncio.wait_for(
                        self.find_pocs(
                            cve_id=cve_id,
                            max_results=max_results,
                            sources=sources,
                            min_confidence=min_confidence,
                            bypass_cache=bypass_cache,
                        ),
                        timeout=effective_timeout,
                    )
                )
        except RuntimeError:
            return asyncio.run(
                asyncio.wait_for(
                    self.find_pocs(
                        cve_id=cve_id,
                        max_results=max_results,
                        sources=sources,
                        min_confidence=min_confidence,
                        bypass_cache=bypass_cache,
                    ),
                    timeout=effective_timeout,
                )
            )


# Global singleton instance
_poc_finder_instance = PoCFinderEngine()


def get_poc_finder() -> PoCFinderEngine:
    return _poc_finder_instance
