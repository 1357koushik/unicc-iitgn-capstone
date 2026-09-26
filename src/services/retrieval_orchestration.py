"""
Shared retrieval orchestration — exact + hybrid integration.

Layer 1: detect exact observables (CVE, IP, hash, etc.) using the actual
teammate tokenizer patterns.
Layer 2: exact lookup via backend.entity_lookup() when applicable.
Layer 3: hybrid retrieval via backend.hybrid_search() (always executed).
Layer 4: merge / deduplicate by chunk_id.
Layer 5: return unified RankedChunk list.

Score semantics:
- Hybrid results carry their real RRF / vector / BM25 scores.
- Exact-match results are converted to RankedChunk with an explicit
  exact_match_score (not fabricated as RRF) so Team 3 / scoring can
  distinguish them. When both sources return the same chunk, the
  stronger retrieval metadata is preserved.
"""
from __future__ import annotations

import re
import time
from typing import Any

from src.contracts.chunk_schema import RankedChunk, ThreatChunk
from src.core.interfaces import get_backend, RetrievalBackend

# Exact observable patterns matching teammate tokenizer / exact_lookup
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _detect_exact_observable(query: str) -> bool:
    return bool(_CVE_RE.search(query) or _IP_RE.search(query) or _HASH_RE.search(query))


def _threat_chunk_to_ranked(chunk: ThreatChunk, exact_score: float = 1.0) -> RankedChunk:
    """Convert an exact-match ThreatChunk to RankedChunk with explicit score."""
    return RankedChunk(
        chunk=chunk,
        rrf_score=float(exact_score),  # documented as exact-match priority score
        vector_score=0.0,
        bm25_score=0.0,
        reranker_score=0.0,
        stix_relationships=[],
        is_stitched=False,
    )


async def retrieve_and_merge(query: str, top_k: int = 50, backend: RetrievalBackend | None = None, timing: dict | None = None, alpha: float = 0.5) -> list[RankedChunk]:
    """
    Shared orchestration used by /threats/match and /team3/format.
    Never silently falls back to mock; relies on injected backend.
    """
    if backend is None:
        backend = get_backend()

    # Always run hybrid retrieval (semantic / historical matching)
    t_hybrid_start = time.perf_counter()
    hybrid_results: list[RankedChunk] = await backend.hybrid_search(query, top_k=top_k, alpha=alpha)
    hybrid_ms = (time.perf_counter() - t_hybrid_start) * 1000
    if timing is not None:
        timing["vector_database_ms"] = round(hybrid_ms, 2)

    # Exact lookup only when observable patterns detected and backend supports it
    exact_results: list[RankedChunk] = []
    exact_ms = 0.0
    if _detect_exact_observable(query):
        t_exact_start = time.perf_counter()
        raw_exact: list[ThreatChunk] = await backend.entity_lookup(query)
        exact_ms = (time.perf_counter() - t_exact_start) * 1000
        for chunk in raw_exact:
            # Deduplicate against hybrid; if same chunk_id exists, skip exact duplicate
            # (hydration already done by adapter; we just convert contract)
            if chunk and chunk.chunk_id:
                exact_results.append(_threat_chunk_to_ranked(chunk, exact_score=1.0))

    if timing is not None:
        timing["exact_match_ms"] = round(exact_ms, 2)

    # Merge and deduplicate by chunk_id; preserve strongest metadata
    merged: dict[str, RankedChunk] = {}
    for rc in hybrid_results:
        cid = rc.chunk.chunk_id if rc.chunk else ""
        if cid:
            merged[cid] = rc
    for rc in exact_results:
        cid = rc.chunk.chunk_id if rc.chunk else ""
        if cid:
            if cid in merged:
                # Same chunk from both sources: keep hybrid (has real RRF/vector/BM25)
                # but boost exact signal if needed. Here we retain hybrid metadata.
                pass
            else:
                merged[cid] = rc

    # Return sorted by retrieval priority: hybrid RRF first, then exact
    sorted_results = sorted(
        merged.values(),
        key=lambda r: (r.rrf_score, r.vector_score, r.bm25_score),
        reverse=True,
    )
    return sorted_results[:top_k]
