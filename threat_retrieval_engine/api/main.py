from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

# Ensure root and internal directories are on sys.path
_API_DIR = Path(__file__).resolve().parent
_ENGINE_DIR = _API_DIR.parent
_ROOT_DIR = _ENGINE_DIR.parent
for p in [_ROOT_DIR, _ENGINE_DIR, _API_DIR, _ENGINE_DIR / "search_engine"]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

try:
    from threat_retrieval_engine.config import get_config
    from threat_retrieval_engine.api.pipeline import get_orchestrator
    from threat_retrieval_engine.api.schemas import (
        MatchRequest,
        MatchResponse,
        PoCFindRequest,
        PoCFindResponse,
    )
    from threat_retrieval_engine.poc_intelligence import get_poc_finder
except ImportError:
    from config import get_config
    from pipeline import get_orchestrator
    from schemas import (
        MatchRequest,
        MatchResponse,
        PoCFindRequest,
        PoCFindResponse,
    )
    from poc_intelligence import get_poc_finder


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Exact, Vector, and Knowledge Graph engines
    orchestrator = get_orchestrator()
    orchestrator.initialize()
    yield
    # Shutdown


app = FastAPI(
    title="Threat Retrieval & Matching Subsystem",
    description="Unified API executing Exact Match, Vector Hybrid Search, and MITRE Knowledge Graph with PoC & Exploit Intelligence",
    version="1.0.0",
    lifespan=lifespan,
)

cfg = get_config()

# CORS middleware with explicit allowlist (R36)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


async def verify_service_auth(request: Request):
    """Optional service-to-service auth check for production deployments (R36)."""
    current_cfg = get_config()
    if not current_cfg.service_auth_enabled:
        return
    token = request.headers.get(current_cfg.api_key_header)
    if not token or token != current_cfg.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service authentication token",
        )


@app.get("/health", tags=["System"])
@app.get("/api/v1/health", tags=["System"])
async def health_check() -> dict[str, Any]:
    """Component health and degradation reporting (R14)."""
    orchestrator = get_orchestrator()
    status_map = {
        "status": "healthy" if not orchestrator.degraded_components else "degraded",
        "components": {
            "qdrant": "available" if orchestrator.qdrant is not None else "unavailable",
            "sqlite": "available" if orchestrator.sqlite is not None else "unavailable",
            "bm25": "degraded" if "bm25" in orchestrator.degraded_components else "available",
            "embedder": "degraded" if "embedder" in orchestrator.degraded_components else "available",
            "reranker": "degraded" if orchestrator.reranker is None else "available",
            "confidence_model": "available" if orchestrator.confidence_model is not None else "degraded",
            "knowledge_graph": orchestrator.attack_graph_status,
        },
        "degraded_components": orchestrator.degraded_components,
    }
    return status_map


@app.get("/ready", tags=["System"])
@app.get("/api/v1/ready", tags=["System"])
async def readiness_check() -> dict[str, str]:
    """Service readiness probe for orchestrator containers (R14)."""
    orchestrator = get_orchestrator()
    if orchestrator.sqlite is not None:
        return {"status": "ready"}
    raise HTTPException(status_code=503, detail="Service not yet ready")


@app.post("/match", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)])
@app.post("/api/v1/threats/match", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)])
@app.post("/query", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)])
@app.post("/", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)])
async def match_threat_query(request: MatchRequest) -> MatchResponse:
    """
    Single unified API endpoint to match threat queries across:
      1. Exact Match Engine (Qdrant payload filters & SQLite)
      2. Vector Hybrid Engine (BGE-M3 dense embeddings + BM25 RRF)
      3. Knowledge Graph Engine (MITRE ATT&CK STIX graph expansion)
    Offloaded to worker threadpool to prevent event-loop stalls (R4).
    """
    orchestrator = get_orchestrator()
    return await asyncio.to_thread(
        orchestrator.run_query,
        query=request.query,
        top_k=request.top_k,
        alpha=request.alpha,
        allowed_sources=request.allowed_sources,
        include_pocs=request.include_pocs,
    )


@app.post("/api/v1/search/hybrid", tags=["Search Engines"], dependencies=[Depends(verify_service_auth)])
async def search_hybrid_endpoint(request: MatchRequest) -> dict[str, Any]:
    """Dedicated Hybrid Search endpoint (BM25 + BGE-M3 RRF) (R14)."""
    orchestrator = get_orchestrator()
    if not orchestrator.hybrid_searcher:
        raise HTTPException(status_code=503, detail="Hybrid search engine unavailable")
    hits = await asyncio.to_thread(
        orchestrator.hybrid_searcher.search,
        query=request.query,
        top_k=request.top_k,
        allowed_sources=request.allowed_sources,
        alpha=request.alpha,
    )
    return {
        "query": request.query,
        "results": [
            {
                "chunk_id": h.chunk_id,
                "rrf_score": h.rrf_score,
                "dense_rank": h.dense_rank,
                "lexical_rank": h.lexical_rank,
                "dense_score": h.dense_score,
            }
            for h in hits
        ],
    }


@app.get("/api/v1/entities/lookup", tags=["Search Engines"], dependencies=[Depends(verify_service_auth)])
@app.post("/api/v1/entities/lookup", tags=["Search Engines"], dependencies=[Depends(verify_service_auth)])
async def lookup_entities_endpoint(value: str | None = None, query: str | None = None) -> dict[str, Any]:
    """Exact identifier entity lookup endpoint (R14)."""
    orchestrator = get_orchestrator()
    from exact_lookup import exact_lookup
    target = value or query or ""
    if not target:
        raise HTTPException(status_code=400, detail="Missing entity query parameter")
    matches = await asyncio.to_thread(
        exact_lookup,
        qdrant=orchestrator.qdrant,
        sqlite=orchestrator.sqlite,
        query=target,
        limit=20,
    )
    return {
        "target": target,
        "matches": [
            {
                "chunk_id": m.chunk_id,
                "matched_field": m.matched_field,
                "matched_value": m.matched_value,
                "doc_id": m.metadata.get("doc_id", ""),
            }
            for m in matches
        ],
    }


@app.post("/api/v1/pocs/find", response_model=PoCFindResponse, tags=["PoC & Exploit Intelligence"], dependencies=[Depends(verify_service_auth)])
@app.post("/pocs/find", response_model=PoCFindResponse, tags=["PoC & Exploit Intelligence"], dependencies=[Depends(verify_service_auth)])
async def find_pocs_for_cve(request: PoCFindRequest) -> PoCFindResponse:
    """
    Task 4: Identify Available POCs or Exploits given a specific CVE.
    Conducts OSINT searches across GitHub, X, Mastodon, and BlueSky,
    deduplicates and validates links, and returns precision-scored findings.
    """
    finder = get_poc_finder()
    return await finder.find_pocs(
        cve_id=request.cve_id,
        max_results=request.max_results,
        sources=request.sources,
        min_confidence=request.min_confidence,
    )
