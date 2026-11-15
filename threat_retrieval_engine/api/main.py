from __future__ import annotations

import asyncio
import contextvars
import hmac
import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


def get_current_request_id() -> str:
    """Return the active request ID from contextvars (R-6.1)."""
    return request_id_ctx.get()

from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from threat_retrieval_engine.config import get_config
from threat_retrieval_engine.api.pipeline import get_orchestrator
from threat_retrieval_engine.api.schemas import (
    MatchRequest,
    MatchResponse,
    PoCFindRequest,
    PoCFindResponse,
)
from threat_retrieval_engine.poc_intelligence import get_poc_finder
from threat_retrieval_engine.runtime import apply_torch_threads, effective_threads


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Check configuration guard and initialize engines
    current_cfg = get_config()
    if current_cfg.service_auth_enabled and not current_cfg.api_key:
        logger.error(
            "CRITICAL CONFIGURATION ERROR: SERVICE_AUTH_ENABLED is True but RETRIEVAL_API_KEY is empty! "
            "All incoming requests requiring authentication will fail with 401."
        )
    threads = apply_torch_threads()
    logger.info("CPU threads: TRE_NUM_THREADS=%d, effective=%s", threads, effective_threads())
    logger.info("Config file: %s; data dir: %s", current_cfg.config_path, current_cfg.data_dir)
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
logger = logging.getLogger("threat_retrieval_engine.api")

# CORS middleware with explicit allowlist (R36)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Structured request execution tracing middleware with request ID and exception logging (R-6.1, R-6.2, R-6.3)."""
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    token = request_id_ctx.set(req_id)
    start_time = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = req_id

        # Deprecation and successor headers for legacy non-/api/v1 endpoints (R-6.3 / #28)
        path = request.url.path
        if not path.startswith("/api/v1") and path not in ("/docs", "/openapi.json", "/redoc"):
            response.headers["Deprecation"] = "true"
            successor = f"/api/v1{path}" if path.startswith("/") else f"/api/v1/{path}"
            if path in ("/match", "/query", "/"):
                successor = "/api/v1/threats/match"
            elif path in ("/pocs/find",):
                successor = "/api/v1/pocs/find"
            elif path in ("/health",):
                successor = "/api/v1/health"
            elif path in ("/ready",):
                successor = "/api/v1/ready"
            response.headers["Link"] = f'<{successor}>; rel="successor-version"'

        return response
    except Exception as exc:
        logger.exception("HTTP %s %s [req_id=%s] unhandled exception: %s", request.method, request.url.path, req_id, exc)
        raise
    finally:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            "HTTP %s %s -> %d in %.2fms [req_id=%s]",
            request.method,
            request.url.path,
            status_code,
            duration_ms,
            req_id,
        )
        request_id_ctx.reset(token)


async def verify_service_auth(request: Request):
    """Optional service-to-service auth check for production deployments (R36)."""
    current_cfg = get_config()
    if not current_cfg.service_auth_enabled:
        return
    token = request.headers.get(current_cfg.api_key_header)
    expected_key = (current_cfg.api_key or "").encode("utf-8")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service authentication token",
        )
    token_bytes = token.encode("utf-8", errors="replace")
    if not hmac.compare_digest(token_bytes, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service authentication token",
        )


@app.get("/health", tags=["System"], deprecated=True)
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
            # C9 ATT&CK build: "available" | "unavailable" | "uninitialized"; details below
            "knowledge_graph": orchestrator.attack_graph_status.get("status", "unavailable"),
        },
        "builds": {"attack": orchestrator.attack_graph_status},
        "degraded_components": orchestrator.degraded_components,
    }
    return status_map


@app.get("/ready", tags=["System"], deprecated=True)
@app.get("/api/v1/ready", tags=["System"])
async def readiness_check() -> dict[str, str]:
    """Service readiness probe for orchestrator containers (R14)."""
    orchestrator = get_orchestrator()
    if orchestrator.sqlite is not None:
        return {"status": "ready"}
    raise HTTPException(status_code=503, detail="Service not yet ready")


@app.post("/api/v1/threats/match", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)])
@app.post("/match", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)], deprecated=True)
@app.post("/query", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)], deprecated=True)
@app.post("/", response_model=MatchResponse, tags=["Threat Matching"], dependencies=[Depends(verify_service_auth)], deprecated=True)
async def match_threat_query(request: MatchRequest) -> MatchResponse:
    """
    Single unified API endpoint to match threat queries across:
      1. Exact Match Engine (Qdrant payload filters & SQLite)
      2. Vector Hybrid Engine (BGE-M3 dense embeddings + BM25 RRF)
      3. Knowledge Graph Engine (MITRE ATT&CK STIX graph expansion)
    Offloaded to worker threadpool with hard deadline enforcement (R-2.4).
    """
    orchestrator = get_orchestrator()
    current_cfg = get_config()
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                orchestrator.run_query,
                query=request.query,
                top_k=request.top_k,
                alpha=request.alpha,
                allowed_sources=request.allowed_sources,
                include_pocs=request.include_pocs,
            ),
            timeout=current_cfg.d_match_seconds,
        )
    except (asyncio.TimeoutError, TimeoutError):
        logger.error("Request exceeded match deadline of %.2fs", current_cfg.d_match_seconds)
        raise HTTPException(
            status_code=504,
            detail=f"Threat match deadline exceeded ({current_cfg.d_match_seconds}s)",
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
    from threat_retrieval_engine.search_engine.exact_lookup import exact_lookup
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
@app.post("/pocs/find", response_model=PoCFindResponse, tags=["PoC & Exploit Intelligence"], dependencies=[Depends(verify_service_auth)], deprecated=True)
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
