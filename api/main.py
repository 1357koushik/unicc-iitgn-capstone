from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure root directory is on sys.path
_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.pipeline import get_orchestrator
from api.schemas import MatchRequest, MatchResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Exact, Vector, and Knowledge Graph engines
    orchestrator = get_orchestrator()
    orchestrator.initialize()
    yield
    # Shutdown


app = FastAPI(
    title="Threat Retrieval & Matching Subsystem",
    description="Unified API executing Exact Match, Vector Hybrid Search, and MITRE Knowledge Graph",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/match", response_model=MatchResponse, tags=["Threat Matching"])
@app.post("/api/v1/threats/match", response_model=MatchResponse, tags=["Threat Matching"])
@app.post("/query", response_model=MatchResponse, tags=["Threat Matching"])
@app.post("/", response_model=MatchResponse, tags=["Threat Matching"])
async def match_threat_query(request: MatchRequest) -> MatchResponse:
    """
    Single unified API endpoint to match threat queries across:
      1. Exact Match Engine (Qdrant payload filters & SQLite)
      2. Vector Hybrid Engine (BGE-M3 dense embeddings + BM25 RRF)
      3. Knowledge Graph Engine (MITRE ATT&CK STIX graph expansion)
    """
    orchestrator = get_orchestrator()
    return orchestrator.run_query(
        query=request.query,
        top_k=request.top_k,
        alpha=request.alpha,
    )
