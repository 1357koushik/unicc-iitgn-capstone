# Integration Guide — Threat Retrieval & Matching Subsystem

## Overview

This document describes how to integrate with the Threat Matching backend. It covers the API contract, the retrieval interface protocol for teammate swap-in, environment configuration, and development workflows.

**Owner:** Cherukuri Harshith Sai — Backend & Intelligence Engineer

---

## API Endpoints

### `POST /api/v1/threats/match`
**Main endpoint.** Accepts a threat query and returns ranked matches with evidence citations.

**Request:**
```json
{
  "query": "Attacker exploited CVE-2024-1234 using T1059 from 10.0.0.1",
  "alpha": 0.5,
  "top_k": 5
}
```

**Response:**
```json
{
  "query_threat_id": "query_1726071234",
  "top_matches": [
    {
      "chunk_id": "chunk_abc",
      "composite_score": 0.87,
      "confidence_tier": "STRONG",
      "attribution": {
        "matching_iocs": ["10.0.0.1"],
        "matching_cves": ["CVE-2024-1234"],
        "shared_malware": [],
        "matching_mitre_techniques": ["T1059"]
      },
      "citations": [
        {
          "doc_id": "doc_abc",
          "doc_title": "APT29 Analysis",
          "source_org": "MITRE",
          "published_date": "2024-06-15T00:00:00Z",
          "page_number": 3,
          "section_header": "Indicators",
          "text_snippet": "APT29 exploited CVE-2024-1234 using T1059...",
          "matched_spans": [
            {"start": 20, "end": 33, "entity": "CVE-2024-1234", "entity_type": "cve"},
            {"start": 40, "end": 45, "entity": "T1059", "entity_type": "mitre"}
          ]
        }
      ]
    }
  ],
  "pipeline_profile": {
    "parse_ms": 0.05,
    "retrieval_ms": 0.12,
    "scoring_ms": 0.08,
    "citation_ms": 0.01,
    "sort_ms": 0.00,
    "total_ms": 0.30
  }
}
```

### `POST /api/v1/entities/lookup`
Thin wrapper for IOC exact-match lookup (delegates to Koushik/Suhani's backend).

### `POST /api/v1/search/hybrid`
Thin wrapper for hybrid search (delegates to Suhani's RRF pipeline).

### `GET /api/v1/health`
Health check endpoint.

---

## Retrieval Backend Protocol

The matching pipeline depends on an upstream retrieval layer. The interface is defined as a Python `Protocol` in `src/core/interfaces.py`:

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class RetrievalBackend(Protocol):
    async def hybrid_search(self, query: str, top_k: int = 50) -> list[RankedChunk]: ...
    async def entity_lookup(self, ioc: str, ioc_type: str | None = None) -> list[ThreatChunk]: ...
```

### How to Swap In a Live Backend

1. **Implement the protocol** in your module:
   ```python
   from src.core.interfaces import RetrievalBackend
   from src.contracts.chunk_schema import RankedChunk, ThreatChunk

   class QdrantRetrievalBackend:
       async def hybrid_search(self, query: str, top_k: int = 50) -> list[RankedChunk]:
           # Your real Qdrant + BM25 + RRF + reranking logic here
           ...

       async def entity_lookup(self, ioc: str, ioc_type: str | None = None) -> list[ThreatChunk]:
           # Your real IOC lookup here
           ...
   ```

2. **Register at startup** in `src/main.py` lifespan:
   ```python
   from src.core.interfaces import set_backend
   from your_module import QdrantRetrievalBackend

   @asynccontextmanager
   async def lifespan(app: FastAPI):
       if settings.RETRIEVAL_BACKEND == "live":
           set_backend(QdrantRetrievalBackend())
       yield
   ```

3. **Set the environment variable:**
   ```bash
   export RETRIEVAL_BACKEND=live
   ```

---

## Data Contracts

All Pydantic v2 models are in `src/contracts/chunk_schema.py`:

| Model | Purpose |
|---|---|
| `EntitySchema` | CVEs, IPs, hashes, malware, MITRE technique IDs |
| `ThreatChunk` | A chunk of threat intel with provenance metadata |
| `ScoredChunk` | ThreatChunk + vector/BM25/RRF scores (Koushik → Suhani) |
| `RankedChunk` | ScoredChunk + reranker score + STIX relationships (Suhani → Harshith) |
| `FeatureAttribution` | Which entities matched between query and chunk |
| `EvidenceCitation` | Structured citation with provenance and character offsets |
| `MatchResult` | Final scored match with attribution and citations |
| `PipelineProfile` | Per-stage latency breakdown |
| `ThreatMatchResponse` | Top-level API response |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RETRIEVAL_BACKEND` | `mock` | `mock` or `live` — controls whether the pipeline uses mock or real retrieval |
| `LOG_LEVEL` | `INFO` | Standard Python log level |
| `API_PREFIX` | `/api/v1` | URL prefix for all routes |
| `APP_VERSION` | `0.1.0` | Application version |
| `CORS_ORIGINS` | `["*"]` | Allowed CORS origins |

---

## Development Workflow

### Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Run Tests
```bash
pytest tests/ -v
```

### Lint & Typecheck
```bash
ruff check src/ tests/
mypy src/
```

### Run Evaluation
```bash
python scripts/evaluate.py
```

### Start Dev Server
```bash
uvicorn src.main:app --reload --port 8000
```

---

## Scoring & Classification

**Composite Score** = 0.35 × IOC + 0.25 × TTP + 0.25 × Semantic + 0.15 × CVE

**Confidence Tiers:**
| Tier | Score Range |
|---|---|
| EXACT | ≥ 0.95 |
| STRONG | 0.80 – 0.94 |
| PARTIAL | 0.55 – 0.79 |
| WEAK | 0.30 – 0.54 |
| UNSUPPORTED | < 0.30 |

## Evaluation & Benchmark Architecture

The benchmark framework (`scripts/evaluate.py`) evaluates the **teammates' existing retrieval implementation** and the **existing Team 2 matching pipeline** end-to-end without creating any benchmark-specific retrieval pathway:

```
TEMPORARY BENCHMARK DATA (data/benchmark_dataset.json)
        ↓
TEAMMATES' EXISTING RETRIEVAL (unicc-iitgn-capstone-main/)
  - Hybrid retrieval: unicc-iitgn-capstone-main/hybrid_search.py (HybridSearcher)
  - Keyword retrieval: unicc-iitgn-capstone-main/bm25_index.py (BM25Index)
        ↓
Actual retrieved historical threats (corpus_store.db via UpstreamRetrievalBackend)
        ↓
run_threat_match_pipeline() (existing src/services/pipeline.py)
        ↓
retrieve_and_merge() (existing src/services/retrieval_orchestration.py)
        ↓
existing scoring / classification / attribution / citation
        ↓
BENCHMARK METRICS (Hit@3, MRR@10, NDCG@10, Macro F1, P95 latency)
```

- **Teammates' Real Retrieval**: Retrieval is performed directly by the teammates' implementations in `unicc-iitgn-capstone-main/`. No benchmark-specific ranking, Jaccard similarity, or synthetic retrievers are used.
- **Teammate Retrieval Engines**:
  - `bm25` (Okapi BM25 Index): `unicc-iitgn-capstone-main/bm25_index.py` (`build_from_sqlite`), querying the 15 CVE records in `corpus_store.db`.
  - `hybrid` (Dense + BM25 + RRF): `unicc-iitgn-capstone-main/hybrid_search.py` (`HybridSearcher`), requires `ftfy`, `torch`, `FlagEmbedding`. When missing, the blocker is reported cleanly without fabricating results.
- **Single Pipeline**: Queries flow through `run_threat_match_pipeline()` using the active `UpstreamRetrievalBackend`.

**Execution Commands:**
```bash
# Auto mode: evaluates using teammates' available retrieval engine (BM25Index / HybridSearcher)
python3 scripts/evaluate.py

# Evaluate specifically against teammates' Okapi BM25 index
python3 scripts/evaluate.py --retrieval=bm25

# Evaluate against teammates' full hybrid searcher (reports blocker if neural deps missing)
python3 scripts/evaluate.py --retrieval=hybrid
```


