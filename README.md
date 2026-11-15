# 🛡️ UNICC × IITGN AI & Cybersecurity Capstone — Team 2

<p align="center">
  <img src="https://img.shields.io/badge/Collaboration-UNICC%20%C3%97%20IIT%20Gandhinagar-007ACC?style=for-the-badge&logo=institution&logoColor=white" alt="UNICC IITGN Collaboration" />
  <img src="https://img.shields.io/badge/Team-2%20%7C%20Threat%20Retrieval%20%26%20Matching-blueviolet?style=for-the-badge" alt="Team 2" />
  <img src="https://img.shields.io/badge/Status-Active%20Development-success?style=for-the-badge" alt="Status: Active Development" />
</p>

<p align="center">
  <a href="#executive-summary">Overview</a> •
  <a href="#system-architecture">Architecture</a> •
  <a href="#key-capabilities">Capabilities</a> •
  <a href="#repository-structure">Repository Structure</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#api-specification">API Contracts</a> •
  <a href="#evaluation--benchmarks">Evaluation</a> •
  <a href="#project-roadmap--milestones">Milestones</a> •
  <a href="#team--governance">Team</a>
</p>

---


## 📖 Executive Summary

Modern Security Operations Centers (SOCs) face an overwhelming influx of disparate Cyber Threat Intelligence (CTI) reports, unstructured malware disclosures, and fast-evolving indicators of compromise (IOCs). Generic conversational AI systems struggle in high-assurance cybersecurity domains due to hallucinations, lack of verifiable source attribution, and poor exact-match precision for technical observables (e.g., CVE codes, file hashes, registry keys).

**Team 2** bridges raw intelligence ingestion and generative analysis by providing an institutional-grade, latency-optimized **Threat Retrieval & Matching Subsystem**. The system ingests normalized corpora from Team 1 (Data & Knowledge Foundation), organizes them into a dual-index architecture (BM25 sparse + BGE-M3 dense representation), conducts multi-stage rank fusion (Reciprocal Rank Fusion with adaptive $\alpha$-routing), and executes a deterministic **5-Tier Threat Matching Algorithm** before exposing validated context and cryptographic evidence citations to Team 3 (LLM Intelligence Gateway) and Team 4 (Investigator UI).

---

## 🏗️ 4-Layer System Architecture

```text
                                  [ TEAM 1: DATA FOUNDATION ]
                                               │
                                     Validated JSONL Intake
                                   (Pydantic v2 Enforcement)
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                            TEAM 2: THREAT RETRIEVAL & MATCHING                              │
│                                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ LAYER 1: Deterministic IOC Exact Lookup (< 1ms)                                       │  │
│  │ Qdrant Payload Filter: Sub-millisecond exact match on CVE IDs, Hashes, IPs, Domains    │  │
│  └───────────────────────────────────────┬───────────────────────────────────────────────┘  │
│                                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ LAYER 2: Hybrid Retrieval & Re-ranking (~145ms)                                       │  │
│  │ • Dense Vector Search (BGE-M3, 1024-dim, HNSW) + Lexical Search (BM25 / Sparse)        │  │
│  │ • Reciprocal Rank Fusion (RRF, k=60) with Dynamic α Domain Routing                    │  │
│  │ • Cross-Encoder Reranking (BAAI/bge-reranker-v2-m3) Top-50 → Top-5                    │  │
│  └───────────────────────────────────────┬───────────────────────────────────────────────┘  │
│                                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ LAYER 3: STIX Graph Expansion & Explainability (~50ms)                                │  │
│  │ Neo4j + python-stix2: Traverses MITRE ATT&CK relations (Actor → Uses → Malware / TTP) │  │
│  └───────────────────────────────────────┬───────────────────────────────────────────────┘  │
│                                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ LAYER 4: 5-Tier Threat Matching & Evidence Citation                                   │  │
│  │ • Composite Score: 0.40*IOC + 0.20*TTP + 0.20*Semantic + 0.20*CVE                     │  │
│  │ • Classification: EXACT | STRONG | PARTIAL | WEAK | UNSUPPORTED                       │  │
│  │ • LlamaIndex CitationQueryEngine (Doc ID, Chunk ID, Provenance Page, Confidence)      │  │
│  └───────────────────────────────────────┬───────────────────────────────────────────────┘  │
└──────────────────────────────────────────┼──────────────────────────────────────────────────┘
                                           │
                             FastAPI REST Endpoints (JSON)
                                           │
                     ┌─────────────────────┴─────────────────────┐
                     ▼                                           ▼
       [ TEAM 3: LLM REASONING ]                   [ TEAM 4: INVESTIGATOR UI ]
       (Summarization & Synthesis)                 (SOC Dashboard & Provenance)
```

---


## ⚡ Technology Stack (100% Free & Local)
| Component | Selected Technology | Role & Engineering Rationale |
| :--- | :--- | :--- |
| **Vector Database** | **Qdrant** (Docker) | Self-hosted, single-stage filtered HNSW, built-in dense + sparse vector indexing. |
| **Embedding Model** | **BAAI/bge-m3** | 1024-dim dense + sparse + ColBERT representations; 8,192 context window; free & local. |
| **Rank Fusion** | **Qdrant RRF Fusion** | Reciprocal Rank Fusion ($k=60$) combining dense semantic and lexical scores. |
| **Cross-Encoder Reranker** | **BAAI/bge-reranker-v2-m3** | Precision token-level cross-attention reranking (50 → 5 candidates). |
| **Knowledge Graph** | **Neo4j + python-stix2** | Stores MITRE ATT&CK STIX bundle for actor/campaign graph explainability. |
| **Exact IOC Lookup** | **Qdrant Payload Filters** | Sub-millisecond exact matching for CVEs, hashes, IPs without an auxiliary database. |
| **Citation Framework** | **LlamaIndex `CitationQueryEngine`** | Automatic chunk-level source attribution, page offsets, and provenance. |
| **Corpus Deduplication** | **MinHash (`datasketch`)** | Jaccard similarity deduplication ($> 0.85$) to prevent redundant index chunks. |
| **API Framework** | **FastAPI (Async)** | Asynchronous OpenAPI-documented REST API with Pydantic v2 data contracts. |
| **Evaluation Suite** | **RAGAS + DeepEval + CTIBench**| Quantitative evaluation across NDCG@10, MRR, citation integrity, and latency SLAs. |

---

## 📁 Repository Structure

```text
unicc-iitgn-capstone/
├── knowledge_foundation/              # [Team 1] Threat data intake, normalization, and live feeds
│   ├── feeds/                         # Live updaters and lookup scripts
│   │   ├── updater.ipynb              # NVD, CISA KEV, EPSS synchronization
│   │   ├── lookup.ipynb               # Interactive normalization and lookup
│   │   └── cve_normalized_lookup.py   # Multi-source joiner and normalizer CLI
│   ├── normalized_cves/               # Verified unified JSON files (sample CVEs)
│   ├── quarantined/                   # Malformed / invalid incoming CVE records
│   └── NORMALIZED_CVE_DATA_GUIDE.md   # Schema and normalization specification
│
├── threat_retrieval_engine/           # [Team 2] Threat Retrieval & Matching Subsystem
│   ├── search_engine/                 # Core RAG retrieval & indexing engine
│   │   ├── ingestion_pipeline.py      # Parse → Deduplicate → Vectorize → Store coordinator
│   │   ├── validator.py               # Intake validation & ThreatChunk creation
│   │   ├── tokenizer.py               # Cyber-aware regex tokenizer
│   │   ├── duplicate_checker.py       # MinHash deduplication engine
│   │   ├── vectorizer.py              # BGE-M3 dense/sparse embedding
│   │   ├── vector_database.py         # Qdrant client & SQLite full-text store
│   │   ├── bm25_index.py              # BM25 sparse keyword index
│   │   ├── exact_lookup.py            # Sub-millisecond deterministic IOC lookup
│   │   ├── hybrid_search.py           # Dense + BM25 RRF fusion with dynamic alpha
│   │   ├── reranker.py                # Cross-Encoder (bge-reranker-v2-m3)
│   │   └── (ATT&CK graph: see threat_retrieval_engine/attack/)
│   ├── api/                           # Serving interface (FastAPI REST service)
│   │   ├── main.py                    # App entry point, unified /match & /pocs/find routes
│   │   ├── pipeline.py                # End-to-end query router, matcher & PoC enricher
│   │   ├── schemas.py                 # Pydantic v2 request/response contracts
│   │   └── helpers.py                 # Indicator extraction and scoring helpers
│   ├── poc_intelligence/              # [Task 4] Multi-source OSINT PoC & Exploit Harvester
│   │   ├── sources/                   # Concurrent scrapers: GitHub, X, Mastodon, BlueSky
│   │   ├── poc_validator.py           # Precision scoring & anti-deception heuristic filters
│   │   ├── result_aggregator.py       # Cross-platform URL deduplication & corroboration
│   │   ├── poc_cache.py               # SQLite-backed KEV-aware TTL cache (1h KEV / 6h default)
│   │   └── poc_finder.py              # Unified async orchestrator (PoCFinderEngine)
│   └── benchmarks/                    # Dedicated benchmark suite
│       └── README.md                  # Latency, NDCG@10, and RAGAS benchmark setup
│
├── config/                            # Runtime parameters
│   └── retrieval_config.yaml          # Fusion weights, alpha thresholds, top-k limits
├── data/                              # Local database storage (gitignored)
│   ├── qdrant_storage/                # Embedded Qdrant vector index
│   └── sqlite/                        # Full-text SQLite corpus database
├── verify/                            # Complete unit and integration test suite
│   ├── test_api_single_endpoint.py
│   ├── test_bm25_index.py
│   ├── test_duplicate_checker.py
│   ├── test_exact_lookup.py
│   ├── test_hybrid_search.py
│   ├── test_ingestion_pipeline.py
│   ├── test_reranker.py
│   ├── test_tokenizer.py
│   ├── test_validator.py
│   ├── test_vector_database.py
│   └── test_vectorizer.py
├── pyproject.toml                     # Project metadata and dependencies
└── README.md                          # Institutional project documentation
```

---

## 🚀 Getting Started

### Prerequisites
* **Python:** Version 3.10 or higher
* **Container Runtime:** Docker & Docker Compose (for running Qdrant locally)
* **Compute:** Minimum 8 GB RAM (16 GB + NVIDIA CUDA-enabled GPU recommended for dense embedding inference)

### 1. Clone & Set Up Virtual Environment

*Coming soon*

### 2. Install Dependencies

*Coming soon*

### 3. Initialize Infrastructure

*Coming soon*

### 4. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env to adjust model paths, Qdrant host, and operational parameters
```

### 5. Start the Engine Service

*Coming soon*

## 🔌 API Specification & Contracts

Team 2 exposes standard HTTP REST interfaces for inter-team microservice integration:

* `POST /api/v1/threats/match` — Executes 4-layer pipeline and returns 5-tier classification and citation evidence.
* `POST /api/v1/pocs/find` — [Task 4] Multi-source OSINT PoC & exploit discovery (GitHub, X, Mastodon, BlueSky) with ≥70% precision scoring.
* `POST /api/v1/search/hybrid` — Standalone hybrid search (dense BGE-M3 + sparse BM25) with dynamic $\alpha$ routing.
* `POST /api/v1/entities/lookup` — Sub-millisecond deterministic exact lookup for CVEs, hashes, and IPs.
* `GET /api/v1/health` — Returns status of Qdrant, Neo4j, embedding models, and rerankers.

### Sample Request (`POST /api/v1/threats/match` or `POST /match`):
```json
{
  "query": "Observed lateral movement using PsExec following exploitation of MS17-010 CVE-2017-0144 from 198.51.100.24 technique T1021.002",
  "top_k": 5,
  "alpha": 0.5,
  "include_pocs": false
}
```

#### Response Schema:
```json
{
  "query_threat_id": "query_1727654321",
  "top_matches": [
    {
      "rank": 1,
      "chunk_id": "chunk_446e0fd5adfb",
      "composite_score": 0.9625,
      "confidence_tier": "EXACT",
      "evidence_record_class": "DESCRIPTION",
      "citations": [
        {
          "doc_id": "CVE-2017-0144_NVD",
          "doc_title": "NVD Vulnerability Details: CVE-2017-0144",
          "source_org": "NVD",
          "published_date": "2017-03-14T00:00:00Z",
          "provenance_status": "VERIFIED",
          "text_snippet": "Remote code execution in Microsoft Server Message Block 1.0 (SMBv1)..."
        }
      ]
    }
  ],
  "pipeline_profile": {
    "dense_search_ms": 1.2,
    "bm25_search_ms": 0.8,
    "rrf_ms": 0.4,
    "rerank_ms": 12.5,
    "confidence_ms": 0.3,
    "stix_ms": 1.1,
    "total_retrieval_ms": 16.3
  }
}
```
      "historical_doc_id": "CISA-AA23-145A",
      "historical_doc_title": "APT29 Phishing and Malware Campaign",
      "source_org": "CISA",
      "published_date": "2023-05-25",
      "composite_score": 0.88,
      "match_category": "STRONG_MATCH",
      "evidence_breakdown": {
        "ioc_similarity": 0.0,
        "ttp_similarity": 0.85,
        "semantic_similarity": 0.91,
        "cve_similarity": 1.0
      },
      "stix_relationships": [
        "[QUERY_CONTEXT] G0016 (APT29) -[uses]-> T1021.002 (Remote Services: SMB/Windows Admin Shares)"
      ],
      "supporting_evidence_chunks": [
        {
          "chunk_id": "chunk_7712",
          "page_number": 4,
          "text": "The threat actors utilized SMB remote code execution and administrative shares...",
          "relevance_score": 0.93,
          "source_url": "https://www.cisa.gov/..."
        }
      ]
    }
  ],
  "latency_breakdown_ms": {
    "layer1_exact_lookup": 0.8,
    "layer2_hybrid_rerank": 142.3,
    "layer3_stix_expansion": 48.1,
    "total": 191.2
  }
}
```

---

## 📊 Evaluation & Benchmarks

To ensure high-assurance retrieval in security-critical settings, Team 2's pipeline is evaluated across quantitative information retrieval (IR) metrics using historical benchmark datasets (CISA advisories, MITRE ATT&CK mappings, and synthetic SOC queries).

| Metric | Target Baseline | Current Milestone Result | Status |
| :--- | :--- | :--- | :--- |
| **NDCG@10** | $\ge 0.85$ | *Benchmarking in Progress* | 🟡 In Execution (Phase 2) |
| **MRR@10** | $\ge 0.80$ | *Benchmarking in Progress* | 🟡 In Execution (Phase 2) |
| **Precision@5 (Technical CVE/IOC)** | $\ge 0.95$ | *Pending Evaluation Run* | 🟡 In Execution (Phase 2) |
| **End-to-End Latency ($p95$)** | $\le 200\text{ ms}$ | *Under Optimization* | 🟡 In Execution (Phase 2) |
| **Hallucination Citation Integrity** | $100\%$ Exact Ref | *Pending Evaluation Run* | 🟡 In Execution (Phase 2) |

> *Detailed benchmark figures, ablation studies (Dense vs. Sparse vs. RRF), and test datasets will be updated upon completion of Phase 2 validation runs.*

---

## 📅 Project Roadmap & Milestones

* [x] **Phase 0: Architecture & Data Contract Specification**
  * Finalized 14-part engineering design questionnaire.
  * Formulated Pydantic v2 intake contracts with Team 1.
* [ ] **Phase 1: Hybrid Retrieval & Vector Index Pipeline** *(In Active Progress)*
  * Implement streaming JSONL batch ingestion.
  * Deploy local Qdrant collection with customized HNSW parameters.
  * Establish BGE-M3 embedding pipeline and BM25 sparse indexer.
* [ ] **Phase 2: Hybrid Fusion, Reranker & 5-Tier Matching Engine** *(Upcoming)*
  * Tune Reciprocal Rank Fusion (RRF) with dynamic $\alpha$ query classification.
  * Integrate Cross-Encoder reranking model.
  * Implement deterministic 5-Tier Threat Matching Algorithm.
* [ ] **Phase 3: Inter-Team Integration & API Hardening** *(Upcoming)*
  * Expose asynchronous REST endpoints to Team 3 and Team 4.
  * Implement end-to-end evidence citation mapping and origin validation.
* [ ] **Phase 4: Capstone Evaluation & Final Demonstration** *(Upcoming)*
  * Execute comprehensive performance benchmarking (NDCG@10, latency profiling).
  * System hardening, documentation freeze, and final project demonstration.

---

## 👥 Team & Governance

### Team 2: Threat Retrieval & Matching
* **Moram Koushik** — Student, IIT Gandhinagar (Roll: `24110210`)
* **Suhani** — Student, IIT Gandhinagar (Roll: `24110358`)
* **Cherukuri Harshith Sai** — Student, IIT Gandhinagar (Roll: `24110091`)

---

## 📜 Citation & Academic Use

If referencing or utilizing the architecture, schemas, or retrieval engines developed within this project, please cite this work as follows:

```bibtex
@misc{unicc_iitgn_team2_2026,
  author       = { Moram Koushik and Suhani and Cherukuri Harshith Sai },
  title        = {Hybrid Threat Retrieval and 5-Tier Matching Architecture for Cyber Threat Intelligence},
  howpublished = {UNICC - IIT Gandhinagar AI \& Cybersecurity Capstone Project},
  year         = {2026},
  month        = {August--November},
  note         = {Team 2: Threat Retrieval \& Matching Subsystem}
}
```

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE) — see the LICENSE file for details. Built for research and educational purposes in collaboration with UNICC and IIT Gandhinagar.