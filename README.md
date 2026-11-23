# 🛡️ UNICC × IITGN AI & Cybersecurity Capstone Platform

<p align="center">
  <img src="https://img.shields.io/badge/Collaboration-UNICC%20%C3%97%20IIT%20Gandhinagar-007ACC?style=for-the-badge&logo=institution&logoColor=white" alt="UNICC IITGN Collaboration" />
  <img src="https://img.shields.io/badge/Platform-Integrated%20Cyber%20AI%20Intelligence-blueviolet?style=for-the-badge" alt="Integrated Cyber AI Intelligence" />
  <img src="https://img.shields.io/badge/Status-Fully%20Integrated-success?style=for-the-badge" alt="Status: Fully Integrated" />
</p>

<p align="center">
  <a href="#executive-summary">Overview</a> •
  <a href="#system-architecture">Architecture</a> •
  <a href="#key-capabilities">Capabilities</a> •
  <a href="#repository-structure">Repository Structure</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#api-specification">API Contracts</a> •
  <a href="#evaluation--benchmarks">Evaluation</a> •
  <a href="#team--collaboration">Team</a>
</p>

---

## 📖 Executive Summary

Modern Security Operations Centers (SOCs) face an overwhelming influx of disparate Cyber Threat Intelligence (CTI) reports, unstructured malware disclosures, and fast-evolving indicators of compromise (IOCs). Generic conversational AI systems struggle in high-assurance cybersecurity domains due to hallucinations, lack of verifiable source attribution, and poor exact-match precision for technical observables (e.g., CVE codes, file hashes, registry keys).

The **UNICC × IITGN AI & Cybersecurity Platform** delivers an institutional-grade, latency-optimized, and end-to-end intelligence ecosystem. The system bridges raw multi-source ingestion, hybrid vector retrieval, knowledge graph traversal, generative LLM reasoning with mathematical zero-hallucination verification, and investigator triage workflows:

1. **Knowledge Foundation & Ingestion**: Multi-source CVE intake (NVD, CISA KEV, EPSS), schema normalization, and live threat feed synchronization.
2. **Threat Retrieval & Matching Subsystem**: Deterministic IOC exact matching (< 1ms), dense-sparse hybrid search (BGE-M3 + Okapi BM25) with Reciprocal Rank Fusion ($k=60$), cross-encoder reranking, and STIX 2.1 ATT&CK knowledge graph expansion.
3. **LLM Intelligence & Evaluation Layer**: Evidence-grounded threat investigation, structured cyber entity extraction (CVEs, IOCs, malware families, threat actors), executive summarization, and patch intelligence with strict document citation binding.
4. **Analyst Dashboard, Security & Network Sensor**: Web-based SOC investigator workspace, enterprise RBAC (Investigator, Auditor, Admin), audit trail logging, and network flow intrusion detection.

---

## 🏗️ 4-Layer System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                            LAYER 1: DATA & KNOWLEDGE FOUNDATION                             │
│  • Multi-Source Ingestion: NVD, CISA KEV, EPSS Feeds, ThreatFox, OSINT Advisories         │
│  • Pydantic v2 Contract Enforcement, Schema Normalization & MinHash Deduplication           │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                        LAYER 2: THREAT RETRIEVAL & HYBRID MATCHING                          │
│                                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ FAST-PATH: Deterministic IOC Exact Lookup (< 1ms)                                     │  │
│  │ Sub-millisecond exact match on CVE IDs, SHA256 Hashes, IPs, and Domains via Qdrant     │  │
│  └───────────────────────────────────────┬───────────────────────────────────────────────┘  │
│                                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ HYBRID SEARCH & RANK FUSION (~145ms)                                                  │  │
│  │ • Dense Vector Search (BGE-M3 1024-dim, HNSW) + Lexical Search (Okapi BM25)          │  │
│  │ • Reciprocal Rank Fusion (RRF, k=60) with Dynamic α Domain Routing                    │  │
│  │ • Cross-Encoder Reranking (BAAI/bge-reranker-v2-m3) Top-50 → Top-5                    │  │
│  └───────────────────────────────────────┬───────────────────────────────────────────────┘  │
│                                          ▼                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ STIX 2.1 GRAPH EXPANSION & CITATION SCORING (~50ms)                                   │  │
│  │ • Traverses MITRE ATT&CK relations (Actor → Uses → Malware / TTP / Technique)         │  │
│  │ • Deterministic 5-Tier Classification: EXACT | STRONG | PARTIAL | WEAK | UNSUPPORTED  │  │
│  │ • Chunk-Level Source Attribution, Cryptographic Provenance & Evidence Citations       │  │
│  └───────────────────────────────────────┬───────────────────────────────────────────────┘  │
└──────────────────────────────────────────┼──────────────────────────────────────────────────┘
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                          LAYER 3: LLM INTELLIGENCE & EVALUATION                             │
│  • Unified AI Gateway: Local On-Premise (Ollama Llama-3 / Mistral) & Cloud APIs             │
│  • Autonomous Cyber Entity Extraction: CVEs, Network IOCs, Threat Actors, Malware Families │
│  • Evidence-Grounded Threat Investigation: Zero-hallucination citation enforcement (100%)    │
│  • Actionable Patch Intelligence: Patch status, fixed bulletins, and remediation workarounds│
│  • Quantitative Benchmark Suite: 5-pillar mathematical scoring engine (evaluate_llm.py)     │
└──────────────────────────────────────────┬──────────────────────────────────────────────────┘
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                    LAYER 4: ANALYST WORKSPACE, RBAC & NETWORK SENSOR                        │
│  • Security Analyst Workspace: Upload incident reports, review matches & sign off triage   │
│  • Enterprise RBAC Matrix: Fine-grained access control (Investigator, Auditor, Admin)       │
│  • Tamper-Evident Audit Logging: User correlation IDs, session tracking, and audit trails   │
│  • Network Security Sensor: Real-time traffic flow anomaly detection & signature alerts     │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Technology Stack (100% Free & Local Architecture)

| Component | Selected Technology | Role & Engineering Rationale |
| :--- | :--- | :--- |
| **Vector Database** | **Qdrant** (Docker) | Self-hosted, single-stage filtered HNSW, built-in dense + sparse vector indexing. |
| **Embedding Model** | **BAAI/bge-m3** | 1024-dim dense + sparse + ColBERT representations; 8,192 context window; free & local. |
| **Rank Fusion** | **Qdrant RRF Fusion** | Reciprocal Rank Fusion ($k=60$) combining dense semantic and lexical scores. |
| **Cross-Encoder Reranker** | **BAAI/bge-reranker-v2-m3** | Precision token-level cross-attention reranking (50 → 5 candidates). |
| **Knowledge Graph** | **Neo4j + python-stix2** | Stores MITRE ATT&CK STIX bundle for actor/campaign graph explainability. |
| **Exact IOC Lookup** | **Qdrant Payload Filters** | Sub-millisecond exact matching for CVEs, hashes, IPs without auxiliary overhead. |
| **LLM Reasoning Layer** | **Ollama (Llama-3/Mistral) & Cloud APIs** | Unified local/cloud AI gateway with Pydantic v2 structured JSON validation. |
| **Citation Framework** | **LlamaIndex `CitationQueryEngine`** | Automatic chunk-level source attribution, page offsets, and provenance. |
| **Corpus Deduplication** | **MinHash (`datasketch`)** | Jaccard similarity deduplication ($> 0.85$) preventing redundant index chunks. |
| **API & Security** | **FastAPI + JWT + RBAC** | Asynchronous OpenAPI-documented REST API with role-based access control. |
| **Evaluation Suite** | **Integrated Evaluation Suite** | Mathematical scoring across Macro F1, Groundedness, NDCG@10, and latency SLAs. |

---

## 📁 Repository Structure

```text
unicc-iitgn-capstone/
├── knowledge_foundation/              # Threat data intake, normalization, and live feeds
│   ├── feeds/                         # Live updaters and lookup scripts (NVD, CISA KEV, EPSS)
│   ├── normalized_cves/               # Verified unified JSON files
│   ├── quarantined/                   # Malformed / invalid incoming CVE records
│   └── NORMALIZED_CVE_DATA_GUIDE.md   # Schema and normalization specification
│
├── threat_retrieval_engine/           # Threat Retrieval & 5-Tier Matching Subsystem
│   ├── search_engine/                 # Ingestion pipeline, Qdrant vectors, BM25, rerankers
│   ├── api/                           # Serving interface (FastAPI REST service: /match, /lookup)
│   ├── poc_intelligence/              # Multi-source OSINT PoC & exploit discovery (GitHub, X, etc.)
│   ├── attack/                        # MITRE ATT&CK STIX 2.1 graph expansion models
│   └── benchmarks/                    # Retrieval latency and precision benchmarks
│
├── llm/                               # LLM Intelligence, Gateway & Evaluation Subsystem
│   ├── gateway/                       # Unified AI gateway (Local Ollama, Cloud Gemini/OpenAI)
│   ├── workflows/                     # Autonomous workflows (Investigator, Summarizer, Extractor)
│   ├── schemas/                       # Pydantic v2 response validation models & contracts
│   ├── prompts/                       # Domain-calibrated cybersecurity system prompt templates
│   └── evaluation/                    # Automated benchmark evaluation suite
│       ├── evaluate_llm.py            # Benchmark execution runner & scorecard generator
│       ├── metrics.py                 # Mathematical scoring engine (Macro F1, Groundedness)
│       ├── benchmark_data.py          # Ground-truth CTI evaluation scenarios
│       ├── benchmark_results.json     # Calibrated benchmark scorecard output
│       └── README.md                  # LLM evaluation documentation
│
├── security_platform/                 # Team 4: the application people use
│   ├── backend/                       # Application backend APIs, authentication & RBAC
│   ├── frontend/                      # Security Analyst & Investigator Web Dashboard
│   ├── network_sensor/                # Network Intrusion Detection & Telemetry Subsystem
│   └── tests/                         # Network sensor test suite
│
├── benchmarks_v2/                     # Ground-truth retrieval and evaluation pipelines
├── results/                           # Evaluation metrics, latency profiles & baseline scorecards
├── config/                            # Runtime parameters (retrieval_config.yaml)
├── docs/                              # System documentation and API design specifications
├── verify/                            # Unit and integration test suite
├── pyproject.toml                     # Project metadata and dependencies
└── README.md                          # Institutional project documentation
```

---

## 🚀 Getting Started

### Run the whole system with Docker (recommended)

One command starts the web app (dashboard, login, audit log, AI gateway, network sensor) and the
Team 2 retrieval service, with an optional on-premise AI model (Ollama):

```bash
cp .env.example .env                 # set JWT_SECRET; see the guide for the rest
# put the retrieval data folder (about 8 GB, from the project team) at ./retrieval-data
docker compose up -d --build         # then open http://localhost:8080
```

The complete guide - requirements, the retrieval data, settings, first login, Gemini or Ollama,
checks, backups, security checklist and troubleshooting - is
**[docs/DOCKER_SETUP.md](docs/DOCKER_SETUP.md)**.

### Run from source (development)

### Prerequisites
* **Python:** Version 3.10 or higher
* **Compute:** Minimum 8 GB RAM (16 GB + NVIDIA CUDA-enabled GPU recommended for local inference)

### 1. Set Up Virtual Environment

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt  # Or pip install -e .
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env to adjust model paths, Qdrant host, and operational parameters
```

### 4. Running the Subsystems

#### Run the LLM Evaluation Benchmark Suite
```bash
python llm/evaluation/evaluate_llm.py
# Or with API backend:
python llm/evaluation/evaluate_llm.py --backend=api
```

#### Start the Retrieval Engine API
```bash
uvicorn threat_retrieval_engine.api.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🔌 API Specification & Contracts

The platform exposes asynchronous HTTP REST interfaces for microservice and analyst UI integration:

* `POST /api/v1/threats/match` — Executes 4-layer retrieval pipeline and returns 5-tier classification and citation evidence.
* `POST /api/v1/pocs/find` — Multi-source OSINT PoC & exploit discovery (GitHub, X, Mastodon, BlueSky) with $\ge 70\%$ precision scoring.
* `POST /api/v1/search/hybrid` — Standalone hybrid search (dense BGE-M3 + sparse BM25) with dynamic $\alpha$ routing.
* `POST /api/v1/entities/lookup` — Sub-millisecond deterministic exact lookup for CVEs, hashes, and IPs.
* `GET /api/v1/health` — Returns status of Qdrant, Neo4j, embedding models, and rerankers.

### Sample Request (`POST /api/v1/threats/match`):
```json
{
  "query": "Observed lateral movement using PsExec following exploitation of MS17-010 CVE-2017-0144 from 198.51.100.24 technique T1021.002",
  "top_k": 5,
  "alpha": 0.5,
  "include_pocs": false
}
```

---

## 📊 Evaluation & Benchmarks

The system is evaluated across quantitative information retrieval (IR) metrics and generative cognitive quality gates:

### Retrieval & Matching Benchmarks
| Metric | Target Baseline | Achieved Milestone | Status |
| :--- | :--- | :--- | :--- |
| **NDCG@10** | $\ge 0.85$ | $0.885$ | `PASS` |
| **Deterministic Exact Match Latency** | $\le 5\text{ ms}$ | $< 1\text{ ms}$ | `PASS` |
| **End-to-End Latency ($p95$)** | $\le 200\text{ ms}$ | $145\text{ ms}$ | `PASS` |
| **Citation Integrity** | $100\%$ Exact Ref | $100\%$ Ref Attribution | `PASS` |

### LLM Intelligence Quality Gates
| Dimension | Achieved Score | Quality Gate SLA | Verdict |
| :--- | :--- | :--- | :--- |
| **Entity Extraction Macro F1** | **82.3%** | $\ge 80\%$ | `PASS` |
| **Citation Groundedness (RAG)** | **100.0%** | $\ge 90\%$ | `PASS` |
| **Hallucination Rate** | **0.0%** | $\le 10\%$ | `PASS` |
| **Patch Intelligence Precision** | **82.0%** | $\ge 80\%$ | `PASS` |

---

## 👥 Team & Collaboration

Built in institutional collaboration between the **United Nations International Computing Centre (UNICC)** and **Indian Institute of Technology Gandhinagar (IITGN)** as a unified cybersecurity capstone team.

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE) — see the LICENSE file for details. Built for research and educational purposes in collaboration with UNICC and IIT Gandhinagar.
