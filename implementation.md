# Implementation Plan:

## 1. Executive Summary & Role Scope

building the data intake foundation, embedding vectorization pipeline, in-process vector indexing, local relational storage, and pre-ingestion deduplication.
1. **Embedded Qdrant (`QdrantClient(path="...")`)**: Persistent local-disk vector database running in-process without any background daemon, container, or network port.
2. **Decoupled SQLite Database (`corpus_store.db`)**: High-performance local relational storage (WAL mode) for full prose text, raw JSON, and PDF citation provenance.
3. **BAAI `bge-m3`**: Unified embedding model extracting both 1024-dim dense vectors and SPLADE sparse lexical weights in a single pass.

---

## 2. Architecture & Data Flow (Pure Python)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        TEAM 1: DATA FOUNDATION                           │
│  Outputs unified normalized CVE JSON (via cve_normalized_lookup.py)       │
│  (Unifies NVD, CVE List V5, CISA KEV, EPSS; raw feeds as fallback)       │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                                    ▼ (Normalized JSON / JSONL streaming)
┌──────────────────────────────────────────────────────────────────────────┐
│ MORAM KOUSHIK                                                            │
│                                                                          │
│  [Epic K-1: Native Setup]   [Epic K-2: Ingestion & Validation]           │
│  - pyproject.toml           - Pydantic v2 ThreatChunk schema contract    │
│  - Config YAML matrices     - Normalized CVE parser & raw fallbacks      │
│  - Embedded Qdrant client   - Mojibake cleaner & quarantine logger       │
│    (QdrantClient(path=...)) - Strategy C rich context constructor        │
│                             - Token sequence gate (8,192 max tokens)     │
│                             - Dynamic GPU/CPU batch scheduler            │
│                                                                          │
│  [Epic K-3: Vector Indexing & Corpus Storage]                            │
│  - BGE-M3 Pipeline (Dense 1024d + SPLADE sparse weights)                 │
│  - L2 Unit Normalization (Cosine Similarity = Dot Product)               │
│  - In-Process Qdrant HNSW collection (m=32, ef_construct=200)            │
│  - Qdrant Scalar Quantization (Int8 -> 4x RAM reduction)                 │
│  - Single-stage payload filter indexes (source_org, severity, cves, etc) │
│  - Decoupled SQLite corpus store (WAL mode, < 1ms text hydration)        │
│  - MinHash LSH deduplication engine (configurable Jaccard threshold)     │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 ▼ (In-process Qdrant)                 ▼ (SQLite Store)
┌──────────────────────────────────────┐ ┌────────────────────────────────┐
│ SUHANI (Search & Relevance)          │ │ HARSHITH SAI (Backend & Eval)  │
│ - Lexical BM25 & Regex Tokenizer     │ │ - 5-Tier Threat Classifier     │
│ - Reciprocal Rank Fusion (k=60)      │ │ - LlamaIndex Citation Engine   │
│ - BGE Cross-Encoder Reranker         │ │ - FastAPI REST Microservice    │
│ - MITRE ATT&CK STIX integration      │ │ - 100-Case Golden Evaluation   │
└──────────────────────────────────────┘ └────────────────────────────────┘
```

---


#### Deliverable K-1.2: Embedded Local Qdrant Initialization (`qdrant_local.py`)
Run Qdrant entirely in-process using local disk persistence:
```python
from qdrant_client import QdrantClient

# Runs embedded locally on disk — ZERO Docker, ZERO external ports needed
client = QdrantClient(path="./data/qdrant_storage")
```
- Direct disk persistence managed by Qdrant's embedded storage engine.
- Exact same Python API (`client.search`, `client.upsert`, `client.create_collection`).
- Seamless future path: if a central server is needed later, only the connection string changes.

#### Deliverable K-1.3: Deterministic Dependency Blueprint (`pyproject.toml`)
Standard Python packages installable via `pip install -e .`:
```toml
[project]
name = "unicc-team2-retrieval"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "torch>=2.2.0",
    "FlagEmbedding>=1.2.10",
    "transformers>=4.40.0",
    "qdrant-client>=1.9.0",
    "pydantic>=2.7.0",
    "pydantic-settings>=2.2.0",
    "aiosqlite>=0.20.0",
    "datasketch>=1.6.4",
    "ftfy>=6.2.0",
    "pyyaml>=6.0.1",
    "numpy>=1.26.0",
]
```

#### Deliverable K-1.4: Config Matrices
- `config/model_config.yaml`: Model name (`BAAI/bge-m3`), dimension (`1024`), sequence ceiling (`8192`), query prefix (`"Represent this sentence for searching relevant passages: "`).
- `config/retrieval_config.yaml`: Local paths (`data/qdrant_storage`, `data/sqlite/corpus_store.db`), HNSW parameters (`M=32, ef_construct=200, ef_search=64`), Int8 scalar quantization, MinHash threshold.

---

### Epic K-2: Data Ingestion & Validation Pipeline (Sprints 1–2)

#### Deliverable K-2.1: Pydantic v2 Ingestion Contract (`chunk_schema.py`)
Locked contract between Team 1 and Team 2:
```python
from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

class IOCEntities(BaseModel):
    ipv4: List[str] = Field(default_factory=list)
    ipv6: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    sha256: List[str] = Field(default_factory=list)
    md5: List[str] = Field(default_factory=list)

class CyberEntities(BaseModel):
    cves: List[str] = Field(default_factory=list)
    iocs: IOCEntities = Field(default_factory=IOCEntities)
    mitre_ttps: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "UNKNOWN"

class ThreatChunk(BaseModel):
    chunk_id: str = Field(..., description="Unique deterministic chunk ID")
    doc_id: str = Field(..., description="Parent document identifier")
    doc_title: str = Field(..., description="Advisory or CTI report title")
    source_org: str = Field(..., description="NVD, CISA, ENISA, NIST, ShadowServer")
    published_date: datetime = Field(..., description="ISO-8601 published date")
    page_number: Optional[int] = None
    section_header: str = ""
    text: str = Field(..., min_length=15, description="Primary clean content")
    entities: CyberEntities = Field(default_factory=CyberEntities)
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    bbox: Optional[List[float]] = None
```

#### Deliverable K-2.2: Normalized Data Intake & Multi-Format Parser (`validator.py`)
- **Primary Intake**: Ingests Team 1's unified normalized CVE JSON records (`CVE-ID_normalized.json` or JSONL) produced by `cve_normalized_lookup.py`. Pulls pre-joined NVD, CVE List V5, CISA KEV, and EPSS attributes into `ThreatChunk`.
- **Fallback Intake**: Retains full capability to directly parse raw NVD yearly JSON, CVE V5 git tree, and CISA/EPSS CSVs.
- Logs runtime stats: records/files processed, valid chunks emitted, quarantined records.

#### Deliverable K-2.3: Chunk Sanitizer & Quarantine Logger (`validator.py`)
- Repairs Unicode mojibake (`â€™`, `\ufffd`, smart quotes) with `ftfy` or clean regex fallback.
- Enforces character boundaries (min 15 chars, max 32,000 chars).
- Automatically routes invalid or corrupt records to `data/quarantined/failed_<timestamp>.jsonl` with error reasons, preventing pipeline crashes.

#### Deliverable K-2.4: Strategy C Embedding Context Builder (`validator.py`)
Enriches chunk text with metadata anchors before vectorization:
```python
enriched_text = (
    f"Document: {chunk.doc_title} | "
    f"Section: {chunk.section_header} | "
    f"Content: {chunk.text} | "
    f"CVEs: {', '.join(chunk.entities.cves)} | "
    f"Malware: {', '.join(chunk.entities.malware_families)} | "
    f"TTPs: {', '.join(chunk.entities.mitre_ttps)}"
)
```

#### Deliverable K-2.5: Token Sequence Gate
Inspects token lengths with `AutoTokenizer.from_pretrained("BAAI/bge-m3")` to defend against silent truncation beyond the 8,192 token limit.

#### Deliverable K-2.6: Asymmetric Prefix Injector
- **Document chunks (index time)**: Embedded directly as Strategy C text without prefix.
- **Search queries (query time)**: Prepend `"Represent this sentence for searching relevant passages: " + query`.

#### Deliverable K-2.7: Hardware-Adaptive Dynamic Batching (`vectorizer.py`)
- Automatically detects CUDA availability (`torch.cuda.is_available()`).
- CUDA GPU: Batch size **64** with `fp16=True`.
- CPU-only: Batch size **16** with thread pinning.

---

### Epic K-3: Vector Indexing & Corpus Storage (Sprints 3–4)

#### Deliverable K-3.1: BGE-M3 Vector Pipeline (`vectorizer.py`)
Single-pass vectorization using `FlagEmbedding.BGEM3FlagModel`:
- Generates **1024-dim dense vectors**.
- Generates **SPLADE sparse lexical weights** (`{token_id: weight}`).
- Applies **L2 unit normalization** ($\|v\|_2 = 1.0$), guaranteeing that Dot Product equals Cosine Similarity.

#### Deliverable K-3.2: Embedded Qdrant Collection Tuning (`vector_database.py`)
Creates collection `threat_intelligence_kb`:
```python
from qdrant_client.models import *

client.create_collection(
    collection_name="threat_intelligence_kb",
    vectors_config={"dense": VectorParams(size=1024, distance=Distance.COSINE)},
    sparse_vectors_config={"sparse": SparseVectorParams()},
    hnsw_config=HnswConfigDiff(m=32, ef_construct=200),
    quantization_config=ScalarQuantizationConfig(
        type=ScalarType.INT8, quantile=0.99, always_ram=True
    ),
)
```

#### Deliverable K-3.3: Payload Filter Indexes
Configures single-stage payload indexes in Qdrant to eliminate post-filtering recall collapse:
- `source_org`: `PayloadSchemaType.KEYWORD`
- `severity`: `PayloadSchemaType.KEYWORD`
- `cves`: `PayloadSchemaType.KEYWORD`
- `mitre_ttps`: `PayloadSchemaType.KEYWORD`
- `threat_actors`: `PayloadSchemaType.KEYWORD`
- `published_date`: `PayloadSchemaType.DATETIME`

#### Deliverable K-3.4: Decoupled SQLite Corpus Persistence (`vector_database.py`)
Qdrant stores only vectors, chunk IDs, and filter tags. All full text, raw JSON, and PDF citation coordinates reside in a decoupled SQLite database (`data/sqlite/corpus_store.db`):
- Uses WAL mode (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`) for fast concurrent async access.
- Sub-millisecond text and provenance hydration by `chunk_id`.

#### Deliverable K-3.5: Duplicate Checker (`duplicate_checker.py`)
- Generates 3-gram character/word shingles for input text.
- Computes 128-permutation MinHash signatures via `datasketch`.
- Identifies and skips near-duplicate threat advisories using a 90% similarity threshold.


## 4. Pipeline File Structure

The system is organized into the following main files:
- **`validator.py`**: Cleans and validates the incoming raw data.
- **`duplicate_checker.py`**: Tool to check the duplicate reports present (uses 90% threshold).
- **`vectorizer.py`**: Uses BGE-M3 and all its related stuff to extract embeddings.
- **`vector_database.py`**: Handles the quantized Qdrant vector database related code and SQLite.
- **`main.py`**: This is the main pipeline flow. It connects every file, starting from `validator.py` to `vector_database.py`.


## 5. Verification & Testing Plan

### Automated Test Commands
- **Schema Validation**: `pytest tests/unit/test_chunk_schema.py`
- **Sanitizer & Quarantine**: `pytest tests/unit/test_sanitizer.py`
- **MinHash Deduplication**: `pytest tests/unit/test_minhash.py`
- **Context Builder & Prefixes**: `pytest tests/unit/test_context_builder.py`
- **BGE-M3 Pipeline**: `pytest tests/unit/test_bge_pipeline.py`
- **End-to-End Ingestion to Local Storage**: `pytest tests/integration/test_storage_pipeline.py`

### Static Code Quality Gates
- **Linting**: `ruff check src/ tests/` (Zero linting errors)
- **Typing**: `mypy --strict src/team2/` (Strict static type safety)
