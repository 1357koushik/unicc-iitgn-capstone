# Deliverable Summary — Corrected Benchmark Architecture

**Owner:** Cherukuri Harshith Sai — Backend & Intelligence Engineer (Project_Course)
**Capstone:** IIT Gandhinagar AI Cybersecurity Capstone — Team 2

---

## 1. Architecture Correction Summary

Per project architecture requirements, the evaluation benchmark was refactored to use the **teammates' existing retrieval implementation** from `unicc-iitgn-capstone-main/` without any benchmark-specific retrieval:

- **Single Pipeline Flow**: The benchmark feeds temporary benchmark queries directly through the **teammates' existing retrieval** and the **existing Team 2 pipeline**:
  ```
  TEMPORARY BENCHMARK QUERY (data/benchmark_dataset.json)
          ↓
  TEAMMATES' EXISTING RETRIEVAL (unicc-iitgn-capstone-main/)
    - hybrid_search.py (HybridSearcher)
    - bm25_index.py (BM25Index)
          ↓
  ACTUAL RETRIEVED HISTORICAL THREATS (corpus_store.db)
          ↓
  run_threat_match_pipeline() (src/services/pipeline.py)
          ↓
  retrieve_and_merge() (src/services/retrieval_orchestration.py)
          ↓
  existing scoring / classification / attribution / citation
          ↓
  BENCHMARK METRICS (Hit@3, MRR@10, NDCG@10, Macro F1, P95 latency)
  ```
- **Eliminated Benchmark Retrieval**: Removed `BenchmarkRetrievalBackend`, `_text_similarity()`, custom Jaccard ranking, duplicate BM25, and artificial score boosting.
- **Teammate Retrieval Interfaces Used**:
  - `bm25_index.py` (`BM25Index.search` via `build_from_sqlite`): Actively executes the teammates' Okapi BM25 engine against the 15 CVE records in `unicc-iitgn-capstone-main/data/sqlite/corpus_store.db`.
  - `hybrid_search.py` (`HybridSearcher.search`): Integrates dense vector + BM25 + RRF fusion; cleanly reports missing environment dependencies (`ftfy`, `torch`, `FlagEmbedding`) when running without GPU/model packages.
- **Replaceability Guarantee**: When other teams deliver real upstream search/ingestion systems, temporary benchmark data can be replaced by actual data without altering any code in the Team 2 pipeline.

---

## 2. Benchmark Evaluation Results (Teammates' Okapi BM25 Retrieval Engine)

### Dataset: `data/benchmark_dataset.json` (10 queries against teammate SQLite corpus)
```
Retrieval Engine : Teammates' Okapi BM25Index (unicc-iitgn-capstone-main/bm25_index.py)
Data Flow        : Benchmark Query
                   → Teammates' Existing Retrieval (unicc-iitgn-capstone-main)
                   → Existing Threat Matching (src/services/pipeline.py)
                   → Existing Scoring / Classification / Citations
                   → Benchmark Evaluation Metrics

RETRIEVAL EVALUATION (Teammates' Retrieval Engine)
  Hit@3:    1.0000
  MRR@10:   0.9375
  NDCG@10:  0.9539

CLASSIFICATION EVALUATION (Existing Team 2 Pipeline)
Macro F1: 0.1200

P95 Latency: 0.75 ms (SLA Target: <= 200.0 ms — PASS)
```


---

## 3. Test Suite Verification

- **Command**: `PYTHONPATH=unicc-iitgn-capstone-main:Project_Course:Project_Course/.venv/lib/python3.13/site-packages pytest Project_Course/tests/ -v`
- **Result**: **80 passed, 1 skipped, 0 failed** in 0.44s.

---

## 4. Teammate Boundary Integrity

- **Directory Boundary**: `unicc-iitgn-capstone-main/` remained **STRICTLY READ-ONLY**.
- **Modifications**: Exactly 0 files created, modified, or deleted in teammate codebase.


