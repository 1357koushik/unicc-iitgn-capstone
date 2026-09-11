# Verification Guide

This folder contains all tests to prove the pipeline works correctly, end-to-end.
No external data or internet connection is required — everything runs on small fake data built inside the tests.

---

## How to Run the Tests

### 1. Install dependencies first

```bash
pip install -e ".[dev]"
```

### 2. Run all tests at once

```bash
cd verify
pytest . -v
```

### 3. Run a single test file

```bash
pytest verify/test_validator.py -v
pytest verify/test_vectorizer.py -v
pytest verify/test_vector_database.py -v
pytest verify/test_duplicate_checker.py -v
pytest verify/test_main_pipeline.py -v
```

### 4. Run with coverage report (shows which lines of code are tested)

```bash
pytest verify/ -v --cov=src --cov-report=term-missing
```

---

## What Each Test File Checks

### `test_validator.py`
Verifies `src/validator.py` — the data cleaner and parser.

| Test | What it proves |
|------|---------------|
| `test_sanitize_text_fixes_mojibake` | Broken characters like `â€™` get fixed to `'` |
| `test_sanitize_text_collapses_whitespace` | Extra spaces and newlines become one space |
| `test_is_valid_text_too_short` | Text under 15 characters is rejected |
| `test_is_valid_text_too_long` | Text over 32,000 characters is rejected |
| `test_is_valid_text_ok` | Normal text passes the check |
| `test_threat_chunk_schema_valid` | A correct ThreatChunk is created without errors |
| `test_threat_chunk_schema_text_too_short` | Pydantic blocks a chunk with text < 15 chars |
| `test_build_context_includes_fields` | The enriched context string contains title, CVEs, text |
| `test_add_query_prefix` | The query prefix is correctly prepended at query time |
| `test_cvss_score_to_severity` | CVSS scores map to the right severity labels |
| `test_make_chunk_id_deterministic` | Same doc+text always gives same chunk_id |
| `test_kev_csv_parser` | A fake CISA KEV CSV produces valid ThreatChunks |
| `test_epss_csv_parser_skips_low_scores` | EPSS records below 0.5 are not emitted |
| `test_quarantine_on_bad_text` | A record with no text is written to quarantine, not crashed |
| `test_parse_normalized_record_complete` | Full extraction from Team 1's unified normalized JSON structure |
| `test_parse_normalized_directory` | Ingests a directory of Team 1 `*_normalized.json` files |
| `test_parse_normalized_jsonl` | Streams Team 1 normalized records from a JSONL file |

---

### `test_vectorizer.py`
Verifies `src/vectorizer.py` — the BGE-M3 embedding model.

> **Note:** These tests mock the actual model so they run fast (no GPU or download needed).

| Test | What it proves |
|------|---------------|
| `test_encode_returns_correct_count` | One VectorResult is returned per input |
| `test_dense_vector_is_1024_dims` | Dense vector has exactly 1024 dimensions |
| `test_dense_vector_is_l2_normalized` | The L2 norm of the dense vector equals 1.0 |
| `test_sparse_vector_has_int_keys` | SPLADE weights use integer token IDs as keys |
| `test_enriched_text_is_preserved` | The context string is stored in VectorResult |

---

### `test_vector_database.py`
Verifies `src/vector_database.py` — Qdrant and SQLite storage.

| Test | What it proves |
|------|---------------|
| `test_qdrant_collection_created` | The `threat_intelligence_kb` collection exists after setup |
| `test_sqlite_table_created` | The `corpus` table exists with the correct columns |
| `test_store_and_fetch_text` | A chunk stored in SQLite can be retrieved by chunk_id |
| `test_fetch_nonexistent_returns_none` | Querying a missing chunk_id returns None safely |
| `test_store_ignores_duplicates` | Upserting the same chunk twice does not duplicate rows in SQLite |
| `test_fetch_chunk_metadata` | Full metadata dict is returned correctly |

---

### `test_duplicate_checker.py`
Verifies `src/duplicate_checker.py` — the MinHash deduplication engine.

| Test | What it proves |
|------|---------------|
| `test_unique_document_passes` | A brand-new document is not flagged as duplicate |
| `test_exact_duplicate_caught` | The same text twice → second is blocked |
| `test_near_duplicate_caught` | Text changed by only a few words is still blocked |
| `test_different_documents_pass` | Two clearly different reports both pass through |
| `test_filter_returns_correct_count` | filter() keeps right number of unique chunks |
| `test_reset_clears_index` | After reset(), a previously seen document is accepted again |

---

### `test_main_pipeline.py`
End-to-end integration test. Runs the whole pipeline on tiny fake data files.

| Test | What it proves |
|------|---------------|
| `test_full_pipeline_kev_only` | A fake KEV CSV file flows all the way to Qdrant + SQLite storage |
| `test_full_pipeline_epss_only` | A fake EPSS CSV file is filtered, vectorized, and stored |
| `test_pipeline_deduplication_works` | Identical rows in input result in only 1 stored chunk |
| `test_pipeline_quarantine_created` | A bad record produces a quarantine file, not a crash |

---

## Interpreting Results

```
PASSED   = test passed, code works correctly
FAILED   = test failed, something is broken
ERROR    = the test itself crashed (usually a missing import or file)
```

If all tests show `PASSED`, the entire pipeline is verified and safe to run on real data.
