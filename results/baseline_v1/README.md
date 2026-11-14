# v1 baseline (tag `v1-baseline`, commit 7db46c7)

Reproducible record of the current v1 retrieval engine on the IITGN server (CPU only, 362,301 rows).
Produced by `scripts/baseline_v1/run_baseline.sh`; checked by `scripts/baseline_v1/check_reproducible.py` (PASS).

## Retrieval quality (hybrid search, 29 known-answer queries)

| Category | n | hit@1 r1 | hit@1 r2 | hit@5 r1 | hit@5 r2 | hit@10 r1 | hit@10 r2 | MRR r1 | MRR r2 |
|---|---|---|---|---|---|---|---|---|---|
| all | 29 | 11 | 11 | 19 | 19 | 19 | 19 | 0.474 | 0.474 |
| nickname | 14 | 3 | 3 | 5 | 5 | 5 | 5 | 0.268 | 0.268 |
| description | 7 | 4 | 4 | 7 | 7 | 7 | 7 | 0.679 | 0.679 |
| typo | 3 | 1 | 1 | 2 | 2 | 2 | 2 | 0.417 | 0.417 |
| vendor | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 1.000 | 1.000 |
| exact-id | 2 | 0 | 0 | 2 | 2 | 2 | 2 | 0.500 | 0.500 |

## Latency and errors

| Metric | run1 | run2 |
|---|---|---|
| /threats/match p50 (s, 30 calls) | 13.37 | 12.84 |
| /threats/match max (s) | 15.03 | 15.02 |
| HTTP 504 in stage_timings (of 30) | 9 | 6 |
| non-200 in stage_timings | 9 | 6 |
| hybrid search p50 (s, 29 calls) | 3.34 | 3.63 |
| hybrid search max (s) | 5.06 | 6.62 |
| HTTP 504 in hybrid search | 0 | 0 |
| HTTP 504 in quality_tests match/off-topic calls | 5 | 3 |

Example `pipeline_profile` (run1, first call): `{"exact_match_ms": 0.1, "vector_database_ms": 11930.8, "knowledge_graph_ms": 0.1, "scoring_ms": 4.6, "citation_ms": 0.5, "poc_discovery_ms": 0.0, "total_ms": 11937.7}`

## Notes

- Server copy of `threat_retrieval_engine/` and `config/` is identical to 7db46c7 apart from line endings (server LF, repo CRLF).
- Run order: run1 then run2, each with a freshly started server (run_baseline.sh). Load averages in `manifest.json`.
- A first attempt of the pair was discarded: a bug in run_baseline.sh left run1's uvicorn alive, so run2 reused it (port in use). Fixed and re-run.
- Full per-query data: `quality_run*.json`; per-stage data: `stage_timings_run*.json`.
