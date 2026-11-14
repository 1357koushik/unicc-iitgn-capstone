# Evaluation report: v1_hybrid on dev

**PROVISIONAL: 67 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-14T17:03:45Z |
| Harness | b4-1 commit `2d7e24cbaabcd6a32ad0c335923a6fca795d03cc` |
| Dataset | version b4-example-1 at `benchmarks_v2\eval\example\dataset` |
| Manifest sha256 | `20a44f7d81b40a3478095efc7233eb17cb0922203ee5d834cf7b6adb16c52115` (files verified) |
| Query file sha256 | `7eb5049ebc6708da85da7344b3579a2f933cc5f4ad15e3aec34f28754a91517d` |
| Qrels file sha256 | `34cd609986bf26905aae88fc2035c3a35201bc1dbcdae22242413de85c174542` |
| Run file | `results\eval\example\b4-example-v1_hybrid.jsonl` sha256 `2ecb29a299e8f79d84fe6c85d03aefdea41e38b006d7c3b7cb4f3b616d425cc8` |
| Variant config | `{"adapter": "http_v1", "base_url": "http://127.0.0.1:8765", "endpoint": "/api/v1/search/hybrid", "mapping": {"abstain_when_empty": false, "abstained": null, "doc_id": "chunk_id", "doc_id_resolver": {"kind": "sqlite", "path": "~/data/sqlite/corpus_store.db", "sql": "select doc_id from corpus where chunk_id = ?"}, "doc_id_transform": "cve_prefix", "probability": null, "results": "results", "score": "rrf_score", "tier": null}, "request": {"top_k": 10}, "timeout_s": 120.0}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [17.49, 7.68, 3.04] -> [9.49, 7.11, 3.1] |
| Service health | `{"components": {"bm25": "available", "confidence_model": "available", "embedder": "available", "knowledge_graph": "starter_stub", "qdrant": "available", "reranker": "available", "sqlite": "available"}, "degraded_components": [], "status": "healthy"}` |
| Split / slices | dev / all |
| Queries | 10 evaluated of 10 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['ndcg@10', 'success@1'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T0 | 1 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.167 [0.167, 0.167] | 0.294 [0.294, 0.294] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | – | 9/10 (0.900) |
| T1 | 2 | 0.500 [0.000, 1.000] | 1.000 [1.000, 1.000] | 0.750 [0.500, 1.000] | 0.815 [0.631, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | – | 17/19 (0.895) |
| T2 | 3 | 0.667 [0.000, 1.000] | 1.000 [1.000, 1.000] | 0.750 [0.250, 1.000] | 0.741 [0.431, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 23/28 (0.821) |
| T3 | 1 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.918 [0.918, 0.918] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | – | 8/10 (0.800) |
| T5 | 1 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | – | 10/10 (1.000) |
| T7 | 0 | – | – | – | – | – | – | – | – | 0/0 |
| **macro (slices)** | – | 0.433 [0.267, 0.600] | 0.600 [0.600, 0.600] | 0.533 [0.433, 0.633] | 0.554 [0.479, 0.629] | 0.800 [0.800, 0.800] | 0.800 [0.800, 0.800] | 0.800 [0.800, 0.800] | 1.000 [1.000, 1.000] | – |
| **overall** | 8 | 0.500 [0.143, 0.857] | 0.750 [0.429, 1.000] | 0.615 [0.323, 0.896] | 0.633 [0.383, 0.865] | 0.875 [0.600, 1.000] | 0.875 [0.600, 1.000] | 0.875 [0.600, 1.000] | 1.000 [1.000, 1.000] | 67/77 (0.870) |
| T3+T4 | 1 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.918 [0.918, 0.918] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | – | 8/10 (0.800) |
| free_text | 6 | 0.500 [0.125, 0.875] | 0.667 [0.250, 1.000] | 0.569 [0.208, 0.893] | 0.572 [0.265, 0.857] | 0.833 [0.500, 1.000] | 0.833 [0.500, 1.000] | 0.833 [0.500, 1.000] | 1.000 [1.000, 1.000] | 50/58 (0.862) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T0 | 9 | 0.000 / 1.000 | 0.000 / 1.000 | 0.167 / 1.000 | 0.294 / 1.000 |
| T1 | 17 | 0.500 / 1.000 | 1.000 / 1.000 | 0.750 / 1.000 | 0.815 / 1.000 |
| T2 | 23 | 0.667 / 1.000 | 1.000 / 1.000 | 0.750 / 1.000 | 0.741 / 0.992 |
| T3 | 8 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 0.918 / 0.993 |
| T5 | 10 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| overall | 67 | 0.500 / 1.000 | 0.750 / 1.000 | 0.615 / 1.000 | 0.633 / 0.996 |
| T3+T4 | 8 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 0.918 / 0.993 |
| free_text | 50 | 0.500 / 1.000 | 0.667 / 1.000 | 0.569 / 1.000 | 0.572 / 0.995 |

Pairs to judge: 67 (export with `python -m benchmarks_v2.eval pool`).

## Abstention and errors

| Population | n | False-accept rate (unanswerable) | Abstention rate (answerable) | AURC | Max coverage | Errors | HTTP 504 |
|---|---|---|---|---|---|---|---|
| T0 | 1 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T1 | 2 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T2 | 3 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T3 | 1 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T5 | 1 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T7 | 2 | 0.000 [0.000, 0.000] (0/2) (no tiers) | – | – | – | 0 | 0 |
| overall | 10 | 0.000 [0.000, 0.000] (0/2) (no tiers) | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T3+T4 | 1 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| free_text | 8 | 0.000 [0.000, 0.000] (0/2) (no tiers) | 0.000 [0.000, 0.000] | – | – | 0 | 0 |

## Calibration

| Population | pairs | ECE (bins) | Brier | unjudged excluded |
|---|---|---|---|---|
| T0 | 0 | – (0/10) | – | 0 |
| T1 | 0 | – (0/10) | – | 0 |
| T2 | 0 | – (0/10) | – | 0 |
| T3 | 0 | – (0/10) | – | 0 |
| T5 | 0 | – (0/10) | – | 0 |
| T7 | 0 | – (0/10) | – | 0 |
| overall | 0 | – (0/10) | – | 0 |
| T3+T4 | 0 | – (0/10) | – | 0 |
| free_text | 0 | – (0/10) | – | 0 |

Observed precision per tier (pairs in the top 10, label grade >= 2):

| Population | Tier | n | Precision | Wilson 95% | Bootstrap 95% |
|---|---|---|---|---|---|

## Latency (end to end, ms)

| Population | n | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| T0 | 1 | 10256 [10256, 10256] | 10256 [10256, 10256] | 10256 [10256, 10256] | 10256 |
| T1 | 2 | 4744 [3929, 5560] | 5479 [3929, 5560] | 5544 [3929, 5560] | 5560 |
| T2 | 3 | 3404 [3201, 3657] | 3632 [3201, 3657] | 3652 [3201, 3657] | 3657 |
| T3 | 1 | 7205 [7205, 7205] | 7205 [7205, 7205] | 7205 [7205, 7205] | 7205 |
| T5 | 1 | 4157 [4157, 4157] | 4157 [4157, 4157] | 4157 [4157, 4157] | 4157 |
| T7 | 2 | 3195 [3124, 3265] | 3258 [3124, 3265] | 3264 [3124, 3265] | 3265 |
| overall | 10 | 3793 [3265, 5681] | 8883 [4157, 10256] | 9982 [4157, 10256] | 10256 |
| T3+T4 | 1 | 7205 [7205, 7205] | 7205 [7205, 7205] | 7205 [7205, 7205] | 7205 |
| free_text | 8 | 3531 [3201, 7205] | 9188 [3893, 10256] | 10043 [4104, 10256] | 10256 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a5f9849e2dc3a8a0f\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 4, FAIL 2, MISSING 14, NOT_APPLICABLE 5, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 67 unjudged (rate 0.8701) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **FAIL** | 0.5000 [0.0000, 1.0000] | >= 1.0 |  |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **PASS** | 1.0000 [1.0000, 1.0000] | >= 0.9, lower >= 0.85 |  |
| T3T4_recall10 | T3+T4 | **PASS** | 1.0000 [1.0000, 1.0000] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **PASS** | 1.0000 [1.0000, 1.0000] | >= 0.75 |  |
| T6_within5_ndcg | T6_vs_clean | **MISSING** | n/a |  | parent pair T6_vs_clean / ndcg@10 not in report |
| T6_within5_success1 | T6_vs_clean | **MISSING** | n/a |  | parent pair T6_vs_clean / success@1 not in report |
| T8_success1 | T8 | **MISSING** | n/a |  | population T8 not in report |
| T7_false_accept | T7 | **MISSING** | n/a |  | variant returns no confidence tiers; false accepts cannot be judged |
| reranker_vs_ceiling_ndcg | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| reranker_vs_ceiling_success1 | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| strong_precision | overall | **MISSING** | n/a |  | no STRONG results in overall |
| ece_overall | overall | **MISSING** | n/a |  | no probabilities in overall |
| ece_per_slice[T0] | T0 | **NOT_APPLICABLE** | n/a |  | no probabilities in T0 |
| ece_per_slice[T1] | T1 | **NOT_APPLICABLE** | n/a |  | no probabilities in T1 |
| ece_per_slice[T2] | T2 | **NOT_APPLICABLE** | n/a |  | no probabilities in T2 |
| ece_per_slice[T3] | T3 | **NOT_APPLICABLE** | n/a |  | no probabilities in T3 |
| ece_per_slice[T4] | T4 | **MISSING** | n/a |  | population T4 not in report |
| ece_per_slice[T6] | T6 | **MISSING** | n/a |  | population T6 not in report |
| ece_per_slice[T7] | T7 | **NOT_APPLICABLE** | n/a |  | no probabilities in T7 |
| ece_per_slice[T8] | T8 | **MISSING** | n/a |  | population T8 not in report |
| ece_per_slice[T9] | T9 | **MISSING** | n/a |  | population T9 not in report |
| latency_free_text_p95 | free_text | **FAIL** | 9188.4786 [3893.4397, 10256.4677] | <= 3000 | target 1000 ms not met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
