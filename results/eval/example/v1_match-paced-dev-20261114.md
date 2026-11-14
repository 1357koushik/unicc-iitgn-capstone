# Evaluation report: v1_match on dev

**PROVISIONAL: 16 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-14T17:03:22Z |
| Harness | b4-1 commit `2d7e24cbaabcd6a32ad0c335923a6fca795d03cc` |
| Dataset | version b4-example-1 at `benchmarks_v2\eval\example\dataset` |
| Manifest sha256 | `20a44f7d81b40a3478095efc7233eb17cb0922203ee5d834cf7b6adb16c52115` (files verified) |
| Query file sha256 | `7eb5049ebc6708da85da7344b3579a2f933cc5f4ad15e3aec34f28754a91517d` |
| Qrels file sha256 | `34cd609986bf26905aae88fc2035c3a35201bc1dbcdae22242413de85c174542` |
| Run file | `results\eval\example\b4-example-paced-v1_match.jsonl` sha256 `afbd6fd63e86fc7e07569fe9903d9b6239fa01ee79001c4848280e26953abea9` |
| Variant config | `{"adapter": "http_v1", "base_url": "http://127.0.0.1:8765", "endpoint": "/api/v1/threats/match", "mapping": {"abstain_when_empty": true, "abstained": null, "doc_id": "citations.0.doc_id", "doc_id_transform": "cve_prefix", "probability": "composite_score", "results": "top_matches", "score": "composite_score", "tier": "confidence_tier"}, "request": {"top_k": 10}, "timeout_s": 120.0}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [0.81, 0.33, 0.15] -> [10.15, 7.4, 3.47] |
| Service health | `{"components": {"bm25": "available", "confidence_model": "available", "embedder": "available", "knowledge_graph": "starter_stub", "qdrant": "available", "reranker": "available", "sqlite": "available"}, "degraded_components": [], "status": "healthy"}` |
| Split / slices | dev / all |
| Queries | 10 evaluated of 10 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['ndcg@10', 'success@1'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T0 | 1 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | – | 0/0 |
| T1 | 2 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | – | 16/18 (0.889) |
| T2 | 3 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0/0 |
| T3 | 1 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | – | 0/0 |
| T5 | 1 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | – | 0/0 |
| T7 | 0 | – | – | – | – | – | – | – | – | 0/0 |
| **macro (slices)** | – | 0.200 [0.200, 0.200] | 0.200 [0.200, 0.200] | 0.200 [0.200, 0.200] | 0.200 [0.200, 0.200] | 0.200 [0.200, 0.200] | 0.200 [0.200, 0.200] | 0.200 [0.200, 0.200] | 0.000 [0.000, 0.000] | – |
| **overall** | 8 | 0.250 [0.000, 0.571] | 0.250 [0.000, 0.571] | 0.250 [0.000, 0.571] | 0.250 [0.000, 0.571] | 0.250 [0.000, 0.571] | 0.250 [0.000, 0.571] | 0.250 [0.000, 0.571] | 0.000 [0.000, 0.000] | 16/18 (0.889) |
| T3+T4 | 1 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | – | 0/0 |
| free_text | 6 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0/0 |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T1 | 16 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 |
| overall | 16 | 0.250 / 0.250 | 0.250 / 0.250 | 0.250 / 0.250 | 0.250 / 0.250 |

Pairs to judge: 16 (export with `python -m benchmarks_v2.eval pool`).

## Abstention and errors

| Population | n | False-accept rate (unanswerable) | Abstention rate (answerable) | AURC | Max coverage | Errors | HTTP 504 |
|---|---|---|---|---|---|---|---|
| T0 | 1 | – | 0.000 [0.000, 0.000] | – | – | 1 | 1 |
| T1 | 2 | – | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 | 0 | 0 |
| T2 | 3 | – | 0.000 [0.000, 0.000] | – | – | 3 | 3 |
| T3 | 1 | – | 0.000 [0.000, 0.000] | – | – | 1 | 1 |
| T5 | 1 | – | 0.000 [0.000, 0.000] | – | – | 1 | 1 |
| T7 | 2 | 0.000 [0.000, 0.000] (0/2) | – | – | – | 2 | 2 |
| overall | 10 | 0.000 [0.000, 0.000] (0/2) | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.200 | 8 | 8 |
| T3+T4 | 1 | – | 0.000 [0.000, 0.000] | – | – | 1 | 1 |
| free_text | 8 | 0.000 [0.000, 0.000] (0/2) | 0.000 [0.000, 0.000] | – | – | 8 | 8 |

## Calibration

| Population | pairs | ECE (bins) | Brier | unjudged excluded |
|---|---|---|---|---|
| T0 | 0 | – (0/10) | – | 0 |
| T1 | 2 | 0.000 [0.000, 0.000] (1/10) | 0.000 [0.000, 0.000] | 16 |
| T2 | 0 | – (0/10) | – | 0 |
| T3 | 0 | – (0/10) | – | 0 |
| T5 | 0 | – (0/10) | – | 0 |
| T7 | 0 | – (0/10) | – | 0 |
| overall | 2 | 0.000 [0.000, 0.000] (1/10) | 0.000 [0.000, 0.000] | 16 |
| T3+T4 | 0 | – (0/10) | – | 0 |
| free_text | 0 | – (0/10) | – | 0 |

Observed precision per tier (pairs in the top 10, label grade >= 2):

| Population | Tier | n | Precision | Wilson 95% | Bootstrap 95% |
|---|---|---|---|---|---|
| T1 | EXACT | 2 | 1.000 | [0.342, 1.000] | [1.000, 1.000] |
| overall | EXACT | 2 | 1.000 | [0.342, 1.000] | [1.000, 1.000] |

Reliability diagram data (overall, equal-mass bins):

| Bin | n | p range | mean p | observed | Wilson 95% |
|---|---|---|---|---|---|
| 1 | 2 | 1.000–1.000 | 1.000 | 1.000 | [0.342, 1.000] |

## Latency (end to end, ms)

| Population | n | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| T0 | 1 | 15012 [15012, 15012] | 15012 [15012, 15012] | 15012 [15012, 15012] | 15012 |
| T1 | 2 | 11164 [10770, 11559] | 11519 [10770, 11559] | 11551 [10770, 11559] | 11559 |
| T2 | 3 | 15021 [15020, 15024] | 15024 [15020, 15024] | 15024 [15020, 15024] | 15024 |
| T3 | 1 | 15018 [15018, 15018] | 15018 [15018, 15018] | 15018 [15018, 15018] | 15018 |
| T5 | 1 | 15019 [15019, 15019] | 15019 [15019, 15019] | 15019 [15019, 15019] | 15019 |
| T7 | 2 | 15023 [15020, 15025] | 15025 [15020, 15025] | 15025 [15020, 15025] | 15025 |
| overall | 10 | 15019 [13288, 15022] | 15025 [15020, 15025] | 15025 [15020, 15025] | 15025 |
| T3+T4 | 1 | 15018 [15018, 15018] | 15018 [15018, 15018] | 15018 [15018, 15018] | 15018 |
| free_text | 8 | 15020 [15018, 15024] | 15025 [15020, 15025] | 15025 [15020, 15025] | 15025 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: v1_match - v1_hybrid

Reference run `results\eval\example\b4-example-v1_hybrid.jsonl` (sha256 `2ecb29a299e8f79d84fe6c85d03aefdea41e38b006d7c3b7cb4f3b616d425cc8`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v1_match | v1_hybrid | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T0 | S@1 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| T0 | S@5 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T0 | MRR@10 | 0.000 | 0.167 | -0.167 [-0.167, -0.167] | 0.000 | – |
| T0 | nDCG@10 | 0.000 | 0.294 | -0.294 [-0.294, -0.294] | 0.000 | no (lower -0.294) |
| T0 | R@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T0 | R@50 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T0 | R@100 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T1 | S@1 | 1.000 | 0.500 | 0.500 [0.000, 1.000] | 0.502 | yes (lower 0.000) |
| T1 | S@5 | 1.000 | 1.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T1 | MRR@10 | 1.000 | 0.750 | 0.250 [0.000, 0.500] | 0.502 | – |
| T1 | nDCG@10 | 1.000 | 0.815 | 0.185 [0.000, 0.369] | 0.502 | yes (lower 0.000) |
| T1 | R@10 | 1.000 | 1.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T1 | R@50 | 1.000 | 1.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T1 | R@100 | 1.000 | 1.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T2 | S@1 | 0.000 | 0.667 | -0.667 [-1.000, 0.000] | 0.076 | no (lower -1.000) |
| T2 | S@5 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T2 | MRR@10 | 0.000 | 0.750 | -0.750 [-1.000, -0.250] | 0.000 | – |
| T2 | nDCG@10 | 0.000 | 0.741 | -0.741 [-1.000, -0.431] | 0.000 | no (lower -1.000) |
| T2 | R@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T2 | R@50 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T2 | R@100 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T2 | SetR@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3 | S@1 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | no (lower -1.000) |
| T3 | S@5 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3 | MRR@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3 | nDCG@10 | 0.000 | 0.918 | -0.918 [-0.918, -0.918] | 0.000 | no (lower -0.918) |
| T3 | R@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3 | R@50 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3 | R@100 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T5 | S@1 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| T5 | S@5 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T5 | MRR@10 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T5 | nDCG@10 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| T5 | R@10 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T5 | R@50 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| T5 | R@100 | 0.000 | 0.000 | 0.000 [0.000, 0.000] | 1.000 | – |
| overall | S@1 | 0.250 | 0.500 | -0.250 [-0.714, 0.250] | 0.422 | no (lower -0.714) |
| overall | S@5 | 0.250 | 0.750 | -0.500 [-0.857, -0.143] | 0.013 | – |
| overall | MRR@10 | 0.250 | 0.615 | -0.365 [-0.742, 0.012] | 0.066 | – |
| overall | nDCG@10 | 0.250 | 0.633 | -0.383 [-0.705, -0.053] | 0.025 | no (lower -0.705) |
| overall | R@10 | 0.250 | 0.875 | -0.625 [-1.000, -0.250] | 0.002 | – |
| overall | R@50 | 0.250 | 0.875 | -0.625 [-1.000, -0.250] | 0.002 | – |
| overall | R@100 | 0.250 | 0.875 | -0.625 [-1.000, -0.250] | 0.002 | – |
| overall | SetR@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3+T4 | S@1 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | no (lower -1.000) |
| T3+T4 | S@5 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3+T4 | MRR@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.000 | 0.918 | -0.918 [-0.918, -0.918] | 0.000 | no (lower -0.918) |
| T3+T4 | R@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3+T4 | R@50 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| T3+T4 | R@100 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| free_text | S@1 | 0.000 | 0.500 | -0.500 [-0.858, -0.125] | 0.048 | no (lower -0.858) |
| free_text | S@5 | 0.000 | 0.667 | -0.667 [-1.000, -0.250] | 0.008 | – |
| free_text | MRR@10 | 0.000 | 0.569 | -0.569 [-0.893, -0.208] | 0.001 | – |
| free_text | nDCG@10 | 0.000 | 0.572 | -0.572 [-0.857, -0.266] | 0.001 | no (lower -0.857) |
| free_text | R@10 | 0.000 | 0.833 | -0.833 [-1.000, -0.500] | 0.001 | – |
| free_text | R@50 | 0.000 | 0.833 | -0.833 [-1.000, -0.500] | 0.001 | – |
| free_text | R@100 | 0.000 | 0.833 | -0.833 [-1.000, -0.500] | 0.001 | – |
| free_text | SetR@10 | 0.000 | 1.000 | -1.000 [-1.000, -1.000] | 0.000 | – |
| macro | S@1 | – | – | -0.233 [-0.400, -0.067] | 0.016 | no (lower -0.400) |
| macro | S@5 | – | – | -0.400 [-0.400, -0.400] | 0.000 | – |
| macro | MRR@10 | – | – | -0.333 [-0.433, -0.233] | 0.000 | – |
| macro | nDCG@10 | – | – | -0.354 [-0.429, -0.279] | 0.000 | no (lower -0.429) |
| macro | R@10 | – | – | -0.600 [-0.600, -0.600] | 0.000 | – |
| macro | R@50 | – | – | -0.600 [-0.600, -0.600] | 0.000 | – |
| macro | R@100 | – | – | -0.600 [-0.600, -0.600] | 0.000 | – |
| macro | SetR@10 | – | – | -1.000 [-1.000, -1.000] | 0.000 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a5f9849e2dc3a8a0f\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 4, FAIL 5, MISSING 11, NOT_APPLICABLE 5, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 16 unjudged (rate 0.8889) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **PASS** | 1.0000 [1.0000, 1.0000] | >= 1.0 |  |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **NOT_APPLICABLE** | n/a |  | report is the reference variant v1_match itself |
| T2_success5 | T2 | **FAIL** | 0.0000 [0.0000, 0.0000] | >= 0.9, lower >= 0.85 |  |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.0000 [0.0000, 0.0000] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.0000 [0.0000, 0.0000] | >= 0.75 |  |
| T6_within5_ndcg | T6_vs_clean | **MISSING** | n/a |  | parent pair T6_vs_clean / ndcg@10 not in report |
| T6_within5_success1 | T6_vs_clean | **MISSING** | n/a |  | parent pair T6_vs_clean / success@1 not in report |
| T8_success1 | T8 | **MISSING** | n/a |  | population T8 not in report |
| T7_false_accept | T7 | **PASS** | 0.0000 [0.0000, 0.0000] | <= 0.01 |  |
| reranker_vs_ceiling_ndcg | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| reranker_vs_ceiling_success1 | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| strong_precision | overall | **MISSING** | n/a |  | no STRONG results in overall |
| ece_overall | overall | **PASS** | 0.0000 [0.0000, 0.0000] | <= 0.05 |  |
| ece_per_slice[T0] | T0 | **NOT_APPLICABLE** | n/a |  | no probabilities in T0 |
| ece_per_slice[T1] | T1 | **PASS** | 0.0000 [0.0000, 0.0000] | <= 0.05 |  |
| ece_per_slice[T2] | T2 | **NOT_APPLICABLE** | n/a |  | no probabilities in T2 |
| ece_per_slice[T3] | T3 | **NOT_APPLICABLE** | n/a |  | no probabilities in T3 |
| ece_per_slice[T4] | T4 | **MISSING** | n/a |  | population T4 not in report |
| ece_per_slice[T6] | T6 | **MISSING** | n/a |  | population T6 not in report |
| ece_per_slice[T7] | T7 | **NOT_APPLICABLE** | n/a |  | no probabilities in T7 |
| ece_per_slice[T8] | T8 | **MISSING** | n/a |  | population T8 not in report |
| ece_per_slice[T9] | T9 | **MISSING** | n/a |  | population T9 not in report |
| latency_free_text_p95 | free_text | **FAIL** | 15024.8475 [15020.3129, 15025.2943] | <= 3000 | target 1000 ms not met |
| no_http_504 | overall | **FAIL** | 8 | <= 0 |  |
