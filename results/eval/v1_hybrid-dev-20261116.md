# Evaluation report: v1_hybrid on dev

**PROVISIONAL: 12328 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-15T20:38:10Z |
| Harness | b4-1 commit `2963e15604d0021516e2e36147bee7c740a3398e` |
| Dataset | version v2.0 at `data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `results\eval\runs\v1_hybrid-dev.jsonl` sha256 `506cd754e1b339106ca35279dc0cc78aeca482c3ca3e21a3fb3ed9b7876307bd` |
| Variant config | `{"adapter": "http_v1", "base_url": "http://127.0.0.1:8765", "endpoint": "/api/v1/search/hybrid", "mapping": {"abstain_when_empty": false, "abstained": null, "doc_id": "chunk_id", "doc_id_resolver": {"kind": "sqlite", "path": "~/data/sqlite/corpus_store.db", "sql": "select doc_id from corpus where chunk_id = ?"}, "doc_id_transform": "cve_prefix", "probability": null, "results": "results", "score": "rrf_score", "tier": null}, "request": {"top_k": 10}, "timeout_s": 120.0}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [4.76, 4.27, 4.42] -> [5.4, 4.32, 4.03] |
| Service health | `{"components": {"bm25": "available", "confidence_model": "available", "embedder": "available", "knowledge_graph": "starter_stub", "qdrant": "available", "reranker": "available", "sqlite": "available"}, "degraded_components": [], "status": "healthy"}` |
| Split / slices | dev / all |
| Queries | 1489 evaluated of 1489 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['ndcg@10', 'success@1'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T0 | 106 | 0.198 [0.123, 0.274] | 0.321 [0.236, 0.415] | 0.249 [0.176, 0.328] | 0.231 [0.165, 0.303] | 0.296 [0.216, 0.382] | 0.296 [0.216, 0.382] | 0.296 [0.216, 0.382] | 0.241 [0.140, 0.356] | 988/1043 (0.947) |
| T1 | 150 | 0.013 [0.000, 0.033] | 0.593 [0.513, 0.673] | 0.297 [0.259, 0.337] | 0.385 [0.340, 0.431] | 0.652 [0.579, 0.726] | 0.652 [0.579, 0.726] | 0.652 [0.579, 0.726] | 0.906 [0.825, 0.976] | 1375/1498 (0.918) |
| T2 | 99 | 0.162 [0.091, 0.232] | 0.222 [0.141, 0.303] | 0.189 [0.118, 0.263] | 0.206 [0.134, 0.281] | 0.263 [0.182, 0.354] | 0.263 [0.182, 0.354] | 0.263 [0.182, 0.354] | 0.000 [0.000, 0.000] | 964/990 (0.974) |
| T3 | 300 | 0.247 [0.200, 0.297] | 0.443 [0.387, 0.500] | 0.337 [0.290, 0.384] | 0.389 [0.343, 0.437] | 0.560 [0.503, 0.617] | 0.560 [0.503, 0.617] | 0.560 [0.503, 0.617] | – | 2829/2997 (0.944) |
| T4 | 160 | 0.194 [0.138, 0.256] | 0.350 [0.281, 0.425] | 0.262 [0.205, 0.324] | 0.299 [0.241, 0.360] | 0.428 [0.354, 0.504] | 0.428 [0.354, 0.504] | 0.428 [0.354, 0.504] | 0.458 [0.217, 0.708] | 1513/1590 (0.952) |
| T5 | 120 | 0.258 [0.183, 0.342] | 0.475 [0.383, 0.567] | 0.349 [0.277, 0.424] | 0.380 [0.314, 0.449] | 0.520 [0.434, 0.604] | 0.520 [0.434, 0.604] | 0.520 [0.434, 0.604] | 0.427 [0.293, 0.565] | 1053/1199 (0.878) |
| T6 | 154 | 0.175 [0.117, 0.240] | 0.286 [0.214, 0.357] | 0.226 [0.166, 0.288] | 0.242 [0.182, 0.302] | 0.321 [0.248, 0.394] | 0.321 [0.248, 0.394] | 0.321 [0.248, 0.394] | 0.233 [0.093, 0.397] | 1472/1533 (0.960) |
| T7 | 0 | – | – | – | – | – | – | – | – | 0/0 |
| T8 | 120 | 0.267 [0.192, 0.350] | 0.383 [0.300, 0.475] | 0.318 [0.243, 0.396] | 0.357 [0.281, 0.433] | 0.483 [0.392, 0.575] | 0.483 [0.392, 0.575] | 0.483 [0.392, 0.575] | – | 934/1199 (0.779) |
| T9 | 120 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 1200/1200 (1.000) |
| **macro (slices)** | – | 0.168 [0.148, 0.189] | 0.342 [0.317, 0.367] | 0.248 [0.227, 0.268] | 0.277 [0.257, 0.296] | 0.391 [0.367, 0.416] | 0.391 [0.367, 0.417] | 0.391 [0.366, 0.416] | 0.324 [0.273, 0.374] | – |
| **overall** | 1329 | 0.176 [0.156, 0.197] | 0.362 [0.336, 0.388] | 0.262 [0.241, 0.282] | 0.296 [0.275, 0.316] | 0.422 [0.396, 0.448] | 0.422 [0.396, 0.448] | 0.422 [0.396, 0.448] | 0.294 [0.239, 0.352] | 12328/13249 (0.930) |
| temporal_holdout | 73 | 0.082 [0.027, 0.151] | 0.219 [0.123, 0.315] | 0.146 [0.082, 0.217] | 0.157 [0.096, 0.226] | 0.215 [0.130, 0.308] | 0.215 [0.130, 0.308] | 0.215 [0.130, 0.308] | 0.292 [0.120, 0.480] | 689/729 (0.945) |
| T3+T4 | 460 | 0.228 [0.191, 0.267] | 0.411 [0.365, 0.457] | 0.311 [0.274, 0.348] | 0.358 [0.321, 0.395] | 0.514 [0.468, 0.559] | 0.514 [0.468, 0.559] | 0.514 [0.468, 0.559] | 0.458 [0.217, 0.705] | 4342/4587 (0.947) |
| T9_id_name | 45 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | – | 450/450 (1.000) |
| free_text | 1179 | 0.197 [0.174, 0.220] | 0.332 [0.306, 0.359] | 0.257 [0.235, 0.279] | 0.284 [0.262, 0.306] | 0.393 [0.366, 0.420] | 0.393 [0.366, 0.420] | 0.393 [0.366, 0.420] | 0.215 [0.163, 0.269] | 10953/11751 (0.932) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T0 | 988 | 0.198 / 1.000 | 0.321 / 1.000 | 0.249 / 1.000 | 0.231 / 0.997 |
| T1 | 1375 | 0.013 / 1.000 | 0.593 / 1.000 | 0.297 / 1.000 | 0.385 / 0.999 |
| T2 | 964 | 0.162 / 1.000 | 0.222 / 1.000 | 0.189 / 1.000 | 0.206 / 1.000 |
| T3 | 2829 | 0.247 / 1.000 | 0.443 / 1.000 | 0.337 / 1.000 | 0.389 / 0.999 |
| T4 | 1513 | 0.194 / 1.000 | 0.350 / 1.000 | 0.262 / 1.000 | 0.299 / 1.000 |
| T5 | 1053 | 0.258 / 0.900 | 0.475 / 1.000 | 0.349 / 0.943 | 0.380 / 0.974 |
| T6 | 1472 | 0.175 / 1.000 | 0.286 / 1.000 | 0.226 / 1.000 | 0.242 / 0.998 |
| T8 | 934 | 0.267 / 0.842 | 0.383 / 0.992 | 0.318 / 0.907 | 0.357 / 0.897 |
| T9 | 1200 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| overall | 12328 | 0.176 / 0.977 | 0.362 / 0.999 | 0.262 / 0.986 | 0.296 / 0.987 |
| temporal_holdout | 689 | 0.082 / 0.932 | 0.219 / 1.000 | 0.146 / 0.963 | 0.157 / 0.976 |
| T3+T4 | 4342 | 0.228 / 1.000 | 0.411 / 1.000 | 0.311 / 1.000 | 0.358 / 0.999 |
| T9_id_name | 450 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| free_text | 10953 | 0.197 / 0.974 | 0.332 / 0.999 | 0.257 / 0.985 | 0.284 / 0.986 |

Pairs to judge: 12328 (export with `python -m benchmarks_v2.eval pool`).

## Abstention and errors

| Population | n | False-accept rate (unanswerable) | Abstention rate (answerable) | AURC | Max coverage | Errors | HTTP 504 |
|---|---|---|---|---|---|---|---|
| T0 | 106 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T1 | 150 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T2 | 99 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T3 | 300 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T4 | 160 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T5 | 120 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T6 | 154 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T7 | 160 | 0.000 [0.000, 0.000] (0/160) (no tiers) | – | – | – | 0 | 0 |
| T8 | 120 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T9 | 120 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| overall | 1489 | 0.000 [0.000, 0.000] (0/160) (no tiers) | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| temporal_holdout | 73 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T3+T4 | 460 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T9_id_name | 45 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| free_text | 1339 | 0.000 [0.000, 0.000] (0/160) (no tiers) | 0.000 [0.000, 0.000] | – | – | 0 | 0 |

## Calibration

| Population | pairs | ECE (bins) | Brier | unjudged excluded |
|---|---|---|---|---|
| T0 | 0 | – (0/10) | – | 0 |
| T1 | 0 | – (0/10) | – | 0 |
| T2 | 0 | – (0/10) | – | 0 |
| T3 | 0 | – (0/10) | – | 0 |
| T4 | 0 | – (0/10) | – | 0 |
| T5 | 0 | – (0/10) | – | 0 |
| T6 | 0 | – (0/10) | – | 0 |
| T7 | 0 | – (0/10) | – | 0 |
| T8 | 0 | – (0/10) | – | 0 |
| T9 | 0 | – (0/10) | – | 0 |
| overall | 0 | – (0/10) | – | 0 |
| temporal_holdout | 0 | – (0/10) | – | 0 |
| T3+T4 | 0 | – (0/10) | – | 0 |
| T9_id_name | 0 | – (0/10) | – | 0 |
| free_text | 0 | – (0/10) | – | 0 |

Observed precision per tier (pairs in the top 10, label grade >= 2):

| Population | Tier | n | Precision | Wilson 95% | Bootstrap 95% |
|---|---|---|---|---|---|

## Latency (end to end, ms)

| Population | n | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| T0 | 106 | 5506 [5079, 5767] | 7444 [6862, 8650] | 9172 [7462, 9466] | 9466 |
| T1 | 150 | 3752 [3675, 3878] | 5219 [4804, 5960] | 6436 [5615, 6644] | 6644 |
| T2 | 99 | 3531 [3291, 3873] | 5107 [4454, 5432] | 5532 [5083, 5802] | 5802 |
| T3 | 300 | 3953 [3854, 4083] | 5373 [5116, 5614] | 5807 [5664, 6131] | 6821 |
| T4 | 160 | 3741 [3594, 3952] | 5477 [5063, 5582] | 5952 [5515, 6408] | 6408 |
| T5 | 120 | 3997 [3656, 4190] | 5594 [5044, 5980] | 6222 [5749, 6348] | 6348 |
| T6 | 154 | 4248 [4061, 4426] | 5894 [5584, 6605] | 6753 [6412, 7234] | 7234 |
| T7 | 160 | 3624 [3486, 3750] | 4718 [4471, 5132] | 5323 [4943, 6115] | 6115 |
| T8 | 120 | 3945 [3790, 4098] | 5078 [4630, 5405] | 5472 [5083, 5491] | 5491 |
| T9 | 120 | 3823 [3552, 3948] | 5248 [4540, 5436] | 5466 [5256, 5774] | 5774 |
| overall | 1489 | 3925 [3873, 3964] | 5751 [5580, 5885] | 6777 [6602, 7240] | 9466 |
| temporal_holdout | 73 | 3908 [3774, 4105] | 5598 [4966, 6284] | 6377 [5587, 6616] | 6616 |
| T3+T4 | 460 | 3885 [3796, 3975] | 5438 [5164, 5560] | 5878 [5693, 6331] | 6821 |
| T9_id_name | 45 | 3965 [3884, 4046] | 5303 [4439, 5687] | 5582 [4970, 5774] | 5774 |
| free_text | 1339 | 3948 [3889, 3997] | 5768 [5586, 5916] | 6806 [6616, 7292] | 9466 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | ndcg@10 | 154 | 0 | -0.035 [-0.074, 0.004] | 0.078 |
| T6_vs_clean | success@1 | 154 | 0 | -0.013 [-0.065, 0.039] | 0.713 |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 3, FAIL 7, MISSING 6, NOT_APPLICABLE 9, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 12328 unjudged (rate 0.9305) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **FAIL** | 0.0133 [0.0000, 0.0333] | >= 1.0 |  |
| T9_id_name_success1 | T9_id_name | **FAIL** | 0.0000 [0.0000, 0.0000] | >= 1.0 |  |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **FAIL** | 0.2222 [0.1414, 0.3030] | >= 0.9, lower >= 0.85 |  |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.5139 [0.4679, 0.5585] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.3107 [0.2742, 0.3476] | >= 0.75 |  |
| T6_within5_ndcg | T6 | **PASS** | diff -0.0350 [-0.0744, 0.0039] | diff >= -0.05 |  |
| T6_within5_success1 | T6 | **PASS** | diff -0.0130 [-0.0649, 0.0390] | diff >= -0.05 |  |
| T8_success1 | T8 | **FAIL** | 0.2667 [0.1917, 0.3500] | >= 0.8 |  |
| T7_false_accept | T7 | **MISSING** | n/a |  | variant returns no confidence tiers; false accepts cannot be judged |
| reranker_vs_ceiling_ndcg | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| reranker_vs_ceiling_success1 | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| strong_precision | overall | **MISSING** | n/a |  | no STRONG results in overall |
| ece_overall | overall | **MISSING** | n/a |  | no probabilities in overall |
| ece_per_slice[T0] | T0 | **NOT_APPLICABLE** | n/a |  | no probabilities in T0 |
| ece_per_slice[T1] | T1 | **NOT_APPLICABLE** | n/a |  | no probabilities in T1 |
| ece_per_slice[T2] | T2 | **NOT_APPLICABLE** | n/a |  | no probabilities in T2 |
| ece_per_slice[T3] | T3 | **NOT_APPLICABLE** | n/a |  | no probabilities in T3 |
| ece_per_slice[T4] | T4 | **NOT_APPLICABLE** | n/a |  | no probabilities in T4 |
| ece_per_slice[T6] | T6 | **NOT_APPLICABLE** | n/a |  | no probabilities in T6 |
| ece_per_slice[T7] | T7 | **NOT_APPLICABLE** | n/a |  | no probabilities in T7 |
| ece_per_slice[T8] | T8 | **NOT_APPLICABLE** | n/a |  | no probabilities in T8 |
| ece_per_slice[T9] | T9 | **NOT_APPLICABLE** | n/a |  | no probabilities in T9 |
| latency_free_text_p95 | free_text | **FAIL** | 5768.1396 [5586.2983, 5915.9724] | <= 3000 | target 1000 ms not met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |

## Warnings

- 1 equivalence units have members judged with different grades (the maximum grade is used)
