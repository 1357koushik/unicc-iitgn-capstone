# Evaluation report: cmp_v1 on train

**PROVISIONAL: 8701 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:23:20Z |
| Harness | b4-1 commit `403325fc1d07208ddb11938027df191f3acdc271` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1-train.jsonl` sha256 `0c5a13da1283207fb367eab3d1af09f276e2bfc4ea0ea97907754f5e8d3e0b6b` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"index": "compare/v1", "k": 100, "kinds": "all"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [22.5, 22.33, 22.55] -> [17.72, 21.08, 22.1] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "1e1fde3b6bc046dc7049", "path": "/home/koushik.moram/team2/dense/qvec/qvec-1e1fde3b6bc046dc7049.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.297 [0.260, 0.333] | 0.510 [0.470, 0.550] | 0.386 [0.351, 0.421] | 0.433 [0.399, 0.468] | 0.582 [0.542, 0.622] | 0.722 [0.685, 0.757] | 0.793 [0.760, 0.825] | – | 5650/6000 (0.942) |
| T4 | 320 | 0.175 [0.134, 0.216] | 0.344 [0.291, 0.397] | 0.248 [0.207, 0.290] | 0.287 [0.245, 0.330] | 0.420 [0.366, 0.474] | 0.530 [0.475, 0.584] | 0.582 [0.528, 0.635] | 0.230 [0.097, 0.381] | 3051/3200 (0.953) |
| **macro (slices)** | – | 0.236 [0.208, 0.264] | 0.427 [0.394, 0.460] | 0.317 [0.291, 0.344] | 0.360 [0.333, 0.388] | 0.501 [0.467, 0.535] | 0.626 [0.593, 0.658] | 0.688 [0.656, 0.719] | 0.230 [0.096, 0.388] | – |
| **overall** | 920 | 0.254 [0.227, 0.283] | 0.452 [0.420, 0.484] | 0.338 [0.312, 0.364] | 0.382 [0.356, 0.408] | 0.525 [0.493, 0.557] | 0.655 [0.624, 0.685] | 0.720 [0.690, 0.748] | 0.230 [0.096, 0.383] | 8701/9200 (0.946) |
| T3+T4 | 920 | 0.254 [0.227, 0.283] | 0.452 [0.420, 0.485] | 0.338 [0.312, 0.365] | 0.382 [0.355, 0.409] | 0.525 [0.493, 0.558] | 0.655 [0.624, 0.687] | 0.720 [0.691, 0.749] | 0.230 [0.097, 0.385] | 8701/9200 (0.946) |
| free_text | 920 | 0.254 [0.227, 0.284] | 0.452 [0.421, 0.485] | 0.338 [0.311, 0.365] | 0.382 [0.356, 0.409] | 0.525 [0.494, 0.557] | 0.655 [0.624, 0.685] | 0.720 [0.691, 0.749] | 0.230 [0.096, 0.387] | 8701/9200 (0.946) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5650 | 0.297 / 1.000 | 0.510 / 1.000 | 0.386 / 1.000 | 0.433 / 1.000 |
| T4 | 3051 | 0.175 / 1.000 | 0.344 / 1.000 | 0.248 / 1.000 | 0.287 / 0.999 |
| overall | 8701 | 0.254 / 1.000 | 0.452 / 1.000 | 0.338 / 1.000 | 0.382 / 1.000 |
| T3+T4 | 8701 | 0.254 / 1.000 | 0.452 / 1.000 | 0.338 / 1.000 | 0.382 / 1.000 |
| free_text | 8701 | 0.254 / 1.000 | 0.452 / 1.000 | 0.338 / 1.000 | 0.382 / 1.000 |

Pairs to judge: 8701 (export with `python -m benchmarks_v2.eval pool`).

## Abstention and errors

| Population | n | False-accept rate (unanswerable) | Abstention rate (answerable) | AURC | Max coverage | Errors | HTTP 504 |
|---|---|---|---|---|---|---|---|
| T3 | 600 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T4 | 320 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| overall | 920 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| T3+T4 | 920 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |
| free_text | 920 | – | 0.000 [0.000, 0.000] | – | – | 0 | 0 |

## Calibration

| Population | pairs | ECE (bins) | Brier | unjudged excluded |
|---|---|---|---|---|
| T3 | 0 | – (0/10) | – | 0 |
| T4 | 0 | – (0/10) | – | 0 |
| overall | 0 | – (0/10) | – | 0 |
| T3+T4 | 0 | – (0/10) | – | 0 |
| free_text | 0 | – (0/10) | – | 0 |

Observed precision per tier (pairs in the top 10, label grade >= 2):

| Population | Tier | n | Precision | Wilson 95% | Bootstrap 95% |
|---|---|---|---|---|---|

## Latency (end to end, ms)

| Population | n | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| T3 | 600 | 25 [24, 26] | 77 [40, 90] | 107 [101, 245] | 386 |
| T4 | 320 | 23 [21, 24] | 30 [29, 43] | 104 [77, 208] | 273 |
| overall | 920 | 24 [24, 25] | 56 [39, 87] | 107 [101, 218] | 386 |
| T3+T4 | 920 | 24 [24, 25] | 56 [39, 87] | 107 [101, 231] | 386 |
| free_text | 920 | 24 [24, 25] | 56 [39, 87] | 107 [101, 218] | 386 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8701 unjudged (rate 0.9458) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.5253 [0.4933, 0.5580] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.3378 [0.3117, 0.3653] | >= 0.75 |  |
| T6_within5_ndcg | T6_vs_clean | **MISSING** | n/a |  | parent pair T6_vs_clean / ndcg@10 not in report |
| T6_within5_success1 | T6_vs_clean | **MISSING** | n/a |  | parent pair T6_vs_clean / success@1 not in report |
| T8_success1 | T8 | **MISSING** | n/a |  | population T8 not in report |
| T7_false_accept | T7 | **MISSING** | n/a |  | population T7 not in report |
| reranker_vs_ceiling_ndcg | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| reranker_vs_ceiling_success1 | overall | **MISSING** | n/a |  | no comparison against reranker_ceiling in report (score --compare <reranker_ceiling run>) |
| strong_precision | overall | **MISSING** | n/a |  | no STRONG results in overall |
| ece_overall | overall | **MISSING** | n/a |  | no probabilities in overall |
| ece_per_slice[T0] | T0 | **MISSING** | n/a |  | population T0 not in report |
| ece_per_slice[T1] | T1 | **MISSING** | n/a |  | population T1 not in report |
| ece_per_slice[T2] | T2 | **MISSING** | n/a |  | population T2 not in report |
| ece_per_slice[T3] | T3 | **NOT_APPLICABLE** | n/a |  | no probabilities in T3 |
| ece_per_slice[T4] | T4 | **NOT_APPLICABLE** | n/a |  | no probabilities in T4 |
| ece_per_slice[T6] | T6 | **MISSING** | n/a |  | population T6 not in report |
| ece_per_slice[T7] | T7 | **MISSING** | n/a |  | population T7 not in report |
| ece_per_slice[T8] | T8 | **MISSING** | n/a |  | population T8 not in report |
| ece_per_slice[T9] | T9 | **MISSING** | n/a |  | population T9 not in report |
| latency_free_text_p95 | free_text | **PASS** | 56.2281 [38.9748, 87.0440] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
