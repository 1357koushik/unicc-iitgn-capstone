# Evaluation report: cmp_bge-m3_v1cover on train

**PROVISIONAL: 8670 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:55:10Z |
| Harness | b4-1 commit `403325fc1d07208ddb11938027df191f3acdc271` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_bge-m3_v1cover-train.jsonl` sha256 `fb86c505798d52d053c8d199a0754eed0b182c2f39becb62e8e9a9242818ad1b` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"index": "compare/bge-m3", "k": 100, "kinds": "cve", "restrict_to": "compare/v1"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [22.79, 22.44, 22.45] -> [23.58, 22.83, 22.59] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "1e1fde3b6bc046dc7049", "path": "/home/koushik.moram/team2/dense/qvec/qvec-1e1fde3b6bc046dc7049.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.392 [0.353, 0.432] | 0.583 [0.543, 0.622] | 0.471 [0.436, 0.507] | 0.511 [0.476, 0.546] | 0.637 [0.598, 0.675] | 0.783 [0.750, 0.817] | 0.828 [0.797, 0.858] | – | 5616/6000 (0.936) |
| T4 | 320 | 0.178 [0.138, 0.219] | 0.334 [0.284, 0.388] | 0.254 [0.213, 0.296] | 0.287 [0.246, 0.331] | 0.399 [0.347, 0.453] | 0.536 [0.482, 0.590] | 0.582 [0.529, 0.636] | 0.336 [0.167, 0.517] | 3054/3200 (0.954) |
| **macro (slices)** | – | 0.285 [0.256, 0.314] | 0.459 [0.426, 0.491] | 0.362 [0.335, 0.390] | 0.399 [0.372, 0.428] | 0.518 [0.485, 0.551] | 0.660 [0.628, 0.692] | 0.705 [0.674, 0.736] | 0.336 [0.167, 0.520] | – |
| **overall** | 920 | 0.317 [0.288, 0.347] | 0.497 [0.464, 0.528] | 0.395 [0.367, 0.424] | 0.433 [0.405, 0.461] | 0.554 [0.522, 0.587] | 0.697 [0.668, 0.728] | 0.743 [0.714, 0.771] | 0.336 [0.167, 0.523] | 8670/9200 (0.942) |
| T3+T4 | 920 | 0.317 [0.288, 0.348] | 0.497 [0.465, 0.528] | 0.395 [0.367, 0.424] | 0.433 [0.405, 0.461] | 0.554 [0.522, 0.586] | 0.697 [0.668, 0.727] | 0.743 [0.715, 0.771] | 0.336 [0.165, 0.522] | 8670/9200 (0.942) |
| free_text | 920 | 0.317 [0.288, 0.348] | 0.497 [0.465, 0.528] | 0.395 [0.368, 0.424] | 0.433 [0.405, 0.461] | 0.554 [0.522, 0.585] | 0.697 [0.668, 0.726] | 0.743 [0.715, 0.770] | 0.336 [0.167, 0.525] | 8670/9200 (0.942) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5616 | 0.392 / 1.000 | 0.583 / 1.000 | 0.471 / 1.000 | 0.511 / 1.000 |
| T4 | 3054 | 0.178 / 1.000 | 0.334 / 1.000 | 0.254 / 1.000 | 0.287 / 0.999 |
| overall | 8670 | 0.317 / 1.000 | 0.497 / 1.000 | 0.395 / 1.000 | 0.433 / 1.000 |
| T3+T4 | 8670 | 0.317 / 1.000 | 0.497 / 1.000 | 0.395 / 1.000 | 0.433 / 1.000 |
| free_text | 8670 | 0.317 / 1.000 | 0.497 / 1.000 | 0.395 / 1.000 | 0.433 / 1.000 |

Pairs to judge: 8670 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 28 [27, 30] | 45 [43, 68] | 106 [101, 130] | 466 |
| T4 | 320 | 27 [25, 28] | 37 [37, 38] | 41 [38, 101] | 110 |
| overall | 920 | 28 [27, 29] | 43 [40, 45] | 105 [93, 110] | 466 |
| T3+T4 | 920 | 28 [27, 29] | 43 [40, 45] | 105 [93, 110] | 466 |
| free_text | 920 | 28 [27, 29] | 43 [40, 45] | 105 [93, 110] | 466 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: cmp_bge-m3_v1cover - cmp_v1

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1-train.jsonl` (sha256 `0c5a13da1283207fb367eab3d1af09f276e2bfc4ea0ea97907754f5e8d3e0b6b`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | cmp_bge-m3_v1cover | cmp_v1 | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.392 | 0.297 | 0.095 [0.060, 0.130] | 0.000 | – |
| T3 | S@5 | 0.583 | 0.510 | 0.073 [0.037, 0.108] | 0.000 | – |
| T3 | MRR@10 | 0.471 | 0.386 | 0.085 [0.057, 0.114] | 0.000 | – |
| T3 | nDCG@10 | 0.511 | 0.433 | 0.078 [0.050, 0.105] | 0.000 | yes (lower 0.050) |
| T3 | R@10 | 0.637 | 0.582 | 0.055 [0.018, 0.092] | 0.002 | – |
| T3 | R@50 | 0.783 | 0.722 | 0.062 [0.028, 0.095] | 0.000 | yes (lower 0.028) |
| T3 | R@100 | 0.828 | 0.793 | 0.035 [0.003, 0.067] | 0.036 | – |
| T4 | S@1 | 0.178 | 0.175 | 0.003 [-0.034, 0.041] | 0.936 | – |
| T4 | S@5 | 0.334 | 0.344 | -0.009 [-0.047, 0.028] | 0.672 | – |
| T4 | MRR@10 | 0.254 | 0.248 | 0.006 [-0.024, 0.036] | 0.726 | – |
| T4 | nDCG@10 | 0.287 | 0.287 | 0.000 [-0.028, 0.030] | 0.983 | no (lower -0.028) |
| T4 | R@10 | 0.399 | 0.420 | -0.020 [-0.061, 0.020] | 0.321 | – |
| T4 | R@50 | 0.536 | 0.530 | 0.006 [-0.033, 0.045] | 0.755 | no (lower -0.033) |
| T4 | R@100 | 0.582 | 0.582 | 0.001 [-0.037, 0.038] | 1.000 | – |
| T4 | SetR@10 | 0.336 | 0.230 | 0.107 [0.022, 0.208] | 0.012 | – |
| overall | S@1 | 0.317 | 0.254 | 0.063 [0.038, 0.090] | 0.000 | – |
| overall | S@5 | 0.497 | 0.452 | 0.045 [0.018, 0.072] | 0.002 | – |
| overall | MRR@10 | 0.395 | 0.338 | 0.057 [0.037, 0.079] | 0.000 | – |
| overall | nDCG@10 | 0.433 | 0.382 | 0.051 [0.030, 0.072] | 0.000 | yes (lower 0.030) |
| overall | R@10 | 0.554 | 0.525 | 0.029 [0.002, 0.056] | 0.038 | – |
| overall | R@50 | 0.697 | 0.655 | 0.042 [0.017, 0.068] | 0.002 | yes (lower 0.017) |
| overall | R@100 | 0.743 | 0.720 | 0.023 [-0.001, 0.047] | 0.062 | – |
| overall | SetR@10 | 0.336 | 0.230 | 0.107 [0.024, 0.208] | 0.015 | – |
| T3+T4 | S@1 | 0.317 | 0.254 | 0.063 [0.037, 0.089] | 0.000 | – |
| T3+T4 | S@5 | 0.497 | 0.452 | 0.045 [0.018, 0.071] | 0.001 | – |
| T3+T4 | MRR@10 | 0.395 | 0.338 | 0.057 [0.036, 0.079] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.433 | 0.382 | 0.051 [0.030, 0.071] | 0.000 | yes (lower 0.030) |
| T3+T4 | R@10 | 0.554 | 0.525 | 0.029 [0.001, 0.056] | 0.040 | – |
| T3+T4 | R@50 | 0.697 | 0.655 | 0.042 [0.018, 0.068] | 0.000 | yes (lower 0.018) |
| T3+T4 | R@100 | 0.743 | 0.720 | 0.023 [-0.000, 0.047] | 0.053 | – |
| T3+T4 | SetR@10 | 0.336 | 0.230 | 0.107 [0.022, 0.208] | 0.015 | – |
| free_text | S@1 | 0.317 | 0.254 | 0.063 [0.037, 0.089] | 0.000 | – |
| free_text | S@5 | 0.497 | 0.452 | 0.045 [0.017, 0.071] | 0.001 | – |
| free_text | MRR@10 | 0.395 | 0.338 | 0.057 [0.036, 0.079] | 0.000 | – |
| free_text | nDCG@10 | 0.433 | 0.382 | 0.051 [0.030, 0.072] | 0.000 | yes (lower 0.030) |
| free_text | R@10 | 0.554 | 0.525 | 0.029 [0.002, 0.056] | 0.038 | – |
| free_text | R@50 | 0.697 | 0.655 | 0.042 [0.017, 0.068] | 0.001 | yes (lower 0.017) |
| free_text | R@100 | 0.743 | 0.720 | 0.023 [-0.001, 0.047] | 0.064 | – |
| free_text | SetR@10 | 0.336 | 0.230 | 0.107 [0.024, 0.208] | 0.014 | – |
| macro | S@1 | – | – | 0.049 [0.025, 0.074] | 0.000 | – |
| macro | S@5 | – | – | 0.032 [0.006, 0.058] | 0.016 | – |
| macro | MRR@10 | – | – | 0.045 [0.025, 0.066] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.039 [0.019, 0.059] | 0.000 | yes (lower 0.019) |
| macro | R@10 | – | – | 0.017 [-0.009, 0.044] | 0.205 | – |
| macro | R@50 | – | – | 0.034 [0.009, 0.059] | 0.006 | yes (lower 0.009) |
| macro | R@100 | – | – | 0.018 [-0.006, 0.042] | 0.151 | – |
| macro | SetR@10 | – | – | 0.107 [0.024, 0.210] | 0.012 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8670 unjudged (rate 0.9424) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.5541 [0.5219, 0.5859] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.3953 [0.3675, 0.4240] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 42.5237 [40.4640, 44.9974] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
