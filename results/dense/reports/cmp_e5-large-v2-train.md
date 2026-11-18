# Evaluation report: cmp_e5-large-v2 on train

**PROVISIONAL: 8627 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T20:55:43Z |
| Harness | b4-1 commit `c711bed3b1bded343e09f2c04e3f9e42f248ef54` |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_e5-large-v2-train.jsonl` sha256 `21bb93770336d617ac7dd6d6e117059f3393057984758098c60454182f2f1f52` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"index": "compare/e5-large-v2", "k": 100, "kinds": "all"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [22.39, 21.66, 21.46] -> [22.5, 21.87, 21.69] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "7d45c5c59e1656740bcb", "path": "/home/koushik.moram/team2/dense/qvec/qvec-7d45c5c59e1656740bcb.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.398 [0.360, 0.437] | 0.625 [0.587, 0.663] | 0.497 [0.462, 0.532] | 0.544 [0.510, 0.577] | 0.690 [0.652, 0.727] | 0.838 [0.808, 0.868] | 0.883 [0.857, 0.908] | – | 5584/6000 (0.931) |
| T4 | 320 | 0.184 [0.144, 0.228] | 0.362 [0.309, 0.416] | 0.262 [0.221, 0.305] | 0.302 [0.260, 0.345] | 0.439 [0.385, 0.493] | 0.560 [0.507, 0.614] | 0.607 [0.554, 0.660] | 0.286 [0.136, 0.446] | 3043/3200 (0.951) |
| **macro (slices)** | – | 0.291 [0.263, 0.320] | 0.494 [0.460, 0.527] | 0.380 [0.354, 0.407] | 0.423 [0.396, 0.451] | 0.565 [0.532, 0.598] | 0.699 [0.669, 0.730] | 0.745 [0.715, 0.775] | 0.286 [0.133, 0.453] | – |
| **overall** | 920 | 0.324 [0.295, 0.354] | 0.534 [0.502, 0.566] | 0.415 [0.388, 0.444] | 0.460 [0.432, 0.488] | 0.603 [0.571, 0.635] | 0.741 [0.713, 0.769] | 0.787 [0.761, 0.813] | 0.286 [0.136, 0.449] | 8627/9200 (0.938) |
| T3+T4 | 920 | 0.324 [0.295, 0.354] | 0.534 [0.502, 0.566] | 0.415 [0.388, 0.444] | 0.460 [0.432, 0.488] | 0.603 [0.572, 0.635] | 0.741 [0.714, 0.770] | 0.787 [0.762, 0.814] | 0.286 [0.135, 0.450] | 8627/9200 (0.938) |
| free_text | 920 | 0.324 [0.295, 0.354] | 0.534 [0.501, 0.566] | 0.415 [0.388, 0.444] | 0.460 [0.433, 0.487] | 0.603 [0.572, 0.633] | 0.741 [0.714, 0.768] | 0.787 [0.762, 0.813] | 0.286 [0.136, 0.454] | 8627/9200 (0.938) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5584 | 0.398 / 1.000 | 0.625 / 1.000 | 0.497 / 1.000 | 0.544 / 1.000 |
| T4 | 3043 | 0.184 / 1.000 | 0.362 / 1.000 | 0.262 / 1.000 | 0.302 / 0.999 |
| overall | 8627 | 0.324 / 1.000 | 0.534 / 1.000 | 0.415 / 1.000 | 0.460 / 1.000 |
| T3+T4 | 8627 | 0.324 / 1.000 | 0.534 / 1.000 | 0.415 / 1.000 | 0.460 / 1.000 |
| free_text | 8627 | 0.324 / 1.000 | 0.534 / 1.000 | 0.415 / 1.000 | 0.460 / 1.000 |

Pairs to judge: 8627 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 700 [692, 706] | 819 [805, 825] | 924 [870, 1091] | 1517 |
| T4 | 320 | 708 [700, 715] | 818 [797, 847] | 892 [849, 918] | 1076 |
| overall | 920 | 702 [695, 708] | 819 [807, 829] | 908 [876, 1038] | 1517 |
| T3+T4 | 920 | 702 [695, 708] | 819 [807, 829] | 908 [877, 1054] | 1517 |
| free_text | 920 | 702 [695, 708] | 819 [807, 829] | 908 [877, 1054] | 1517 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: cmp_e5-large-v2 - cmp_v1

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1-train.jsonl` (sha256 `0c5a13da1283207fb367eab3d1af09f276e2bfc4ea0ea97907754f5e8d3e0b6b`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | cmp_e5-large-v2 | cmp_v1 | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.398 | 0.297 | 0.102 [0.065, 0.138] | 0.000 | – |
| T3 | S@5 | 0.625 | 0.510 | 0.115 [0.077, 0.153] | 0.000 | – |
| T3 | MRR@10 | 0.497 | 0.386 | 0.112 [0.081, 0.142] | 0.000 | – |
| T3 | nDCG@10 | 0.544 | 0.433 | 0.111 [0.082, 0.140] | 0.000 | yes (lower 0.082) |
| T3 | R@10 | 0.690 | 0.582 | 0.108 [0.072, 0.145] | 0.000 | – |
| T3 | R@50 | 0.838 | 0.722 | 0.117 [0.083, 0.152] | 0.000 | yes (lower 0.083) |
| T3 | R@100 | 0.883 | 0.793 | 0.090 [0.058, 0.122] | 0.000 | – |
| T4 | S@1 | 0.184 | 0.175 | 0.009 [-0.031, 0.050] | 0.697 | – |
| T4 | S@5 | 0.362 | 0.344 | 0.019 [-0.031, 0.069] | 0.516 | – |
| T4 | MRR@10 | 0.262 | 0.248 | 0.014 [-0.022, 0.051] | 0.446 | – |
| T4 | nDCG@10 | 0.302 | 0.287 | 0.016 [-0.020, 0.051] | 0.383 | no (lower -0.020) |
| T4 | R@10 | 0.439 | 0.420 | 0.020 [-0.026, 0.067] | 0.415 | – |
| T4 | R@50 | 0.560 | 0.530 | 0.030 [-0.011, 0.072] | 0.157 | no (lower -0.011) |
| T4 | R@100 | 0.607 | 0.582 | 0.026 [-0.014, 0.065] | 0.209 | – |
| T4 | SetR@10 | 0.286 | 0.230 | 0.056 [-0.048, 0.176] | 0.334 | – |
| overall | S@1 | 0.324 | 0.254 | 0.070 [0.042, 0.098] | 0.000 | – |
| overall | S@5 | 0.534 | 0.452 | 0.082 [0.051, 0.112] | 0.000 | – |
| overall | MRR@10 | 0.415 | 0.338 | 0.078 [0.054, 0.102] | 0.000 | – |
| overall | nDCG@10 | 0.460 | 0.382 | 0.078 [0.055, 0.101] | 0.000 | yes (lower 0.055) |
| overall | R@10 | 0.603 | 0.525 | 0.077 [0.048, 0.106] | 0.000 | – |
| overall | R@50 | 0.741 | 0.655 | 0.087 [0.060, 0.114] | 0.000 | yes (lower 0.060) |
| overall | R@100 | 0.787 | 0.720 | 0.068 [0.043, 0.093] | 0.000 | – |
| overall | SetR@10 | 0.286 | 0.230 | 0.056 [-0.045, 0.179] | 0.323 | – |
| T3+T4 | S@1 | 0.324 | 0.254 | 0.070 [0.042, 0.097] | 0.000 | – |
| T3+T4 | S@5 | 0.534 | 0.452 | 0.082 [0.052, 0.112] | 0.000 | – |
| T3+T4 | MRR@10 | 0.415 | 0.338 | 0.078 [0.054, 0.101] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.460 | 0.382 | 0.078 [0.056, 0.101] | 0.000 | yes (lower 0.056) |
| T3+T4 | R@10 | 0.603 | 0.525 | 0.077 [0.049, 0.106] | 0.000 | – |
| T3+T4 | R@50 | 0.741 | 0.655 | 0.087 [0.061, 0.113] | 0.000 | yes (lower 0.061) |
| T3+T4 | R@100 | 0.787 | 0.720 | 0.068 [0.044, 0.093] | 0.000 | – |
| T3+T4 | SetR@10 | 0.286 | 0.230 | 0.056 [-0.045, 0.176] | 0.327 | – |
| free_text | S@1 | 0.324 | 0.254 | 0.070 [0.042, 0.098] | 0.000 | – |
| free_text | S@5 | 0.534 | 0.452 | 0.082 [0.051, 0.112] | 0.000 | – |
| free_text | MRR@10 | 0.415 | 0.338 | 0.078 [0.054, 0.102] | 0.000 | – |
| free_text | nDCG@10 | 0.460 | 0.382 | 0.078 [0.056, 0.101] | 0.000 | yes (lower 0.056) |
| free_text | R@10 | 0.603 | 0.525 | 0.077 [0.049, 0.107] | 0.000 | – |
| free_text | R@50 | 0.741 | 0.655 | 0.087 [0.060, 0.114] | 0.000 | yes (lower 0.060) |
| free_text | R@100 | 0.787 | 0.720 | 0.068 [0.043, 0.093] | 0.000 | – |
| free_text | SetR@10 | 0.286 | 0.230 | 0.056 [-0.044, 0.177] | 0.334 | – |
| macro | S@1 | – | – | 0.056 [0.029, 0.082] | 0.000 | – |
| macro | S@5 | – | – | 0.067 [0.036, 0.098] | 0.000 | – |
| macro | MRR@10 | – | – | 0.063 [0.039, 0.086] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.063 [0.041, 0.086] | 0.000 | yes (lower 0.041) |
| macro | R@10 | – | – | 0.064 [0.034, 0.094] | 0.000 | – |
| macro | R@50 | – | – | 0.073 [0.048, 0.100] | 0.000 | yes (lower 0.048) |
| macro | R@100 | – | – | 0.058 [0.033, 0.083] | 0.000 | – |
| macro | SetR@10 | – | – | 0.056 [-0.044, 0.178] | 0.327 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8627 unjudged (rate 0.9377) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.6028 [0.5716, 0.6350] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.4155 [0.3877, 0.4441] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 818.7207 [806.8384, 829.1033] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
