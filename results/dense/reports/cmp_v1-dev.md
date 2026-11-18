# Evaluation report: cmp_v1 on dev

**PROVISIONAL: 12467 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T15:50:54Z |
| Harness | b4-1 commit `32a50b73da90374291fe86aecab1ff73d291c3d5` |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1-dev.jsonl` sha256 `bbc1309096012c08a9e64a3d5d701a1f6af81a03f221c2ff2dcf308ad78460f3` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"index": "compare/v1", "k": 100, "kinds": "all"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [23.65, 23.28, 22.62] -> [23.8, 23.4, 22.8] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "1e1fde3b6bc046dc7049", "path": "/home/koushik.moram/team2/dense/qvec/qvec-1e1fde3b6bc046dc7049.sqlite"}, "encoder": {"bat` |
| Split / slices | dev / all |
| Queries | 1489 evaluated of 1489 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T0 | 106 | 0.217 [0.142, 0.302] | 0.283 [0.198, 0.368] | 0.245 [0.170, 0.326] | 0.223 [0.155, 0.297] | 0.281 [0.203, 0.366] | 0.384 [0.298, 0.475] | 0.390 [0.303, 0.481] | 0.166 [0.086, 0.260] | 1010/1060 (0.953) |
| T1 | 150 | 0.080 [0.040, 0.127] | 0.153 [0.100, 0.213] | 0.108 [0.066, 0.156] | 0.125 [0.081, 0.172] | 0.187 [0.127, 0.250] | 0.282 [0.213, 0.353] | 0.356 [0.281, 0.433] | 0.043 [0.000, 0.111] | 1471/1500 (0.981) |
| T2 | 99 | 0.131 [0.071, 0.202] | 0.182 [0.111, 0.263] | 0.156 [0.093, 0.225] | 0.174 [0.108, 0.244] | 0.232 [0.152, 0.313] | 0.303 [0.212, 0.394] | 0.313 [0.222, 0.404] | 0.000 [0.000, 0.000] | 967/990 (0.977) |
| T3 | 300 | 0.277 [0.227, 0.327] | 0.473 [0.417, 0.530] | 0.359 [0.312, 0.408] | 0.403 [0.356, 0.452] | 0.543 [0.487, 0.600] | 0.703 [0.653, 0.753] | 0.760 [0.713, 0.807] | – | 2837/3000 (0.946) |
| T4 | 160 | 0.175 [0.119, 0.237] | 0.412 [0.338, 0.487] | 0.273 [0.217, 0.330] | 0.319 [0.262, 0.376] | 0.490 [0.413, 0.566] | 0.626 [0.550, 0.699] | 0.691 [0.616, 0.759] | 0.458 [0.245, 0.675] | 1512/1600 (0.945) |
| T5 | 120 | 0.283 [0.208, 0.367] | 0.467 [0.375, 0.558] | 0.357 [0.284, 0.435] | 0.376 [0.307, 0.448] | 0.489 [0.403, 0.574] | 0.655 [0.571, 0.736] | 0.702 [0.622, 0.779] | 0.379 [0.253, 0.511] | 1058/1200 (0.882) |
| T6 | 154 | 0.156 [0.104, 0.214] | 0.253 [0.188, 0.325] | 0.199 [0.144, 0.258] | 0.216 [0.161, 0.274] | 0.310 [0.238, 0.383] | 0.411 [0.333, 0.488] | 0.454 [0.376, 0.530] | 0.161 [0.036, 0.311] | 1482/1540 (0.962) |
| T7 | 0 | – | – | – | – | – | – | – | – | 0/0 |
| T8 | 120 | 0.258 [0.183, 0.342] | 0.442 [0.350, 0.533] | 0.328 [0.255, 0.404] | 0.373 [0.299, 0.449] | 0.517 [0.425, 0.608] | 0.642 [0.558, 0.725] | 0.675 [0.592, 0.758] | – | 930/1200 (0.775) |
| T9 | 120 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 1200/1200 (1.000) |
| **macro (slices)** | – | 0.175 [0.154, 0.196] | 0.296 [0.273, 0.320] | 0.225 [0.205, 0.245] | 0.245 [0.226, 0.265] | 0.339 [0.315, 0.363] | 0.445 [0.421, 0.470] | 0.482 [0.458, 0.507] | 0.173 [0.129, 0.216] | – |
| **overall** | 1329 | 0.187 [0.166, 0.207] | 0.321 [0.297, 0.347] | 0.242 [0.222, 0.263] | 0.267 [0.247, 0.288] | 0.369 [0.344, 0.395] | 0.484 [0.458, 0.511] | 0.526 [0.500, 0.553] | 0.161 [0.120, 0.206] | 12467/13290 (0.938) |
| temporal_holdout | 73 | 0.096 [0.027, 0.164] | 0.164 [0.082, 0.247] | 0.119 [0.055, 0.191] | 0.131 [0.067, 0.201] | 0.171 [0.089, 0.260] | 0.240 [0.151, 0.342] | 0.260 [0.164, 0.363] | 0.031 [0.000, 0.104] | 695/730 (0.952) |
| T3+T4 | 460 | 0.241 [0.202, 0.280] | 0.452 [0.407, 0.498] | 0.329 [0.292, 0.367] | 0.374 [0.337, 0.411] | 0.525 [0.480, 0.570] | 0.676 [0.633, 0.718] | 0.736 [0.695, 0.776] | 0.458 [0.243, 0.676] | 4349/4600 (0.945) |
| T9_id_name | 45 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | – | 450/450 (1.000) |
| free_text | 1179 | 0.200 [0.178, 0.223] | 0.343 [0.316, 0.370] | 0.259 [0.237, 0.282] | 0.285 [0.263, 0.307] | 0.392 [0.365, 0.419] | 0.510 [0.481, 0.538] | 0.548 [0.520, 0.576] | 0.176 [0.131, 0.226] | 10996/11790 (0.933) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T0 | 1010 | 0.217 / 1.000 | 0.283 / 1.000 | 0.245 / 1.000 | 0.223 / 0.998 |
| T1 | 1471 | 0.080 / 1.000 | 0.153 / 1.000 | 0.108 / 1.000 | 0.125 / 1.000 |
| T2 | 967 | 0.131 / 1.000 | 0.182 / 1.000 | 0.156 / 1.000 | 0.174 / 1.000 |
| T3 | 2837 | 0.277 / 1.000 | 0.473 / 1.000 | 0.359 / 1.000 | 0.403 / 1.000 |
| T4 | 1512 | 0.175 / 1.000 | 0.412 / 1.000 | 0.273 / 1.000 | 0.319 / 1.000 |
| T5 | 1058 | 0.283 / 0.917 | 0.467 / 1.000 | 0.357 / 0.954 | 0.376 / 0.974 |
| T6 | 1482 | 0.156 / 0.994 | 0.253 / 1.000 | 0.199 / 0.997 | 0.216 / 0.998 |
| T8 | 930 | 0.258 / 0.875 | 0.442 / 0.983 | 0.328 / 0.918 | 0.373 / 0.912 |
| T9 | 1200 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| overall | 12467 | 0.187 / 0.980 | 0.321 / 0.998 | 0.242 / 0.988 | 0.267 / 0.989 |
| temporal_holdout | 695 | 0.096 / 0.918 | 0.164 / 1.000 | 0.119 / 0.951 | 0.131 / 0.972 |
| T3+T4 | 4349 | 0.241 / 1.000 | 0.452 / 1.000 | 0.329 / 1.000 | 0.374 / 1.000 |
| T9_id_name | 450 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| free_text | 10996 | 0.200 / 0.978 | 0.343 / 0.998 | 0.259 / 0.987 | 0.285 / 0.988 |

Pairs to judge: 12467 (export with `python -m benchmarks_v2.eval pool`).

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
| T0 | 106 | 28 [27, 29] | 91 [78, 103] | 109 [92, 393] | 393 |
| T1 | 150 | 23 [22, 24] | 67 [35, 84] | 99 [78, 104] | 104 |
| T2 | 99 | 23 [21, 25] | 36 [32, 63] | 74 [36, 109] | 109 |
| T3 | 300 | 24 [23, 26] | 36 [34, 41] | 79 [43, 97] | 99 |
| T4 | 160 | 23 [22, 25] | 37 [33, 40] | 73 [38, 98] | 98 |
| T5 | 120 | 28 [26, 30] | 42 [36, 76] | 76 [42, 95] | 95 |
| T6 | 154 | 28 [27, 29] | 41 [38, 45] | 80 [42, 93] | 93 |
| T7 | 160 | 21 [21, 22] | 33 [32, 35] | 35 [34, 74] | 74 |
| T8 | 120 | 27 [25, 29] | 40 [37, 58] | 78 [40, 107] | 107 |
| T9 | 120 | 22 [22, 23] | 35 [33, 39] | 64 [36, 101] | 101 |
| overall | 1489 | 24 [23, 25] | 40 [38, 42] | 93 [82, 98] | 393 |
| temporal_holdout | 73 | 26 [24, 28] | 41 [34, 58] | 62 [40, 71] | 71 |
| T3+T4 | 460 | 24 [23, 25] | 36 [35, 38] | 75 [45, 97] | 99 |
| T9_id_name | 45 | 22 [21, 23] | 34 [30, 38] | 37 [33, 39] | 39 |
| free_text | 1339 | 25 [24, 26] | 39 [37, 42] | 91 [79, 97] | 393 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | ndcg@10 | 154 | 0 | -0.057 [-0.089, -0.027] | 0.000 |
| T6_vs_clean | success@1 | 154 | 0 | -0.045 [-0.084, -0.013] | 0.016 |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 3, FAIL 7, MISSING 6, NOT_APPLICABLE 9, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 12467 unjudged (rate 0.9381) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **FAIL** | 0.0800 [0.0400, 0.1267] | >= 1.0 |  |
| T9_id_name_success1 | T9_id_name | **FAIL** | 0.0000 [0.0000, 0.0000] | >= 1.0 |  |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **FAIL** | 0.1818 [0.1111, 0.2626] | >= 0.9, lower >= 0.85 |  |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.5248 [0.4795, 0.5699] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.3292 [0.2923, 0.3670] | >= 0.75 |  |
| T6_within5_ndcg | T6 | **FAIL** | diff -0.0572 [-0.0892, -0.0274] | diff >= -0.05 |  |
| T6_within5_success1 | T6 | **PASS** | diff -0.0455 [-0.0844, -0.0130] | diff >= -0.05 |  |
| T8_success1 | T8 | **FAIL** | 0.2583 [0.1833, 0.3417] | >= 0.8 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 39.4416 [37.4293, 41.6286] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |

## Warnings

- 1 equivalence units have members judged with different grades (the maximum grade is used)
