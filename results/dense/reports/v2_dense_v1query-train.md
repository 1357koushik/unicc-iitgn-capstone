# Evaluation report: v2_dense_v1query on train

**PROVISIONAL: 8813 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:23:56Z |
| Harness | b4-1 commit `403325fc1d07208ddb11938027df191f3acdc271` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\v2_dense_v1query-train.jsonl` sha256 `eb9b754a2a34cb0c7b1cb199324feb7c5cfa1f1df09bb1937518280abad88ccf` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"k": 100, "kinds": "cve", "query_format": "v1"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [16.77, 20.67, 21.94] -> [23.49, 24.23, 22.58] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "800acba353680e1f4bdc", "path": "/home/koushik.moram/team2/dense/qvec/qvec-800acba353680e1f4bdc.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.235 [0.202, 0.270] | 0.398 [0.360, 0.437] | 0.304 [0.272, 0.338] | 0.343 [0.310, 0.376] | 0.465 [0.425, 0.505] | 0.630 [0.592, 0.668] | 0.687 [0.648, 0.723] | – | 5721/6000 (0.954) |
| T4 | 320 | 0.122 [0.087, 0.159] | 0.250 [0.203, 0.300] | 0.176 [0.141, 0.214] | 0.207 [0.169, 0.246] | 0.306 [0.256, 0.358] | 0.438 [0.384, 0.491] | 0.507 [0.453, 0.561] | 0.167 [0.050, 0.307] | 3092/3200 (0.966) |
| **macro (slices)** | – | 0.178 [0.154, 0.203] | 0.324 [0.294, 0.355] | 0.240 [0.217, 0.265] | 0.275 [0.250, 0.301] | 0.385 [0.354, 0.417] | 0.534 [0.501, 0.567] | 0.597 [0.563, 0.630] | 0.167 [0.047, 0.307] | – |
| **overall** | 920 | 0.196 [0.171, 0.222] | 0.347 [0.316, 0.377] | 0.260 [0.235, 0.285] | 0.295 [0.270, 0.321] | 0.410 [0.378, 0.441] | 0.563 [0.531, 0.595] | 0.624 [0.592, 0.655] | 0.167 [0.050, 0.309] | 8813/9200 (0.958) |
| T3+T4 | 920 | 0.196 [0.170, 0.222] | 0.347 [0.315, 0.378] | 0.260 [0.234, 0.285] | 0.295 [0.269, 0.321] | 0.410 [0.377, 0.442] | 0.563 [0.531, 0.596] | 0.624 [0.593, 0.656] | 0.167 [0.049, 0.308] | 8813/9200 (0.958) |
| free_text | 920 | 0.196 [0.171, 0.222] | 0.347 [0.316, 0.378] | 0.260 [0.235, 0.285] | 0.295 [0.270, 0.321] | 0.410 [0.378, 0.442] | 0.563 [0.532, 0.595] | 0.624 [0.594, 0.655] | 0.167 [0.048, 0.306] | 8813/9200 (0.958) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5721 | 0.235 / 1.000 | 0.398 / 1.000 | 0.304 / 1.000 | 0.343 / 1.000 |
| T4 | 3092 | 0.122 / 1.000 | 0.250 / 1.000 | 0.176 / 1.000 | 0.207 / 1.000 |
| overall | 8813 | 0.196 / 1.000 | 0.347 / 1.000 | 0.260 / 1.000 | 0.295 / 1.000 |
| T3+T4 | 8813 | 0.196 / 1.000 | 0.347 / 1.000 | 0.260 / 1.000 | 0.295 / 1.000 |
| free_text | 8813 | 0.196 / 1.000 | 0.347 / 1.000 | 0.260 / 1.000 | 0.295 / 1.000 |

Pairs to judge: 8813 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 771 [738, 807] | 1363 [1324, 1415] | 1632 [1449, 1971] | 6532 |
| T4 | 320 | 1152 [1114, 1175] | 1449 [1400, 1538] | 1775 [1576, 2018] | 2557 |
| overall | 920 | 987 [956, 1008] | 1402 [1367, 1442] | 1727 [1579, 1947] | 6532 |
| T3+T4 | 920 | 987 [956, 1008] | 1402 [1365, 1442] | 1727 [1579, 1961] | 6532 |
| free_text | 920 | 987 [956, 1008] | 1402 [1367, 1442] | 1727 [1577, 1961] | 6532 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: v2_dense_v1query - v2_dense

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\v2_dense-train.jsonl` (sha256 `2ae29c9d1c2d65fdf5669bd895d5fd3105cdaca598acd13d7844ea353dfb35d8`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_dense_v1query | v2_dense | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.235 | 0.227 | 0.008 [-0.015, 0.032] | 0.532 | – |
| T3 | S@5 | 0.398 | 0.423 | -0.025 [-0.052, 0.002] | 0.071 | – |
| T3 | MRR@10 | 0.304 | 0.310 | -0.006 [-0.025, 0.013] | 0.529 | – |
| T3 | nDCG@10 | 0.343 | 0.354 | -0.012 [-0.030, 0.006] | 0.206 | no (lower -0.030) |
| T3 | R@10 | 0.465 | 0.493 | -0.028 [-0.053, -0.003] | 0.029 | – |
| T3 | R@50 | 0.630 | 0.640 | -0.010 [-0.033, 0.013] | 0.468 | no (lower -0.033) |
| T3 | R@100 | 0.687 | 0.695 | -0.008 [-0.032, 0.017] | 0.536 | – |
| T4 | S@1 | 0.122 | 0.134 | -0.013 [-0.037, 0.013] | 0.378 | – |
| T4 | S@5 | 0.250 | 0.263 | -0.013 [-0.044, 0.019] | 0.473 | – |
| T4 | MRR@10 | 0.176 | 0.190 | -0.013 [-0.032, 0.004] | 0.134 | – |
| T4 | nDCG@10 | 0.207 | 0.225 | -0.018 [-0.038, -0.000] | 0.046 | no (lower -0.038) |
| T4 | R@10 | 0.306 | 0.346 | -0.041 [-0.080, -0.005] | 0.031 | – |
| T4 | R@50 | 0.438 | 0.469 | -0.031 [-0.064, 0.001] | 0.059 | no (lower -0.064) |
| T4 | R@100 | 0.507 | 0.518 | -0.011 [-0.044, 0.021] | 0.509 | – |
| T4 | SetR@10 | 0.167 | 0.123 | 0.043 [0.000, 0.109] | 0.269 | – |
| overall | S@1 | 0.196 | 0.195 | 0.001 [-0.016, 0.018] | 0.961 | – |
| overall | S@5 | 0.347 | 0.367 | -0.021 [-0.041, 0.000] | 0.060 | – |
| overall | MRR@10 | 0.260 | 0.268 | -0.009 [-0.022, 0.005] | 0.225 | – |
| overall | nDCG@10 | 0.295 | 0.309 | -0.014 [-0.027, -0.001] | 0.041 | no (lower -0.027) |
| overall | R@10 | 0.410 | 0.442 | -0.033 [-0.054, -0.012] | 0.003 | – |
| overall | R@50 | 0.563 | 0.580 | -0.017 [-0.036, 0.002] | 0.075 | no (lower -0.036) |
| overall | R@100 | 0.624 | 0.634 | -0.009 [-0.029, 0.010] | 0.362 | – |
| overall | SetR@10 | 0.167 | 0.123 | 0.043 [0.000, 0.111] | 0.265 | – |
| T3+T4 | S@1 | 0.196 | 0.195 | 0.001 [-0.016, 0.018] | 0.965 | – |
| T3+T4 | S@5 | 0.347 | 0.367 | -0.021 [-0.041, 0.000] | 0.057 | – |
| T3+T4 | MRR@10 | 0.260 | 0.268 | -0.009 [-0.022, 0.005] | 0.219 | – |
| T3+T4 | nDCG@10 | 0.295 | 0.309 | -0.014 [-0.027, -0.001] | 0.039 | no (lower -0.027) |
| T3+T4 | R@10 | 0.410 | 0.442 | -0.033 [-0.054, -0.012] | 0.002 | – |
| T3+T4 | R@50 | 0.563 | 0.580 | -0.017 [-0.036, 0.002] | 0.078 | no (lower -0.036) |
| T3+T4 | R@100 | 0.624 | 0.634 | -0.009 [-0.029, 0.010] | 0.343 | – |
| T3+T4 | SetR@10 | 0.167 | 0.123 | 0.043 [0.000, 0.109] | 0.272 | – |
| free_text | S@1 | 0.196 | 0.195 | 0.001 [-0.016, 0.018] | 0.943 | – |
| free_text | S@5 | 0.347 | 0.367 | -0.021 [-0.040, 0.000] | 0.056 | – |
| free_text | MRR@10 | 0.260 | 0.268 | -0.009 [-0.022, 0.005] | 0.224 | – |
| free_text | nDCG@10 | 0.295 | 0.309 | -0.014 [-0.027, -0.001] | 0.036 | no (lower -0.027) |
| free_text | R@10 | 0.410 | 0.442 | -0.033 [-0.053, -0.012] | 0.002 | – |
| free_text | R@50 | 0.563 | 0.580 | -0.017 [-0.036, 0.002] | 0.081 | no (lower -0.036) |
| free_text | R@100 | 0.624 | 0.634 | -0.009 [-0.028, 0.010] | 0.349 | – |
| free_text | SetR@10 | 0.167 | 0.123 | 0.043 [0.000, 0.111] | 0.265 | – |
| macro | S@1 | – | – | -0.002 [-0.019, 0.015] | 0.804 | – |
| macro | S@5 | – | – | -0.019 [-0.040, 0.002] | 0.070 | – |
| macro | MRR@10 | – | – | -0.010 [-0.023, 0.003] | 0.145 | – |
| macro | nDCG@10 | – | – | -0.015 [-0.028, -0.002] | 0.023 | no (lower -0.028) |
| macro | R@10 | – | – | -0.034 [-0.057, -0.012] | 0.002 | – |
| macro | R@50 | – | – | -0.020 [-0.041, -0.001] | 0.043 | no (lower -0.041) |
| macro | R@100 | – | – | -0.010 [-0.030, 0.010] | 0.352 | – |
| macro | SetR@10 | – | – | 0.043 [0.000, 0.109] | 0.263 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8813 unjudged (rate 0.9579) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.4096 [0.3774, 0.4417] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.2598 [0.2343, 0.2849] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 1402.3291 [1366.5199, 1441.8809] | <= 3000 | target 1000 ms not met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
