# Evaluation report: cmp_v1_v1query on train

**PROVISIONAL: 8734 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:23:30Z |
| Harness | b4-1 commit `403325fc1d07208ddb11938027df191f3acdc271` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1_v1query-train.jsonl` sha256 `e450ba4c2fe474d43f590ff9d4641d6a0e23d53437f58cddfe681202f71ffe2c` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"index": "compare/v1", "k": 100, "kinds": "all", "query_format": "v1"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [23.75, 24.25, 22.62] -> [24.86, 24.24, 22.92] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "800acba353680e1f4bdc", "path": "/home/koushik.moram/team2/dense/qvec/qvec-800acba353680e1f4bdc.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.300 [0.263, 0.338] | 0.478 [0.438, 0.518] | 0.376 [0.342, 0.411] | 0.419 [0.385, 0.453] | 0.558 [0.518, 0.598] | 0.715 [0.678, 0.752] | 0.757 [0.722, 0.792] | – | 5665/6000 (0.944) |
| T4 | 320 | 0.172 [0.131, 0.216] | 0.322 [0.272, 0.375] | 0.231 [0.191, 0.273] | 0.262 [0.221, 0.305] | 0.366 [0.316, 0.418] | 0.517 [0.463, 0.571] | 0.571 [0.517, 0.624] | 0.228 [0.091, 0.381] | 3069/3200 (0.959) |
| **macro (slices)** | – | 0.236 [0.208, 0.263] | 0.400 [0.368, 0.432] | 0.304 [0.277, 0.331] | 0.341 [0.313, 0.369] | 0.462 [0.429, 0.495] | 0.616 [0.583, 0.649] | 0.664 [0.631, 0.696] | 0.228 [0.091, 0.386] | – |
| **overall** | 920 | 0.255 [0.227, 0.284] | 0.424 [0.392, 0.455] | 0.326 [0.299, 0.353] | 0.365 [0.338, 0.391] | 0.492 [0.459, 0.524] | 0.646 [0.614, 0.676] | 0.692 [0.661, 0.721] | 0.228 [0.092, 0.382] | 8734/9200 (0.949) |
| T3+T4 | 920 | 0.255 [0.227, 0.284] | 0.424 [0.391, 0.457] | 0.326 [0.298, 0.353] | 0.365 [0.337, 0.392] | 0.492 [0.459, 0.525] | 0.646 [0.615, 0.678] | 0.692 [0.662, 0.722] | 0.228 [0.094, 0.385] | 8734/9200 (0.949) |
| free_text | 920 | 0.255 [0.227, 0.285] | 0.424 [0.392, 0.457] | 0.326 [0.298, 0.354] | 0.365 [0.337, 0.392] | 0.492 [0.460, 0.524] | 0.646 [0.616, 0.677] | 0.692 [0.662, 0.722] | 0.228 [0.092, 0.385] | 8734/9200 (0.949) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5665 | 0.300 / 1.000 | 0.478 / 1.000 | 0.376 / 1.000 | 0.419 / 1.000 |
| T4 | 3069 | 0.172 / 1.000 | 0.322 / 1.000 | 0.231 / 1.000 | 0.262 / 0.999 |
| overall | 8734 | 0.255 / 1.000 | 0.424 / 1.000 | 0.326 / 1.000 | 0.365 / 1.000 |
| T3+T4 | 8734 | 0.255 / 1.000 | 0.424 / 1.000 | 0.326 / 1.000 | 0.365 / 1.000 |
| free_text | 8734 | 0.255 / 1.000 | 0.424 / 1.000 | 0.326 / 1.000 | 0.365 / 1.000 |

Pairs to judge: 8734 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 26 [25, 26] | 79 [61, 83] | 110 [96, 121] | 375 |
| T4 | 320 | 27 [26, 27] | 41 [37, 73] | 91 [73, 103] | 104 |
| overall | 920 | 26 [26, 27] | 72 [43, 81] | 104 [95, 114] | 375 |
| T3+T4 | 920 | 26 [26, 27] | 72 [46, 79] | 104 [95, 114] | 375 |
| free_text | 920 | 26 [26, 27] | 72 [44, 81] | 104 [95, 114] | 375 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: cmp_v1_v1query - cmp_v1

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1-train.jsonl` (sha256 `0c5a13da1283207fb367eab3d1af09f276e2bfc4ea0ea97907754f5e8d3e0b6b`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | cmp_v1_v1query | cmp_v1 | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.300 | 0.297 | 0.003 [-0.023, 0.030] | 0.853 | – |
| T3 | S@5 | 0.478 | 0.510 | -0.032 [-0.058, -0.005] | 0.021 | – |
| T3 | MRR@10 | 0.376 | 0.386 | -0.010 [-0.029, 0.010] | 0.326 | – |
| T3 | nDCG@10 | 0.419 | 0.433 | -0.013 [-0.031, 0.004] | 0.140 | no (lower -0.031) |
| T3 | R@10 | 0.558 | 0.582 | -0.023 [-0.047, 0.000] | 0.061 | – |
| T3 | R@50 | 0.715 | 0.722 | -0.007 [-0.030, 0.017] | 0.630 | no (lower -0.030) |
| T3 | R@100 | 0.757 | 0.793 | -0.037 [-0.062, -0.010] | 0.008 | – |
| T4 | S@1 | 0.172 | 0.175 | -0.003 [-0.028, 0.022] | 0.886 | – |
| T4 | S@5 | 0.322 | 0.344 | -0.022 [-0.056, 0.013] | 0.251 | – |
| T4 | MRR@10 | 0.231 | 0.248 | -0.017 [-0.038, 0.003] | 0.091 | – |
| T4 | nDCG@10 | 0.262 | 0.287 | -0.025 [-0.047, -0.004] | 0.018 | no (lower -0.047) |
| T4 | R@10 | 0.366 | 0.420 | -0.053 [-0.091, -0.016] | 0.004 | – |
| T4 | R@50 | 0.517 | 0.530 | -0.013 [-0.043, 0.017] | 0.420 | no (lower -0.043) |
| T4 | R@100 | 0.571 | 0.582 | -0.011 [-0.039, 0.017] | 0.454 | – |
| T4 | SetR@10 | 0.228 | 0.230 | -0.002 [-0.031, 0.025] | 0.951 | – |
| overall | S@1 | 0.255 | 0.254 | 0.001 [-0.018, 0.021] | 0.954 | – |
| overall | S@5 | 0.424 | 0.452 | -0.028 [-0.049, -0.007] | 0.008 | – |
| overall | MRR@10 | 0.326 | 0.338 | -0.012 [-0.026, 0.002] | 0.096 | – |
| overall | nDCG@10 | 0.365 | 0.382 | -0.017 [-0.031, -0.004] | 0.011 | no (lower -0.031) |
| overall | R@10 | 0.492 | 0.525 | -0.034 [-0.054, -0.013] | 0.001 | – |
| overall | R@50 | 0.646 | 0.655 | -0.009 [-0.028, 0.010] | 0.380 | no (lower -0.028) |
| overall | R@100 | 0.692 | 0.720 | -0.028 [-0.047, -0.008] | 0.005 | – |
| overall | SetR@10 | 0.228 | 0.230 | -0.002 [-0.031, 0.025] | 0.969 | – |
| T3+T4 | S@1 | 0.255 | 0.254 | 0.001 [-0.018, 0.021] | 0.964 | – |
| T3+T4 | S@5 | 0.424 | 0.452 | -0.028 [-0.049, -0.008] | 0.009 | – |
| T3+T4 | MRR@10 | 0.326 | 0.338 | -0.012 [-0.027, 0.002] | 0.099 | – |
| T3+T4 | nDCG@10 | 0.365 | 0.382 | -0.017 [-0.031, -0.004] | 0.013 | no (lower -0.031) |
| T3+T4 | R@10 | 0.492 | 0.525 | -0.034 [-0.054, -0.013] | 0.001 | – |
| T3+T4 | R@50 | 0.646 | 0.655 | -0.009 [-0.028, 0.010] | 0.367 | no (lower -0.028) |
| T3+T4 | R@100 | 0.692 | 0.720 | -0.028 [-0.047, -0.008] | 0.004 | – |
| T3+T4 | SetR@10 | 0.228 | 0.230 | -0.002 [-0.032, 0.025] | 0.962 | – |
| free_text | S@1 | 0.255 | 0.254 | 0.001 [-0.017, 0.020] | 0.949 | – |
| free_text | S@5 | 0.424 | 0.452 | -0.028 [-0.049, -0.008] | 0.011 | – |
| free_text | MRR@10 | 0.326 | 0.338 | -0.012 [-0.027, 0.002] | 0.096 | – |
| free_text | nDCG@10 | 0.365 | 0.382 | -0.017 [-0.031, -0.004] | 0.011 | no (lower -0.031) |
| free_text | R@10 | 0.492 | 0.525 | -0.034 [-0.054, -0.013] | 0.001 | – |
| free_text | R@50 | 0.646 | 0.655 | -0.009 [-0.028, 0.010] | 0.375 | no (lower -0.028) |
| free_text | R@100 | 0.692 | 0.720 | -0.028 [-0.047, -0.008] | 0.005 | – |
| free_text | SetR@10 | 0.228 | 0.230 | -0.002 [-0.031, 0.025] | 0.967 | – |
| macro | S@1 | – | – | 0.000 [-0.018, 0.018] | 1.000 | – |
| macro | S@5 | – | – | -0.027 [-0.049, -0.005] | 0.018 | – |
| macro | MRR@10 | – | – | -0.013 [-0.027, 0.001] | 0.062 | – |
| macro | nDCG@10 | – | – | -0.019 [-0.033, -0.005] | 0.008 | no (lower -0.033) |
| macro | R@10 | – | – | -0.038 [-0.061, -0.016] | 0.001 | – |
| macro | R@50 | – | – | -0.010 [-0.029, 0.009] | 0.314 | no (lower -0.029) |
| macro | R@100 | – | – | -0.024 [-0.043, -0.005] | 0.012 | – |
| macro | SetR@10 | – | – | -0.002 [-0.031, 0.024] | 0.962 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8734 unjudged (rate 0.9493) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.4916 [0.4591, 0.5249] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.3256 [0.2981, 0.3531] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 72.4845 [43.5835, 80.6094] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
