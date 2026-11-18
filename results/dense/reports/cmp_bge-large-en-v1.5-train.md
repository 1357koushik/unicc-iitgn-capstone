# Evaluation report: cmp_bge-large-en-v1.5 on train

**PROVISIONAL: 8638 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T19:42:57Z |
| Harness | b4-1 commit `403325fc1d07208ddb11938027df191f3acdc271` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_bge-large-en-v1.5-train.jsonl` sha256 `a09bef71b8ec40c0dd86d855904665e999dfbd736248b60675eecedfce96edee` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"index": "compare/bge-large-en-v1.5", "k": 100, "kinds": "all"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [20.31, 21.06, 20.66] -> [22.94, 22.36, 21.59] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "5f8a78190f1be41a1f6b", "path": "/home/koushik.moram/team2/dense/qvec/qvec-5f8a78190f1be41a1f6b.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.417 [0.378, 0.457] | 0.628 [0.592, 0.667] | 0.506 [0.471, 0.541] | 0.549 [0.516, 0.583] | 0.685 [0.648, 0.722] | 0.823 [0.792, 0.853] | 0.877 [0.850, 0.903] | – | 5588/6000 (0.931) |
| T4 | 320 | 0.188 [0.144, 0.231] | 0.384 [0.331, 0.438] | 0.270 [0.229, 0.312] | 0.307 [0.265, 0.349] | 0.430 [0.376, 0.483] | 0.564 [0.510, 0.617] | 0.629 [0.577, 0.681] | 0.237 [0.103, 0.386] | 3050/3200 (0.953) |
| **macro (slices)** | – | 0.302 [0.273, 0.332] | 0.506 [0.473, 0.540] | 0.388 [0.361, 0.415] | 0.428 [0.400, 0.456] | 0.557 [0.525, 0.590] | 0.693 [0.663, 0.724] | 0.753 [0.723, 0.783] | 0.237 [0.103, 0.389] | – |
| **overall** | 920 | 0.337 [0.308, 0.367] | 0.543 [0.512, 0.575] | 0.424 [0.396, 0.452] | 0.465 [0.437, 0.493] | 0.596 [0.565, 0.628] | 0.733 [0.705, 0.761] | 0.791 [0.764, 0.817] | 0.237 [0.106, 0.386] | 8638/9200 (0.939) |
| T3+T4 | 920 | 0.337 [0.307, 0.368] | 0.543 [0.511, 0.576] | 0.424 [0.395, 0.452] | 0.465 [0.437, 0.493] | 0.596 [0.565, 0.628] | 0.733 [0.704, 0.761] | 0.791 [0.764, 0.816] | 0.237 [0.103, 0.389] | 8638/9200 (0.939) |
| free_text | 920 | 0.337 [0.308, 0.368] | 0.543 [0.512, 0.575] | 0.424 [0.396, 0.452] | 0.465 [0.437, 0.493] | 0.596 [0.565, 0.627] | 0.733 [0.705, 0.760] | 0.791 [0.765, 0.816] | 0.237 [0.106, 0.388] | 8638/9200 (0.939) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5588 | 0.417 / 1.000 | 0.628 / 1.000 | 0.506 / 1.000 | 0.549 / 1.000 |
| T4 | 3050 | 0.188 / 1.000 | 0.384 / 1.000 | 0.270 / 1.000 | 0.307 / 0.999 |
| overall | 8638 | 0.337 / 1.000 | 0.543 / 1.000 | 0.424 / 1.000 | 0.465 / 1.000 |
| T3+T4 | 8638 | 0.337 / 1.000 | 0.543 / 1.000 | 0.424 / 1.000 | 0.465 / 1.000 |
| free_text | 8638 | 0.337 / 1.000 | 0.543 / 1.000 | 0.424 / 1.000 | 0.465 / 1.000 |

Pairs to judge: 8638 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 720 [716, 724] | 821 [812, 839] | 899 [858, 979] | 2587 |
| T4 | 320 | 726 [718, 730] | 828 [800, 842] | 907 [855, 977] | 1015 |
| overall | 920 | 722 [718, 726] | 824 [812, 838] | 908 [861, 966] | 2587 |
| T3+T4 | 920 | 722 [718, 726] | 824 [812, 838] | 908 [861, 966] | 2587 |
| free_text | 920 | 722 [718, 726] | 824 [812, 838] | 908 [860, 967] | 2587 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: cmp_bge-large-en-v1.5 - cmp_v1

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1-train.jsonl` (sha256 `0c5a13da1283207fb367eab3d1af09f276e2bfc4ea0ea97907754f5e8d3e0b6b`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | cmp_bge-large-en-v1.5 | cmp_v1 | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.417 | 0.297 | 0.120 [0.080, 0.162] | 0.000 | – |
| T3 | S@5 | 0.628 | 0.510 | 0.118 [0.080, 0.158] | 0.000 | – |
| T3 | MRR@10 | 0.506 | 0.386 | 0.120 [0.086, 0.153] | 0.000 | – |
| T3 | nDCG@10 | 0.549 | 0.433 | 0.117 [0.084, 0.148] | 0.000 | yes (lower 0.084) |
| T3 | R@10 | 0.685 | 0.582 | 0.103 [0.065, 0.143] | 0.000 | – |
| T3 | R@50 | 0.823 | 0.722 | 0.102 [0.065, 0.140] | 0.000 | yes (lower 0.065) |
| T3 | R@100 | 0.877 | 0.793 | 0.083 [0.048, 0.118] | 0.000 | – |
| T4 | S@1 | 0.188 | 0.175 | 0.013 [-0.028, 0.053] | 0.602 | – |
| T4 | S@5 | 0.384 | 0.344 | 0.041 [-0.009, 0.091] | 0.119 | – |
| T4 | MRR@10 | 0.270 | 0.248 | 0.022 [-0.015, 0.059] | 0.255 | – |
| T4 | nDCG@10 | 0.307 | 0.287 | 0.020 [-0.017, 0.057] | 0.296 | no (lower -0.017) |
| T4 | R@10 | 0.430 | 0.420 | 0.010 [-0.038, 0.058] | 0.712 | – |
| T4 | R@50 | 0.564 | 0.530 | 0.034 [-0.006, 0.075] | 0.104 | yes (lower -0.006) |
| T4 | R@100 | 0.629 | 0.582 | 0.047 [0.005, 0.090] | 0.030 | – |
| T4 | SetR@10 | 0.237 | 0.230 | 0.007 [-0.079, 0.101] | 0.963 | – |
| overall | S@1 | 0.337 | 0.254 | 0.083 [0.052, 0.113] | 0.000 | – |
| overall | S@5 | 0.543 | 0.452 | 0.091 [0.061, 0.122] | 0.000 | – |
| overall | MRR@10 | 0.424 | 0.338 | 0.086 [0.061, 0.111] | 0.000 | – |
| overall | nDCG@10 | 0.465 | 0.382 | 0.083 [0.059, 0.107] | 0.000 | yes (lower 0.059) |
| overall | R@10 | 0.596 | 0.525 | 0.071 [0.041, 0.101] | 0.000 | – |
| overall | R@50 | 0.733 | 0.655 | 0.078 [0.050, 0.107] | 0.000 | yes (lower 0.050) |
| overall | R@100 | 0.791 | 0.720 | 0.071 [0.044, 0.099] | 0.000 | – |
| overall | SetR@10 | 0.237 | 0.230 | 0.007 [-0.079, 0.103] | 0.955 | – |
| T3+T4 | S@1 | 0.337 | 0.254 | 0.083 [0.052, 0.113] | 0.000 | – |
| T3+T4 | S@5 | 0.543 | 0.452 | 0.091 [0.061, 0.123] | 0.000 | – |
| T3+T4 | MRR@10 | 0.424 | 0.338 | 0.086 [0.061, 0.112] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.465 | 0.382 | 0.083 [0.059, 0.108] | 0.000 | yes (lower 0.059) |
| T3+T4 | R@10 | 0.596 | 0.525 | 0.071 [0.041, 0.102] | 0.000 | – |
| T3+T4 | R@50 | 0.733 | 0.655 | 0.078 [0.050, 0.106] | 0.000 | yes (lower 0.050) |
| T3+T4 | R@100 | 0.791 | 0.720 | 0.071 [0.044, 0.098] | 0.000 | – |
| T3+T4 | SetR@10 | 0.237 | 0.230 | 0.007 [-0.079, 0.101] | 0.964 | – |
| free_text | S@1 | 0.337 | 0.254 | 0.083 [0.052, 0.113] | 0.000 | – |
| free_text | S@5 | 0.543 | 0.452 | 0.091 [0.061, 0.122] | 0.000 | – |
| free_text | MRR@10 | 0.424 | 0.338 | 0.086 [0.061, 0.111] | 0.000 | – |
| free_text | nDCG@10 | 0.465 | 0.382 | 0.083 [0.059, 0.108] | 0.000 | yes (lower 0.059) |
| free_text | R@10 | 0.596 | 0.525 | 0.071 [0.041, 0.101] | 0.000 | – |
| free_text | R@50 | 0.733 | 0.655 | 0.078 [0.050, 0.106] | 0.000 | yes (lower 0.050) |
| free_text | R@100 | 0.791 | 0.720 | 0.071 [0.044, 0.099] | 0.000 | – |
| free_text | SetR@10 | 0.237 | 0.230 | 0.007 [-0.079, 0.102] | 0.962 | – |
| macro | S@1 | – | – | 0.066 [0.037, 0.095] | 0.000 | – |
| macro | S@5 | – | – | 0.079 [0.048, 0.111] | 0.000 | – |
| macro | MRR@10 | – | – | 0.071 [0.046, 0.096] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.068 [0.044, 0.092] | 0.000 | yes (lower 0.044) |
| macro | R@10 | – | – | 0.057 [0.025, 0.088] | 0.000 | – |
| macro | R@50 | – | – | 0.068 [0.041, 0.095] | 0.000 | yes (lower 0.041) |
| macro | R@100 | – | – | 0.065 [0.038, 0.093] | 0.000 | – |
| macro | SetR@10 | – | – | 0.007 [-0.079, 0.103] | 0.946 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8638 unjudged (rate 0.9389) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.5961 [0.5646, 0.6279] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.4238 [0.3954, 0.4521] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 823.6991 [811.8019, 838.2541] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
