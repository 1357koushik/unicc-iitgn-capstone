# Evaluation report: v2_fused_attack on dev

**PROVISIONAL: 539 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-18T06:20:17Z |
| Harness | b4-1 commit `6e96ce378a131db0ac47ed06f7aef5b3b5071340` |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files not verified against manifest) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `51de6d3666201eac1af7cdca2a9e819821ed16e154c24670257b61c79d62fdea` |
| Run file | `results\dense\runs\full\v2_fused_attack-dev.jsonl` sha256 `96b9e85367fce8819faf2269c7032e69701474209d7c832ddb66d34f76385c70` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_fused", "options": {"candidates": 100, "depth": 100, "k": 100, "kinds": "all", "rrf_k": 1, "weights": [1.0, 0.25]}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [9.37, 10.53, 16.4] -> [23.52, 18.01, 17.99] |
| Service health | `{"candidates": 100, "component": "fused", "dense": {"blas": {"blas": [{"internal_api": "openblas", "num_threads": 12, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 12, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 12}, "cache_size": 4096, "disk_cache": {"identity": "5f8a78190f1be41a1f6b", "path": "/home/koushik.moram/team2/dense/qvec/qvec-5f8a78190f1be41` |
| Split / slices | dev / all |
| Queries | 1489 evaluated of 1489 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['ndcg@10', 'success@1'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T0 | 106 | 0.632 [0.538, 0.726] | 0.821 [0.745, 0.887] | 0.718 [0.644, 0.791] | 0.667 [0.610, 0.723] | 0.763 [0.701, 0.822] | 0.869 [0.818, 0.915] | 0.906 [0.860, 0.947] | 0.714 [0.646, 0.781] | 86/1060 (0.081) |
| T1 | 150 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0/1500 (0.000) |
| T2 | 99 | 0.566 [0.465, 0.667] | 0.697 [0.606, 0.788] | 0.618 [0.528, 0.704] | 0.617 [0.533, 0.697] | 0.685 [0.593, 0.772] | 0.797 [0.719, 0.872] | 0.832 [0.757, 0.901] | 0.617 [0.412, 0.812] | 53/990 (0.054) |
| T3 | 300 | 0.643 [0.590, 0.697] | 0.833 [0.790, 0.873] | 0.730 [0.687, 0.772] | 0.825 [0.801, 0.847] | 0.860 [0.826, 0.892] | 0.950 [0.927, 0.970] | 0.969 [0.950, 0.985] | 0.880 [0.849, 0.909] | 136/3000 (0.045) |
| T4 | 160 | 0.512 [0.438, 0.588] | 0.694 [0.625, 0.762] | 0.599 [0.533, 0.665] | 0.645 [0.598, 0.691] | 0.706 [0.650, 0.761] | 0.837 [0.785, 0.885] | 0.860 [0.810, 0.905] | 0.757 [0.706, 0.808] | 85/1600 (0.053) |
| T5 | 120 | 0.558 [0.475, 0.642] | 0.883 [0.825, 0.942] | 0.682 [0.613, 0.748] | 0.790 [0.744, 0.832] | 0.864 [0.805, 0.918] | 0.954 [0.915, 0.987] | 0.979 [0.952, 0.998] | 0.857 [0.772, 0.931] | 25/1200 (0.021) |
| T6 | 154 | 0.435 [0.357, 0.513] | 0.623 [0.545, 0.701] | 0.520 [0.450, 0.589] | 0.554 [0.495, 0.611] | 0.645 [0.578, 0.711] | 0.730 [0.663, 0.793] | 0.771 [0.706, 0.830] | 0.757 [0.688, 0.823] | 59/1540 (0.038) |
| T7 | 0 | – | – | – | – | – | – | – | – | 0/0 |
| T8 | 120 | 0.558 [0.467, 0.650] | 0.825 [0.758, 0.892] | 0.665 [0.595, 0.733] | 0.725 [0.678, 0.770] | 0.915 [0.870, 0.955] | 0.969 [0.936, 0.994] | 0.982 [0.955, 1.000] | 0.882 [0.817, 0.941] | 39/1200 (0.033) |
| T9 | 120 | 0.542 [0.450, 0.633] | 0.725 [0.642, 0.800] | 0.623 [0.546, 0.702] | 0.655 [0.589, 0.722] | 0.607 [0.525, 0.689] | 0.620 [0.540, 0.700] | 0.638 [0.558, 0.717] | 0.429 [0.330, 0.529] | 56/1200 (0.047) |
| **macro (slices)** | – | 0.605 [0.578, 0.631] | 0.789 [0.767, 0.811] | 0.684 [0.662, 0.706] | 0.720 [0.702, 0.737] | 0.783 [0.763, 0.802] | 0.858 [0.841, 0.876] | 0.882 [0.865, 0.897] | 0.766 [0.736, 0.795] | – |
| **overall** | 1329 | 0.612 [0.586, 0.639] | 0.794 [0.772, 0.816] | 0.691 [0.669, 0.713] | 0.736 [0.719, 0.753] | 0.794 [0.775, 0.813] | 0.871 [0.854, 0.888] | 0.893 [0.878, 0.909] | 0.763 [0.737, 0.788] | 539/13290 (0.041) |
| temporal_holdout | 73 | 0.534 [0.425, 0.644] | 0.822 [0.726, 0.904] | 0.648 [0.557, 0.738] | 0.776 [0.714, 0.834] | 0.863 [0.789, 0.927] | 0.965 [0.927, 0.993] | 0.978 [0.945, 1.000] | 0.846 [0.753, 0.930] | 13/730 (0.018) |
| T3+T4 | 460 | 0.598 [0.552, 0.643] | 0.785 [0.746, 0.822] | 0.685 [0.646, 0.722] | 0.762 [0.738, 0.785] | 0.806 [0.776, 0.836] | 0.911 [0.887, 0.933] | 0.931 [0.909, 0.951] | 0.831 [0.802, 0.859] | 221/4600 (0.048) |
| T9_id_name | 45 | 0.911 [0.822, 0.978] | 1.000 [1.000, 1.000] | 0.944 [0.889, 0.989] | 0.933 [0.888, 0.971] | 0.981 [0.952, 1.000] | 0.993 [0.978, 1.000] | 0.993 [0.978, 1.000] | 0.936 [0.833, 1.000] | 13/450 (0.029) |
| free_text | 1179 | 0.563 [0.535, 0.591] | 0.768 [0.743, 0.791] | 0.652 [0.628, 0.675] | 0.702 [0.684, 0.720] | 0.768 [0.746, 0.789] | 0.855 [0.836, 0.872] | 0.880 [0.862, 0.897] | 0.753 [0.727, 0.779] | 539/11790 (0.046) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T0 | 86 | 0.632 / 0.660 | 0.821 / 0.840 | 0.718 / 0.743 | 0.667 / 0.683 |
| T2 | 53 | 0.566 / 0.667 | 0.697 / 0.758 | 0.618 / 0.707 | 0.617 / 0.685 |
| T3 | 136 | 0.643 / 0.663 | 0.833 / 0.843 | 0.730 / 0.747 | 0.825 / 0.834 |
| T4 | 85 | 0.512 / 0.569 | 0.694 / 0.750 | 0.599 / 0.658 | 0.645 / 0.687 |
| T5 | 25 | 0.558 / 0.558 | 0.883 / 0.883 | 0.682 / 0.682 | 0.790 / 0.779 |
| T6 | 59 | 0.435 / 0.474 | 0.623 / 0.636 | 0.520 / 0.555 | 0.554 / 0.576 |
| T8 | 39 | 0.558 / 0.567 | 0.825 / 0.833 | 0.665 / 0.680 | 0.725 / 0.726 |
| T9 | 56 | 0.542 / 0.542 | 0.725 / 0.742 | 0.623 / 0.646 | 0.655 / 0.658 |
| overall | 539 | 0.612 / 0.639 | 0.794 / 0.813 | 0.691 / 0.718 | 0.736 / 0.751 |
| temporal_holdout | 13 | 0.534 / 0.534 | 0.822 / 0.822 | 0.648 / 0.648 | 0.776 / 0.768 |
| T3+T4 | 221 | 0.598 / 0.630 | 0.785 / 0.811 | 0.685 / 0.716 | 0.762 / 0.783 |
| T9_id_name | 13 | 0.911 / 0.911 | 1.000 / 1.000 | 0.944 / 0.944 | 0.933 / 0.907 |
| free_text | 539 | 0.563 / 0.593 | 0.768 / 0.789 | 0.652 / 0.682 | 0.702 / 0.720 |

Pairs to judge: 539 (export with `python -m benchmarks_v2.eval pool`).

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
| T0 | 106 | 73 [58, 80] | 169 [133, 283] | 289 [170, 456] | 456 |
| T1 | 150 | 42 [40, 43] | 93 [65, 99] | 112 [96, 126] | 126 |
| T2 | 99 | 42 [41, 42] | 71 [48, 92] | 93 [71, 101] | 101 |
| T3 | 300 | 44 [43, 45] | 61 [55, 87] | 98 [92, 105] | 110 |
| T4 | 160 | 42 [41, 43] | 88 [52, 98] | 103 [95, 237] | 237 |
| T5 | 120 | 43 [42, 44] | 57 [52, 96] | 105 [58, 184] | 184 |
| T6 | 154 | 46 [45, 48] | 94 [86, 106] | 110 [96, 114] | 114 |
| T7 | 160 | 41 [40, 42] | 69 [49, 79] | 96 [75, 107] | 107 |
| T8 | 120 | 43 [42, 44] | 69 [50, 93] | 94 [71, 97] | 97 |
| T9 | 120 | 41 [40, 42] | 53 [48, 90] | 95 [58, 101] | 101 |
| overall | 1489 | 43 [43, 43] | 94 [91, 98] | 129 [114, 160] | 456 |
| temporal_holdout | 73 | 42 [41, 45] | 75 [54, 95] | 109 [68, 143] | 143 |
| T3+T4 | 460 | 43 [43, 44] | 82 [57, 92] | 100 [96, 109] | 237 |
| T9_id_name | 45 | 40 [38, 42] | 51 [45, 99] | 96 [48, 101] | 101 |
| free_text | 1339 | 43 [43, 43] | 94 [91, 99] | 133 [116, 169] | 456 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | ndcg@10 | 154 | 0 | -0.137 [-0.191, -0.085] | 0.000 |
| T6_vs_clean | success@1 | 154 | 0 | -0.130 [-0.208, -0.052] | 0.002 |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 3, FAIL 7, MISSING 6, NOT_APPLICABLE 9, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 539 unjudged (rate 0.0406) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **PASS** | 1.0000 [1.0000, 1.0000] | >= 1.0 |  |
| T9_id_name_success1 | T9_id_name | **FAIL** | 0.9111 [0.8222, 0.9778] | >= 1.0 |  |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **FAIL** | 0.6970 [0.6061, 0.7879] | >= 0.9, lower >= 0.85 |  |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.8064 [0.7764, 0.8356] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.6845 [0.6464, 0.7216] | >= 0.75 |  |
| T6_within5_ndcg | T6 | **FAIL** | diff -0.1373 [-0.1909, -0.0850] | diff >= -0.05 |  |
| T6_within5_success1 | T6 | **FAIL** | diff -0.1299 [-0.2078, -0.0519] | diff >= -0.05 |  |
| T8_success1 | T8 | **FAIL** | 0.5583 [0.4667, 0.6500] | >= 0.8 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 94.3803 [90.6048, 98.5383] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |

## Warnings

- manifest lists no sha256 for qrels_with_round1_all.jsonl; not verified
- 1 equivalence units have members judged with different grades (the maximum grade is used)
