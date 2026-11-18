# Evaluation report: v2_served on train

**PROVISIONAL: 8518 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-18T03:20:37Z |
| Harness | b4-1 commit `e9588b3218ed5d5e41df47845e78e83a6413dfe0` |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `results\v2\runs\v2_served-train.jsonl` sha256 `e8f29f6858042909223701e146865bb735b8da5408addc9d38c09fa8ccb49c74` |
| Variant config | – |
| Server | – |
| Service health | – |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.478 [0.438, 0.518] | 0.720 [0.683, 0.757] | 0.587 [0.553, 0.620] | 0.641 [0.610, 0.673] | 0.815 [0.783, 0.845] | 0.905 [0.880, 0.928] | 0.930 [0.908, 0.950] | – | 5509/6000 (0.918) |
| T4 | 320 | 0.247 [0.200, 0.297] | 0.463 [0.409, 0.516] | 0.336 [0.292, 0.381] | 0.383 [0.339, 0.428] | 0.540 [0.486, 0.593] | 0.673 [0.622, 0.723] | 0.699 [0.649, 0.748] | 0.422 [0.252, 0.603] | 3009/3200 (0.940) |
| **macro (slices)** | – | 0.363 [0.333, 0.394] | 0.591 [0.559, 0.624] | 0.461 [0.433, 0.490] | 0.512 [0.485, 0.540] | 0.677 [0.646, 0.708] | 0.789 [0.761, 0.817] | 0.814 [0.787, 0.841] | 0.422 [0.249, 0.603] | – |
| **overall** | 920 | 0.398 [0.366, 0.429] | 0.630 [0.599, 0.662] | 0.499 [0.471, 0.528] | 0.551 [0.525, 0.578] | 0.719 [0.690, 0.748] | 0.824 [0.800, 0.849] | 0.850 [0.827, 0.872] | 0.422 [0.249, 0.596] | 8518/9200 (0.926) |
| T3+T4 | 920 | 0.398 [0.365, 0.430] | 0.630 [0.600, 0.662] | 0.499 [0.472, 0.528] | 0.551 [0.525, 0.579] | 0.719 [0.690, 0.748] | 0.824 [0.800, 0.848] | 0.850 [0.827, 0.872] | 0.422 [0.247, 0.601] | 8518/9200 (0.926) |
| free_text | 920 | 0.398 [0.366, 0.429] | 0.630 [0.599, 0.662] | 0.499 [0.472, 0.527] | 0.551 [0.525, 0.578] | 0.719 [0.690, 0.748] | 0.824 [0.800, 0.848] | 0.850 [0.826, 0.872] | 0.422 [0.251, 0.603] | 8518/9200 (0.926) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5509 | 0.478 / 1.000 | 0.720 / 1.000 | 0.587 / 1.000 | 0.641 / 1.000 |
| T4 | 3009 | 0.247 / 1.000 | 0.463 / 1.000 | 0.336 / 1.000 | 0.383 / 1.000 |
| overall | 8518 | 0.398 / 1.000 | 0.630 / 1.000 | 0.499 / 1.000 | 0.551 / 1.000 |
| T3+T4 | 8518 | 0.398 / 1.000 | 0.630 / 1.000 | 0.499 / 1.000 | 0.551 / 1.000 |
| free_text | 8518 | 0.398 / 1.000 | 0.630 / 1.000 | 0.499 / 1.000 | 0.551 / 1.000 |

Pairs to judge: 8518 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 1413 [1297, 1480] | 1799 [1786, 1817] | 1847 [1832, 1867] | 1891 |
| T4 | 320 | 1477 [1243, 1608] | 1824 [1806, 1835] | 1877 [1840, 1932] | 2043 |
| overall | 920 | 1434 [1349, 1487] | 1811 [1797, 1824] | 1856 [1839, 1878] | 2043 |
| T3+T4 | 920 | 1434 [1349, 1487] | 1811 [1797, 1824] | 1856 [1837, 1877] | 2043 |
| free_text | 920 | 1434 [1344, 1487] | 1811 [1797, 1824] | 1856 [1836, 1878] | 2043 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: v2_served - v2_fused_attack

Reference run `results\dense\runs\full\v2_fused_attack-train.jsonl` (sha256 `41ad71df7bbb4d964076c09d640e13f0d5d092af6ae1e1dc5a73b1259cfd176a`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_served | v2_fused_attack | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.478 | 0.480 | -0.002 [-0.013, 0.008] | 0.873 | – |
| T3 | S@5 | 0.720 | 0.717 | 0.003 [-0.003, 0.010] | 0.455 | – |
| T3 | MRR@10 | 0.587 | 0.588 | -0.001 [-0.007, 0.004] | 0.661 | – |
| T3 | nDCG@10 | 0.641 | 0.641 | 0.000 [-0.004, 0.005] | 0.966 | yes (lower -0.004) |
| T3 | R@10 | 0.815 | 0.810 | 0.005 [0.000, 0.012] | 0.105 | – |
| T3 | R@50 | 0.905 | 0.905 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| T3 | R@100 | 0.930 | 0.927 | 0.003 [0.000, 0.008] | 0.286 | – |
| T4 | S@1 | 0.247 | 0.250 | -0.003 [-0.019, 0.013] | 0.858 | – |
| T4 | S@5 | 0.463 | 0.450 | 0.013 [0.003, 0.025] | 0.039 | – |
| T4 | MRR@10 | 0.336 | 0.332 | 0.004 [-0.006, 0.014] | 0.473 | – |
| T4 | nDCG@10 | 0.383 | 0.378 | 0.005 [-0.003, 0.013] | 0.191 | yes (lower -0.003) |
| T4 | R@10 | 0.540 | 0.526 | 0.014 [0.003, 0.028] | 0.013 | – |
| T4 | R@50 | 0.673 | 0.667 | 0.006 [-0.006, 0.019] | 0.454 | yes (lower -0.006) |
| T4 | R@100 | 0.699 | 0.696 | 0.003 [0.000, 0.009] | 0.747 | – |
| T4 | SetR@10 | 0.422 | 0.400 | 0.022 [0.000, 0.071] | 0.736 | – |
| overall | S@1 | 0.398 | 0.400 | -0.002 [-0.011, 0.007] | 0.710 | – |
| overall | S@5 | 0.630 | 0.624 | 0.007 [0.001, 0.013] | 0.037 | – |
| overall | MRR@10 | 0.499 | 0.499 | 0.000 [-0.005, 0.006] | 0.865 | – |
| overall | nDCG@10 | 0.551 | 0.550 | 0.002 [-0.002, 0.006] | 0.375 | yes (lower -0.002) |
| overall | R@10 | 0.719 | 0.711 | 0.008 [0.003, 0.015] | 0.001 | – |
| overall | R@50 | 0.824 | 0.822 | 0.002 [-0.002, 0.007] | 0.460 | yes (lower -0.002) |
| overall | R@100 | 0.850 | 0.846 | 0.003 [0.000, 0.008] | 0.103 | – |
| overall | SetR@10 | 0.422 | 0.400 | 0.022 [0.000, 0.071] | 0.746 | – |
| T3+T4 | S@1 | 0.398 | 0.400 | -0.002 [-0.011, 0.007] | 0.717 | – |
| T3+T4 | S@5 | 0.630 | 0.624 | 0.007 [0.001, 0.013] | 0.034 | – |
| T3+T4 | MRR@10 | 0.499 | 0.499 | 0.000 [-0.005, 0.006] | 0.872 | – |
| T3+T4 | nDCG@10 | 0.551 | 0.550 | 0.002 [-0.002, 0.006] | 0.364 | yes (lower -0.002) |
| T3+T4 | R@10 | 0.719 | 0.711 | 0.008 [0.003, 0.014] | 0.001 | – |
| T3+T4 | R@50 | 0.824 | 0.822 | 0.002 [-0.002, 0.007] | 0.456 | yes (lower -0.002) |
| T3+T4 | R@100 | 0.850 | 0.846 | 0.003 [0.000, 0.008] | 0.100 | – |
| T3+T4 | SetR@10 | 0.422 | 0.400 | 0.022 [0.000, 0.074] | 0.736 | – |
| free_text | S@1 | 0.398 | 0.400 | -0.002 [-0.011, 0.007] | 0.728 | – |
| free_text | S@5 | 0.630 | 0.624 | 0.007 [0.001, 0.013] | 0.031 | – |
| free_text | MRR@10 | 0.499 | 0.499 | 0.000 [-0.005, 0.006] | 0.870 | – |
| free_text | nDCG@10 | 0.551 | 0.550 | 0.002 [-0.002, 0.006] | 0.366 | yes (lower -0.002) |
| free_text | R@10 | 0.719 | 0.711 | 0.008 [0.003, 0.015] | 0.001 | – |
| free_text | R@50 | 0.824 | 0.822 | 0.002 [-0.002, 0.007] | 0.454 | yes (lower -0.002) |
| free_text | R@100 | 0.850 | 0.846 | 0.003 [0.000, 0.008] | 0.104 | – |
| free_text | SetR@10 | 0.422 | 0.400 | 0.022 [0.000, 0.071] | 0.742 | – |
| macro | S@1 | – | – | -0.002 [-0.012, 0.007] | 0.643 | – |
| macro | S@5 | – | – | 0.008 [0.002, 0.016] | 0.014 | – |
| macro | MRR@10 | – | – | 0.001 [-0.004, 0.007] | 0.702 | – |
| macro | nDCG@10 | – | – | 0.003 [-0.002, 0.007] | 0.261 | yes (lower -0.002) |
| macro | R@10 | – | – | 0.010 [0.003, 0.017] | 0.001 | – |
| macro | R@50 | – | – | 0.003 [-0.003, 0.009] | 0.458 | yes (lower -0.003) |
| macro | R@100 | – | – | 0.003 [0.000, 0.008] | 0.099 | – |
| macro | SetR@10 | – | – | 0.022 [0.000, 0.071] | 0.738 | – |

## Comparison: v2_served - v2_full

Reference run `results\v2\runs\v2_full-train.jsonl` (sha256 `d0d8a27fa8f65496dad6cbab04203207056eab3715a60deb7262ed11c61c7ebd`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_served | v2_full | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.478 | 0.363 | 0.115 [0.078, 0.152] | 0.000 | – |
| T3 | S@5 | 0.720 | 0.645 | 0.075 [0.045, 0.107] | 0.000 | – |
| T3 | MRR@10 | 0.587 | 0.486 | 0.100 [0.074, 0.127] | 0.000 | – |
| T3 | nDCG@10 | 0.641 | 0.563 | 0.078 [0.058, 0.098] | 0.000 | yes (lower 0.058) |
| T3 | R@10 | 0.815 | 0.815 | 0.000 [0.000, 0.000] | 1.000 | – |
| T3 | R@50 | 0.905 | 0.905 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| T3 | R@100 | 0.930 | 0.930 | 0.000 [0.000, 0.000] | 1.000 | – |
| T4 | S@1 | 0.247 | 0.191 | 0.056 [0.009, 0.103] | 0.021 | – |
| T4 | S@5 | 0.463 | 0.428 | 0.034 [-0.006, 0.075] | 0.109 | – |
| T4 | MRR@10 | 0.336 | 0.293 | 0.042 [0.009, 0.077] | 0.015 | – |
| T4 | nDCG@10 | 0.383 | 0.348 | 0.035 [0.010, 0.061] | 0.007 | yes (lower 0.010) |
| T4 | R@10 | 0.540 | 0.540 | 0.000 [0.000, 0.000] | 1.000 | – |
| T4 | R@50 | 0.673 | 0.673 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| T4 | R@100 | 0.699 | 0.699 | 0.000 [0.000, 0.000] | 1.000 | – |
| T4 | SetR@10 | 0.422 | 0.422 | 0.000 [0.000, 0.000] | 1.000 | – |
| overall | S@1 | 0.398 | 0.303 | 0.095 [0.065, 0.124] | 0.000 | – |
| overall | S@5 | 0.630 | 0.570 | 0.061 [0.036, 0.085] | 0.000 | – |
| overall | MRR@10 | 0.499 | 0.419 | 0.080 [0.059, 0.101] | 0.000 | – |
| overall | nDCG@10 | 0.551 | 0.488 | 0.063 [0.047, 0.079] | 0.000 | yes (lower 0.047) |
| overall | R@10 | 0.719 | 0.719 | 0.000 [0.000, 0.000] | 1.000 | – |
| overall | R@50 | 0.824 | 0.824 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| overall | R@100 | 0.850 | 0.850 | 0.000 [0.000, 0.000] | 1.000 | – |
| overall | SetR@10 | 0.422 | 0.422 | 0.000 [0.000, 0.000] | 1.000 | – |
| T3+T4 | S@1 | 0.398 | 0.303 | 0.095 [0.065, 0.124] | 0.000 | – |
| T3+T4 | S@5 | 0.630 | 0.570 | 0.061 [0.037, 0.085] | 0.000 | – |
| T3+T4 | MRR@10 | 0.499 | 0.419 | 0.080 [0.059, 0.101] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.551 | 0.488 | 0.063 [0.047, 0.079] | 0.000 | yes (lower 0.047) |
| T3+T4 | R@10 | 0.719 | 0.719 | 0.000 [0.000, 0.000] | 1.000 | – |
| T3+T4 | R@50 | 0.824 | 0.824 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| T3+T4 | R@100 | 0.850 | 0.850 | 0.000 [0.000, 0.000] | 1.000 | – |
| T3+T4 | SetR@10 | 0.422 | 0.422 | 0.000 [0.000, 0.000] | 1.000 | – |
| free_text | S@1 | 0.398 | 0.303 | 0.095 [0.066, 0.125] | 0.000 | – |
| free_text | S@5 | 0.630 | 0.570 | 0.061 [0.037, 0.086] | 0.000 | – |
| free_text | MRR@10 | 0.499 | 0.419 | 0.080 [0.060, 0.102] | 0.000 | – |
| free_text | nDCG@10 | 0.551 | 0.488 | 0.063 [0.048, 0.079] | 0.000 | yes (lower 0.048) |
| free_text | R@10 | 0.719 | 0.719 | 0.000 [0.000, 0.000] | 1.000 | – |
| free_text | R@50 | 0.824 | 0.824 | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| free_text | R@100 | 0.850 | 0.850 | 0.000 [0.000, 0.000] | 1.000 | – |
| free_text | SetR@10 | 0.422 | 0.422 | 0.000 [0.000, 0.000] | 1.000 | – |
| macro | S@1 | – | – | 0.086 [0.055, 0.116] | 0.000 | – |
| macro | S@5 | – | – | 0.055 [0.029, 0.080] | 0.000 | – |
| macro | MRR@10 | – | – | 0.071 [0.050, 0.093] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.056 [0.040, 0.073] | 0.000 | yes (lower 0.040) |
| macro | R@10 | – | – | 0.000 [0.000, 0.000] | 1.000 | – |
| macro | R@50 | – | – | 0.000 [0.000, 0.000] | 1.000 | yes (lower 0.000) |
| macro | R@100 | – | – | 0.000 [0.000, 0.000] | 1.000 | – |
| macro | SetR@10 | – | – | 0.000 [0.000, 0.000] | 1.000 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8518 unjudged (rate 0.9259) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.7192 [0.6903, 0.7484] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.4994 [0.4718, 0.5281] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 1811.4486 [1796.7297, 1823.7150] | <= 3000 | target 1000 ms not met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
