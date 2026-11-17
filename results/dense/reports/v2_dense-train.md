# Evaluation report: v2_dense on train

**PROVISIONAL: 8783 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:21:19Z |
| Harness | b4-1 commit `32a50b73da90374291fe86aecab1ff73d291c3d5` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\v2_dense-train.jsonl` sha256 `2ae29c9d1c2d65fdf5669bd895d5fd3105cdaca598acd13d7844ea353dfb35d8` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"k": 100, "kinds": "cve"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [23.17, 23.26, 22.83] -> [22.43, 22.31, 22.54] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "1e1fde3b6bc046dc7049", "path": "/home/koushik.moram/team2/dense/qvec/qvec-1e1fde3b6bc046dc7049.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.227 [0.193, 0.262] | 0.423 [0.385, 0.463] | 0.310 [0.278, 0.343] | 0.354 [0.322, 0.387] | 0.493 [0.453, 0.533] | 0.640 [0.602, 0.678] | 0.695 [0.658, 0.732] | – | 5703/6000 (0.951) |
| T4 | 320 | 0.134 [0.097, 0.172] | 0.263 [0.216, 0.312] | 0.190 [0.153, 0.228] | 0.225 [0.186, 0.264] | 0.346 [0.294, 0.400] | 0.469 [0.414, 0.522] | 0.518 [0.464, 0.573] | 0.123 [0.015, 0.260] | 3080/3200 (0.963) |
| **macro (slices)** | – | 0.181 [0.156, 0.206] | 0.343 [0.312, 0.374] | 0.250 [0.227, 0.275] | 0.290 [0.264, 0.316] | 0.420 [0.387, 0.453] | 0.554 [0.521, 0.587] | 0.607 [0.573, 0.639] | 0.123 [0.015, 0.263] | – |
| **overall** | 920 | 0.195 [0.170, 0.220] | 0.367 [0.337, 0.398] | 0.268 [0.244, 0.293] | 0.309 [0.284, 0.334] | 0.442 [0.410, 0.474] | 0.580 [0.548, 0.612] | 0.634 [0.603, 0.664] | 0.123 [0.016, 0.260] | 8783/9200 (0.955) |
| T3+T4 | 920 | 0.195 [0.170, 0.221] | 0.367 [0.336, 0.399] | 0.268 [0.243, 0.293] | 0.309 [0.284, 0.335] | 0.442 [0.410, 0.475] | 0.580 [0.548, 0.613] | 0.634 [0.602, 0.665] | 0.123 [0.016, 0.260] | 8783/9200 (0.955) |
| free_text | 920 | 0.195 [0.170, 0.221] | 0.367 [0.336, 0.398] | 0.268 [0.244, 0.294] | 0.309 [0.284, 0.335] | 0.442 [0.410, 0.474] | 0.580 [0.549, 0.612] | 0.634 [0.603, 0.665] | 0.123 [0.014, 0.263] | 8783/9200 (0.955) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5703 | 0.227 / 1.000 | 0.423 / 1.000 | 0.310 / 1.000 | 0.354 / 1.000 |
| T4 | 3080 | 0.134 / 1.000 | 0.263 / 1.000 | 0.190 / 1.000 | 0.225 / 0.999 |
| overall | 8783 | 0.195 / 1.000 | 0.367 / 1.000 | 0.268 / 1.000 | 0.309 / 1.000 |
| T3+T4 | 8783 | 0.195 / 1.000 | 0.367 / 1.000 | 0.268 / 1.000 | 0.309 / 1.000 |
| free_text | 8783 | 0.195 / 1.000 | 0.367 / 1.000 | 0.268 / 1.000 | 0.309 / 1.000 |

Pairs to judge: 8783 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 721 [713, 730] | 851 [835, 865] | 991 [906, 1242] | 1638 |
| T4 | 320 | 716 [697, 726] | 813 [797, 839] | 872 [839, 880] | 887 |
| overall | 920 | 720 [712, 726] | 839 [827, 852] | 936 [880, 1064] | 1638 |
| T3+T4 | 920 | 720 [713, 726] | 839 [827, 852] | 936 [880, 1064] | 1638 |
| free_text | 920 | 720 [712, 726] | 839 [827, 852] | 936 [880, 1064] | 1638 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: v2_dense - v1_hybrid

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\eval\runs\v1_hybrid-train.jsonl` (sha256 `208a6b201644b1392bed892b52dd74faa33f21c52a63f7b02c47831712408602`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_dense | v1_hybrid | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.227 | 0.287 | -0.060 [-0.090, -0.030] | 0.000 | – |
| T3 | S@5 | 0.423 | 0.473 | -0.050 [-0.085, -0.015] | 0.006 | – |
| T3 | MRR@10 | 0.310 | 0.366 | -0.056 [-0.082, -0.029] | 0.000 | – |
| T3 | nDCG@10 | 0.354 | 0.414 | -0.060 [-0.084, -0.034] | 0.000 | no (lower -0.084) |
| T3 | R@10 | 0.493 | 0.568 | -0.075 [-0.108, -0.040] | 0.000 | – |
| T3 | R@50 | 0.640 | 0.568 | 0.072 [0.040, 0.105] | 0.000 | yes (lower 0.040) |
| T3 | R@100 | 0.695 | 0.568 | 0.127 [0.095, 0.160] | 0.000 | – |
| T4 | S@1 | 0.134 | 0.147 | -0.013 [-0.044, 0.016] | 0.470 | – |
| T4 | S@5 | 0.263 | 0.325 | -0.062 [-0.106, -0.019] | 0.005 | – |
| T4 | MRR@10 | 0.190 | 0.219 | -0.029 [-0.055, -0.004] | 0.022 | – |
| T4 | nDCG@10 | 0.225 | 0.256 | -0.030 [-0.056, -0.005] | 0.016 | no (lower -0.056) |
| T4 | R@10 | 0.346 | 0.376 | -0.030 [-0.070, 0.010] | 0.150 | – |
| T4 | R@50 | 0.469 | 0.376 | 0.092 [0.051, 0.135] | 0.000 | yes (lower 0.051) |
| T4 | R@100 | 0.518 | 0.376 | 0.142 [0.098, 0.188] | 0.000 | – |
| T4 | SetR@10 | 0.123 | 0.146 | -0.023 [-0.093, 0.048] | 0.526 | – |
| overall | S@1 | 0.195 | 0.238 | -0.043 [-0.066, -0.022] | 0.000 | – |
| overall | S@5 | 0.367 | 0.422 | -0.054 [-0.083, -0.027] | 0.000 | – |
| overall | MRR@10 | 0.268 | 0.315 | -0.046 [-0.066, -0.027] | 0.000 | – |
| overall | nDCG@10 | 0.309 | 0.359 | -0.049 [-0.069, -0.031] | 0.000 | no (lower -0.069) |
| overall | R@10 | 0.442 | 0.501 | -0.059 [-0.086, -0.033] | 0.000 | – |
| overall | R@50 | 0.580 | 0.501 | 0.079 [0.053, 0.105] | 0.000 | yes (lower 0.053) |
| overall | R@100 | 0.634 | 0.501 | 0.132 [0.106, 0.159] | 0.000 | – |
| overall | SetR@10 | 0.123 | 0.146 | -0.023 [-0.094, 0.047] | 0.511 | – |
| T3+T4 | S@1 | 0.195 | 0.238 | -0.043 [-0.066, -0.022] | 0.000 | – |
| T3+T4 | S@5 | 0.367 | 0.422 | -0.054 [-0.082, -0.028] | 0.000 | – |
| T3+T4 | MRR@10 | 0.268 | 0.315 | -0.046 [-0.066, -0.027] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.309 | 0.359 | -0.049 [-0.068, -0.031] | 0.000 | no (lower -0.068) |
| T3+T4 | R@10 | 0.442 | 0.501 | -0.059 [-0.085, -0.032] | 0.000 | – |
| T3+T4 | R@50 | 0.580 | 0.501 | 0.079 [0.053, 0.105] | 0.000 | yes (lower 0.053) |
| T3+T4 | R@100 | 0.634 | 0.501 | 0.132 [0.106, 0.159] | 0.000 | – |
| T3+T4 | SetR@10 | 0.123 | 0.146 | -0.023 [-0.094, 0.048] | 0.519 | – |
| free_text | S@1 | 0.195 | 0.238 | -0.043 [-0.066, -0.022] | 0.000 | – |
| free_text | S@5 | 0.367 | 0.422 | -0.054 [-0.083, -0.026] | 0.000 | – |
| free_text | MRR@10 | 0.268 | 0.315 | -0.046 [-0.066, -0.027] | 0.000 | – |
| free_text | nDCG@10 | 0.309 | 0.359 | -0.049 [-0.068, -0.031] | 0.000 | no (lower -0.068) |
| free_text | R@10 | 0.442 | 0.501 | -0.059 [-0.086, -0.033] | 0.000 | – |
| free_text | R@50 | 0.580 | 0.501 | 0.079 [0.052, 0.105] | 0.000 | yes (lower 0.052) |
| free_text | R@100 | 0.634 | 0.501 | 0.132 [0.105, 0.158] | 0.000 | – |
| free_text | SetR@10 | 0.123 | 0.146 | -0.023 [-0.097, 0.047] | 0.506 | – |
| macro | S@1 | – | – | -0.036 [-0.057, -0.015] | 0.001 | – |
| macro | S@5 | – | – | -0.056 [-0.084, -0.029] | 0.000 | – |
| macro | MRR@10 | – | – | -0.042 [-0.061, -0.024] | 0.000 | – |
| macro | nDCG@10 | – | – | -0.045 [-0.063, -0.027] | 0.000 | no (lower -0.063) |
| macro | R@10 | – | – | -0.052 [-0.079, -0.026] | 0.000 | – |
| macro | R@50 | – | – | 0.082 [0.056, 0.109] | 0.000 | yes (lower 0.056) |
| macro | R@100 | – | – | 0.134 [0.106, 0.163] | 0.000 | – |
| macro | SetR@10 | – | – | -0.023 [-0.094, 0.047] | 0.518 | – |

## Comparison: v2_dense - v2_lexical

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\v2_lexical-train.jsonl` (sha256 `1cce2566fce371b0b8ce393dcf3d73fd12bec8da0ad07fe10d2f2924da672766`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_dense | v2_lexical | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.227 | 0.480 | -0.253 [-0.297, -0.212] | 0.000 | – |
| T3 | S@5 | 0.423 | 0.710 | -0.287 [-0.330, -0.243] | 0.000 | – |
| T3 | MRR@10 | 0.310 | 0.582 | -0.272 [-0.308, -0.236] | 0.000 | – |
| T3 | nDCG@10 | 0.354 | 0.631 | -0.277 [-0.312, -0.242] | 0.000 | no (lower -0.312) |
| T3 | R@10 | 0.493 | 0.787 | -0.293 [-0.337, -0.250] | 0.000 | – |
| T3 | R@50 | 0.640 | 0.883 | -0.243 [-0.285, -0.203] | 0.000 | no (lower -0.285) |
| T3 | R@100 | 0.695 | 0.902 | -0.207 [-0.247, -0.168] | 0.000 | – |
| T4 | S@1 | 0.134 | 0.250 | -0.116 [-0.169, -0.066] | 0.000 | – |
| T4 | S@5 | 0.263 | 0.456 | -0.194 [-0.253, -0.134] | 0.000 | – |
| T4 | MRR@10 | 0.190 | 0.331 | -0.141 [-0.189, -0.095] | 0.000 | – |
| T4 | nDCG@10 | 0.225 | 0.373 | -0.148 [-0.195, -0.101] | 0.000 | no (lower -0.195) |
| T4 | R@10 | 0.346 | 0.506 | -0.159 [-0.218, -0.099] | 0.000 | – |
| T4 | R@50 | 0.469 | 0.635 | -0.167 [-0.222, -0.110] | 0.000 | no (lower -0.222) |
| T4 | R@100 | 0.518 | 0.648 | -0.130 [-0.183, -0.075] | 0.000 | – |
| T4 | SetR@10 | 0.123 | 0.386 | -0.262 [-0.452, -0.080] | 0.006 | – |
| overall | S@1 | 0.195 | 0.400 | -0.205 [-0.239, -0.172] | 0.000 | – |
| overall | S@5 | 0.367 | 0.622 | -0.254 [-0.289, -0.218] | 0.000 | – |
| overall | MRR@10 | 0.268 | 0.495 | -0.226 [-0.255, -0.197] | 0.000 | – |
| overall | nDCG@10 | 0.309 | 0.541 | -0.232 [-0.260, -0.204] | 0.000 | no (lower -0.260) |
| overall | R@10 | 0.442 | 0.689 | -0.247 [-0.282, -0.211] | 0.000 | – |
| overall | R@50 | 0.580 | 0.797 | -0.217 [-0.250, -0.184] | 0.000 | no (lower -0.250) |
| overall | R@100 | 0.634 | 0.813 | -0.180 [-0.212, -0.148] | 0.000 | – |
| overall | SetR@10 | 0.123 | 0.386 | -0.262 [-0.453, -0.083] | 0.004 | – |
| T3+T4 | S@1 | 0.195 | 0.400 | -0.205 [-0.238, -0.172] | 0.000 | – |
| T3+T4 | S@5 | 0.367 | 0.622 | -0.254 [-0.290, -0.218] | 0.000 | – |
| T3+T4 | MRR@10 | 0.268 | 0.495 | -0.226 [-0.255, -0.197] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.309 | 0.541 | -0.232 [-0.260, -0.204] | 0.000 | no (lower -0.260) |
| T3+T4 | R@10 | 0.442 | 0.689 | -0.247 [-0.282, -0.212] | 0.000 | – |
| T3+T4 | R@50 | 0.580 | 0.797 | -0.217 [-0.250, -0.184] | 0.000 | no (lower -0.250) |
| T3+T4 | R@100 | 0.634 | 0.813 | -0.180 [-0.212, -0.148] | 0.000 | – |
| T3+T4 | SetR@10 | 0.123 | 0.386 | -0.262 [-0.455, -0.082] | 0.003 | – |
| free_text | S@1 | 0.195 | 0.400 | -0.205 [-0.240, -0.173] | 0.000 | – |
| free_text | S@5 | 0.367 | 0.622 | -0.254 [-0.289, -0.220] | 0.000 | – |
| free_text | MRR@10 | 0.268 | 0.495 | -0.226 [-0.256, -0.198] | 0.000 | – |
| free_text | nDCG@10 | 0.309 | 0.541 | -0.232 [-0.261, -0.204] | 0.000 | no (lower -0.261) |
| free_text | R@10 | 0.442 | 0.689 | -0.247 [-0.282, -0.212] | 0.000 | – |
| free_text | R@50 | 0.580 | 0.797 | -0.217 [-0.250, -0.184] | 0.000 | no (lower -0.250) |
| free_text | R@100 | 0.634 | 0.813 | -0.180 [-0.212, -0.149] | 0.000 | – |
| free_text | SetR@10 | 0.123 | 0.386 | -0.262 [-0.455, -0.085] | 0.004 | – |
| macro | S@1 | – | – | -0.184 [-0.217, -0.151] | 0.000 | – |
| macro | S@5 | – | – | -0.240 [-0.277, -0.203] | 0.000 | – |
| macro | MRR@10 | – | – | -0.207 [-0.236, -0.178] | 0.000 | – |
| macro | nDCG@10 | – | – | -0.212 [-0.242, -0.184] | 0.000 | no (lower -0.242) |
| macro | R@10 | – | – | -0.226 [-0.263, -0.189] | 0.000 | – |
| macro | R@50 | – | – | -0.205 [-0.240, -0.171] | 0.000 | no (lower -0.240) |
| macro | R@100 | – | – | -0.168 [-0.201, -0.135] | 0.000 | – |
| macro | SetR@10 | – | – | -0.262 [-0.453, -0.085] | 0.004 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8783 unjudged (rate 0.9547) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.4422 [0.4103, 0.4748] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.2684 [0.2435, 0.2934] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 839.1547 [826.6686, 851.6780] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
