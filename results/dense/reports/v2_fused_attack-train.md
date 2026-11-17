# Evaluation report: v2_fused_attack on train

**PROVISIONAL: 8532 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:21:05Z |
| Harness | b4-1 commit `32a50b73da90374291fe86aecab1ff73d291c3d5` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\v2_fused_attack-train.jsonl` sha256 `622c8fa9734250289f0c81011bcd63808c4be1f2d4897f5a5b2349324aab09bd` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_fused", "options": {"candidates": 100, "depth": 100, "k": 100, "kinds": "all", "rrf_k": 1, "weights": [1.0, 0.25]}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [23.29, 23.91, 22.92] -> [21.97, 22.96, 22.73] |
| Service health | `{"candidates": 100, "component": "fused", "dense": {"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "disk_cache": {"identity": "1e1fde3b6bc046dc7049", "path": "/home/koushik.moram/team2/dense/qvec/qvec-1e1fde3b6bc046dc70` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.480 [0.440, 0.520] | 0.708 [0.672, 0.745] | 0.585 [0.550, 0.618] | 0.636 [0.603, 0.668] | 0.798 [0.765, 0.830] | 0.898 [0.873, 0.922] | 0.922 [0.900, 0.943] | – | 5519/6000 (0.920) |
| T4 | 320 | 0.250 [0.203, 0.300] | 0.456 [0.403, 0.509] | 0.334 [0.289, 0.379] | 0.379 [0.334, 0.424] | 0.527 [0.473, 0.581] | 0.665 [0.614, 0.716] | 0.685 [0.635, 0.735] | 0.422 [0.252, 0.603] | 3013/3200 (0.942) |
| **macro (slices)** | – | 0.365 [0.334, 0.396] | 0.582 [0.550, 0.615] | 0.459 [0.431, 0.488] | 0.508 [0.480, 0.536] | 0.663 [0.631, 0.694] | 0.782 [0.754, 0.810] | 0.804 [0.776, 0.830] | 0.422 [0.249, 0.603] | – |
| **overall** | 920 | 0.400 [0.368, 0.432] | 0.621 [0.589, 0.652] | 0.497 [0.469, 0.526] | 0.547 [0.520, 0.574] | 0.704 [0.675, 0.733] | 0.817 [0.792, 0.842] | 0.839 [0.816, 0.863] | 0.422 [0.249, 0.596] | 8532/9200 (0.927) |
| T3+T4 | 920 | 0.400 [0.368, 0.433] | 0.621 [0.590, 0.652] | 0.497 [0.470, 0.526] | 0.547 [0.520, 0.574] | 0.704 [0.675, 0.734] | 0.817 [0.792, 0.842] | 0.839 [0.816, 0.863] | 0.422 [0.247, 0.601] | 8532/9200 (0.927) |
| free_text | 920 | 0.400 [0.370, 0.433] | 0.621 [0.589, 0.652] | 0.497 [0.470, 0.526] | 0.547 [0.520, 0.574] | 0.704 [0.675, 0.733] | 0.817 [0.792, 0.841] | 0.839 [0.816, 0.863] | 0.422 [0.251, 0.603] | 8532/9200 (0.927) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5519 | 0.480 / 1.000 | 0.708 / 1.000 | 0.585 / 1.000 | 0.636 / 1.000 |
| T4 | 3013 | 0.250 / 1.000 | 0.456 / 1.000 | 0.334 / 1.000 | 0.379 / 1.000 |
| overall | 8532 | 0.400 / 1.000 | 0.621 / 1.000 | 0.497 / 1.000 | 0.547 / 1.000 |
| T3+T4 | 8532 | 0.400 / 1.000 | 0.621 / 1.000 | 0.497 / 1.000 | 0.547 / 1.000 |
| free_text | 8532 | 0.400 / 1.000 | 0.621 / 1.000 | 0.497 / 1.000 | 0.547 / 1.000 |

Pairs to judge: 8532 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 85 [83, 86] | 178 [152, 191] | 236 [212, 539] | 1104 |
| T4 | 320 | 87 [85, 88] | 145 [121, 180] | 187 [180, 197] | 212 |
| overall | 920 | 85 [84, 87] | 170 [150, 182] | 222 [209, 440] | 1104 |
| T3+T4 | 920 | 85 [84, 87] | 170 [150, 182] | 222 [209, 438] | 1104 |
| free_text | 920 | 85 [84, 87] | 170 [150, 182] | 222 [209, 440] | 1104 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: v2_fused_attack - v1_hybrid

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\eval\runs\v1_hybrid-train.jsonl` (sha256 `208a6b201644b1392bed892b52dd74faa33f21c52a63f7b02c47831712408602`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_fused_attack | v1_hybrid | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.480 | 0.287 | 0.193 [0.153, 0.233] | 0.000 | – |
| T3 | S@5 | 0.708 | 0.473 | 0.235 [0.195, 0.275] | 0.000 | – |
| T3 | MRR@10 | 0.585 | 0.366 | 0.219 [0.185, 0.253] | 0.000 | – |
| T3 | nDCG@10 | 0.636 | 0.414 | 0.222 [0.191, 0.255] | 0.000 | yes (lower 0.191) |
| T3 | R@10 | 0.798 | 0.568 | 0.230 [0.192, 0.270] | 0.000 | – |
| T3 | R@50 | 0.898 | 0.568 | 0.330 [0.290, 0.370] | 0.000 | yes (lower 0.290) |
| T3 | R@100 | 0.922 | 0.568 | 0.353 [0.315, 0.393] | 0.000 | – |
| T4 | S@1 | 0.250 | 0.147 | 0.103 [0.056, 0.150] | 0.000 | – |
| T4 | S@5 | 0.456 | 0.325 | 0.131 [0.078, 0.184] | 0.000 | – |
| T4 | MRR@10 | 0.334 | 0.219 | 0.115 [0.074, 0.156] | 0.000 | – |
| T4 | nDCG@10 | 0.379 | 0.256 | 0.124 [0.085, 0.164] | 0.000 | yes (lower 0.085) |
| T4 | R@10 | 0.527 | 0.376 | 0.151 [0.105, 0.198] | 0.000 | – |
| T4 | R@50 | 0.665 | 0.376 | 0.289 [0.241, 0.340] | 0.000 | yes (lower 0.241) |
| T4 | R@100 | 0.685 | 0.376 | 0.309 [0.260, 0.361] | 0.000 | – |
| T4 | SetR@10 | 0.422 | 0.146 | 0.275 [0.123, 0.442] | 0.001 | – |
| overall | S@1 | 0.400 | 0.238 | 0.162 [0.130, 0.193] | 0.000 | – |
| overall | S@5 | 0.621 | 0.422 | 0.199 [0.166, 0.232] | 0.000 | – |
| overall | MRR@10 | 0.497 | 0.315 | 0.183 [0.155, 0.209] | 0.000 | – |
| overall | nDCG@10 | 0.547 | 0.359 | 0.188 [0.163, 0.213] | 0.000 | yes (lower 0.163) |
| overall | R@10 | 0.704 | 0.501 | 0.203 [0.172, 0.234] | 0.000 | – |
| overall | R@50 | 0.817 | 0.501 | 0.316 [0.285, 0.346] | 0.000 | yes (lower 0.285) |
| overall | R@100 | 0.839 | 0.501 | 0.338 [0.307, 0.369] | 0.000 | – |
| overall | SetR@10 | 0.422 | 0.146 | 0.275 [0.125, 0.444] | 0.001 | – |
| T3+T4 | S@1 | 0.400 | 0.238 | 0.162 [0.132, 0.193] | 0.000 | – |
| T3+T4 | S@5 | 0.621 | 0.422 | 0.199 [0.167, 0.230] | 0.000 | – |
| T3+T4 | MRR@10 | 0.497 | 0.315 | 0.183 [0.156, 0.209] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.547 | 0.359 | 0.188 [0.163, 0.214] | 0.000 | yes (lower 0.163) |
| T3+T4 | R@10 | 0.704 | 0.501 | 0.203 [0.172, 0.233] | 0.000 | – |
| T3+T4 | R@50 | 0.817 | 0.501 | 0.316 [0.285, 0.347] | 0.000 | yes (lower 0.285) |
| T3+T4 | R@100 | 0.839 | 0.501 | 0.338 [0.307, 0.369] | 0.000 | – |
| T3+T4 | SetR@10 | 0.422 | 0.146 | 0.275 [0.123, 0.444] | 0.001 | – |
| free_text | S@1 | 0.400 | 0.238 | 0.162 [0.132, 0.193] | 0.000 | – |
| free_text | S@5 | 0.621 | 0.422 | 0.199 [0.167, 0.230] | 0.000 | – |
| free_text | MRR@10 | 0.497 | 0.315 | 0.183 [0.156, 0.210] | 0.000 | – |
| free_text | nDCG@10 | 0.547 | 0.359 | 0.188 [0.163, 0.213] | 0.000 | yes (lower 0.163) |
| free_text | R@10 | 0.704 | 0.501 | 0.203 [0.173, 0.233] | 0.000 | – |
| free_text | R@50 | 0.817 | 0.501 | 0.316 [0.286, 0.347] | 0.000 | yes (lower 0.286) |
| free_text | R@100 | 0.839 | 0.501 | 0.338 [0.308, 0.369] | 0.000 | – |
| free_text | SetR@10 | 0.422 | 0.146 | 0.275 [0.122, 0.441] | 0.001 | – |
| macro | S@1 | – | – | 0.148 [0.118, 0.179] | 0.000 | – |
| macro | S@5 | – | – | 0.183 [0.151, 0.216] | 0.000 | – |
| macro | MRR@10 | – | – | 0.167 [0.141, 0.193] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.173 [0.147, 0.199] | 0.000 | yes (lower 0.147) |
| macro | R@10 | – | – | 0.191 [0.160, 0.221] | 0.000 | – |
| macro | R@50 | – | – | 0.309 [0.279, 0.340] | 0.000 | yes (lower 0.279) |
| macro | R@100 | – | – | 0.331 [0.300, 0.363] | 0.000 | – |
| macro | SetR@10 | – | – | 0.275 [0.125, 0.444] | 0.000 | – |

## Comparison: v2_fused_attack - v2_lexical_attack

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\v2_lexical_attack-train.jsonl` (sha256 `e33db34208531f4a57560b96d28c5e021c0d9d1f48530ceb670d0b3167891c8d`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_fused_attack | v2_lexical_attack | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.480 | 0.480 | 0.000 [0.000, 0.000] | 1.000 | – |
| T3 | S@5 | 0.708 | 0.710 | -0.002 [-0.012, 0.008] | 0.874 | – |
| T3 | MRR@10 | 0.585 | 0.582 | 0.003 [0.000, 0.005] | 0.043 | – |
| T3 | nDCG@10 | 0.636 | 0.631 | 0.005 [-0.000, 0.010] | 0.069 | yes (lower -0.000) |
| T3 | R@10 | 0.798 | 0.787 | 0.012 [-0.003, 0.027] | 0.158 | – |
| T3 | R@50 | 0.898 | 0.883 | 0.015 [0.003, 0.027] | 0.013 | yes (lower 0.003) |
| T3 | R@100 | 0.922 | 0.902 | 0.020 [0.008, 0.033] | 0.001 | – |
| T4 | S@1 | 0.250 | 0.250 | 0.000 [0.000, 0.000] | 1.000 | – |
| T4 | S@5 | 0.456 | 0.456 | 0.000 [-0.022, 0.022] | 1.000 | – |
| T4 | MRR@10 | 0.334 | 0.330 | 0.004 [-0.001, 0.009] | 0.089 | – |
| T4 | nDCG@10 | 0.379 | 0.372 | 0.008 [-0.001, 0.017] | 0.094 | yes (lower -0.001) |
| T4 | R@10 | 0.527 | 0.506 | 0.021 [-0.005, 0.049] | 0.132 | – |
| T4 | R@50 | 0.665 | 0.635 | 0.030 [0.006, 0.055] | 0.014 | yes (lower 0.006) |
| T4 | R@100 | 0.685 | 0.648 | 0.037 [0.016, 0.062] | 0.000 | – |
| T4 | SetR@10 | 0.422 | 0.386 | 0.036 [0.000, 0.095] | 0.257 | – |
| overall | S@1 | 0.400 | 0.400 | 0.000 [0.000, 0.000] | 1.000 | – |
| overall | S@5 | 0.621 | 0.622 | -0.001 [-0.012, 0.009] | 0.913 | – |
| overall | MRR@10 | 0.497 | 0.494 | 0.003 [0.001, 0.005] | 0.007 | – |
| overall | nDCG@10 | 0.547 | 0.541 | 0.006 [0.001, 0.010] | 0.013 | yes (lower 0.001) |
| overall | R@10 | 0.704 | 0.689 | 0.015 [0.001, 0.029] | 0.034 | – |
| overall | R@50 | 0.817 | 0.797 | 0.020 [0.009, 0.032] | 0.001 | yes (lower 0.009) |
| overall | R@100 | 0.839 | 0.813 | 0.026 [0.015, 0.037] | 0.000 | – |
| overall | SetR@10 | 0.422 | 0.386 | 0.036 [0.000, 0.093] | 0.268 | – |
| T3+T4 | S@1 | 0.400 | 0.400 | 0.000 [0.000, 0.000] | 1.000 | – |
| T3+T4 | S@5 | 0.621 | 0.622 | -0.001 [-0.012, 0.009] | 0.919 | – |
| T3+T4 | MRR@10 | 0.497 | 0.494 | 0.003 [0.001, 0.005] | 0.009 | – |
| T3+T4 | nDCG@10 | 0.547 | 0.541 | 0.006 [0.001, 0.010] | 0.013 | yes (lower 0.001) |
| T3+T4 | R@10 | 0.704 | 0.689 | 0.015 [0.002, 0.029] | 0.030 | – |
| T3+T4 | R@50 | 0.817 | 0.797 | 0.020 [0.009, 0.032] | 0.000 | yes (lower 0.009) |
| T3+T4 | R@100 | 0.839 | 0.813 | 0.026 [0.015, 0.038] | 0.000 | – |
| T3+T4 | SetR@10 | 0.422 | 0.386 | 0.036 [0.000, 0.094] | 0.277 | – |
| free_text | S@1 | 0.400 | 0.400 | 0.000 [0.000, 0.000] | 1.000 | – |
| free_text | S@5 | 0.621 | 0.622 | -0.001 [-0.011, 0.009] | 0.922 | – |
| free_text | MRR@10 | 0.497 | 0.494 | 0.003 [0.001, 0.005] | 0.010 | – |
| free_text | nDCG@10 | 0.547 | 0.541 | 0.006 [0.001, 0.010] | 0.014 | yes (lower 0.001) |
| free_text | R@10 | 0.704 | 0.689 | 0.015 [0.001, 0.029] | 0.031 | – |
| free_text | R@50 | 0.817 | 0.797 | 0.020 [0.009, 0.032] | 0.000 | yes (lower 0.009) |
| free_text | R@100 | 0.839 | 0.813 | 0.026 [0.015, 0.037] | 0.000 | – |
| free_text | SetR@10 | 0.422 | 0.386 | 0.036 [0.000, 0.094] | 0.262 | – |
| macro | S@1 | – | – | 0.000 [0.000, 0.000] | 1.000 | – |
| macro | S@5 | – | – | -0.001 [-0.013, 0.012] | 0.902 | – |
| macro | MRR@10 | – | – | 0.003 [0.001, 0.006] | 0.013 | – |
| macro | nDCG@10 | – | – | 0.006 [0.001, 0.011] | 0.023 | yes (lower 0.001) |
| macro | R@10 | – | – | 0.017 [0.001, 0.032] | 0.038 | – |
| macro | R@50 | – | – | 0.022 [0.010, 0.036] | 0.000 | yes (lower 0.010) |
| macro | R@100 | – | – | 0.029 [0.017, 0.042] | 0.000 | – |
| macro | SetR@10 | – | – | 0.036 [0.000, 0.093] | 0.269 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8532 unjudged (rate 0.9274) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.7040 [0.6749, 0.7339] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.4974 [0.4698, 0.5262] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 170.0047 [149.5780, 182.0148] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
