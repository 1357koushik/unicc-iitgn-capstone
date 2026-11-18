# Evaluation report: cmp_bge-m3 on train

**PROVISIONAL: 8680 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:23:46Z |
| Harness | b4-1 commit `403325fc1d07208ddb11938027df191f3acdc271` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_bge-m3-train.jsonl` sha256 `829209bc748a70d15ae2283057cf254404ec5378a8d636ddc17b95ff03743b00` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.dense.eval_adapter:make_dense", "options": {"index": "compare/bge-m3", "k": 100, "kinds": "all"}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [25.61, 23.38, 21.75] -> [26.09, 24.72, 22.65] |
| Service health | `{"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "component": "dense", "disk_cache": {"identity": "1e1fde3b6bc046dc7049", "path": "/home/koushik.moram/team2/dense/qvec/qvec-1e1fde3b6bc046dc7049.sqlite"}, "encoder": {"bat` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.388 [0.350, 0.428] | 0.575 [0.535, 0.613] | 0.466 [0.431, 0.502] | 0.504 [0.469, 0.539] | 0.623 [0.585, 0.662] | 0.777 [0.743, 0.810] | 0.818 [0.787, 0.848] | – | 5624/6000 (0.937) |
| T4 | 320 | 0.172 [0.131, 0.212] | 0.334 [0.284, 0.388] | 0.246 [0.206, 0.288] | 0.280 [0.239, 0.323] | 0.393 [0.340, 0.447] | 0.511 [0.456, 0.566] | 0.570 [0.517, 0.623] | 0.336 [0.167, 0.517] | 3056/3200 (0.955) |
| **macro (slices)** | – | 0.280 [0.252, 0.309] | 0.455 [0.421, 0.487] | 0.356 [0.330, 0.384] | 0.392 [0.366, 0.421] | 0.508 [0.475, 0.541] | 0.644 [0.612, 0.676] | 0.694 [0.662, 0.725] | 0.336 [0.167, 0.520] | – |
| **overall** | 920 | 0.313 [0.284, 0.342] | 0.491 [0.459, 0.524] | 0.390 [0.362, 0.418] | 0.426 [0.398, 0.454] | 0.543 [0.511, 0.576] | 0.684 [0.654, 0.715] | 0.732 [0.703, 0.761] | 0.336 [0.167, 0.523] | 8680/9200 (0.943) |
| T3+T4 | 920 | 0.313 [0.284, 0.343] | 0.491 [0.460, 0.524] | 0.390 [0.362, 0.418] | 0.426 [0.398, 0.454] | 0.543 [0.511, 0.575] | 0.684 [0.655, 0.714] | 0.732 [0.703, 0.761] | 0.336 [0.165, 0.522] | 8680/9200 (0.943) |
| free_text | 920 | 0.313 [0.284, 0.343] | 0.491 [0.460, 0.523] | 0.390 [0.362, 0.418] | 0.426 [0.399, 0.454] | 0.543 [0.512, 0.574] | 0.684 [0.655, 0.713] | 0.732 [0.704, 0.760] | 0.336 [0.167, 0.525] | 8680/9200 (0.943) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5624 | 0.388 / 1.000 | 0.575 / 1.000 | 0.466 / 1.000 | 0.504 / 1.000 |
| T4 | 3056 | 0.172 / 1.000 | 0.334 / 1.000 | 0.246 / 1.000 | 0.280 / 0.999 |
| overall | 8680 | 0.313 / 1.000 | 0.491 / 1.000 | 0.390 / 1.000 | 0.426 / 1.000 |
| T3+T4 | 8680 | 0.313 / 1.000 | 0.491 / 1.000 | 0.390 / 1.000 | 0.426 / 1.000 |
| free_text | 8680 | 0.313 / 1.000 | 0.491 / 1.000 | 0.390 / 1.000 | 0.426 / 1.000 |

Pairs to judge: 8680 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 33 [32, 33] | 89 [67, 100] | 243 [112, 409] | 556 |
| T4 | 320 | 30 [29, 30] | 59 [47, 94] | 105 [94, 114] | 116 |
| overall | 920 | 32 [31, 32] | 78 [64, 95] | 130 [107, 353] | 556 |
| T3+T4 | 920 | 32 [31, 32] | 78 [64, 94] | 130 [107, 355] | 556 |
| free_text | 920 | 32 [31, 32] | 78 [64, 94] | 130 [107, 355] | 556 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: cmp_bge-m3 - cmp_v1

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1-train.jsonl` (sha256 `0c5a13da1283207fb367eab3d1af09f276e2bfc4ea0ea97907754f5e8d3e0b6b`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | cmp_bge-m3 | cmp_v1 | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.388 | 0.297 | 0.092 [0.057, 0.125] | 0.000 | – |
| T3 | S@5 | 0.575 | 0.510 | 0.065 [0.028, 0.100] | 0.001 | – |
| T3 | MRR@10 | 0.466 | 0.386 | 0.081 [0.052, 0.109] | 0.000 | – |
| T3 | nDCG@10 | 0.504 | 0.433 | 0.071 [0.043, 0.099] | 0.000 | yes (lower 0.043) |
| T3 | R@10 | 0.623 | 0.582 | 0.042 [0.005, 0.077] | 0.029 | – |
| T3 | R@50 | 0.777 | 0.722 | 0.055 [0.020, 0.088] | 0.002 | yes (lower 0.020) |
| T3 | R@100 | 0.818 | 0.793 | 0.025 [-0.007, 0.055] | 0.131 | – |
| T4 | S@1 | 0.172 | 0.175 | -0.003 [-0.038, 0.031] | 0.924 | – |
| T4 | S@5 | 0.334 | 0.344 | -0.009 [-0.047, 0.028] | 0.672 | – |
| T4 | MRR@10 | 0.246 | 0.248 | -0.002 [-0.031, 0.028] | 0.883 | – |
| T4 | nDCG@10 | 0.280 | 0.287 | -0.006 [-0.035, 0.023] | 0.646 | no (lower -0.035) |
| T4 | R@10 | 0.393 | 0.420 | -0.027 [-0.067, 0.013] | 0.188 | – |
| T4 | R@50 | 0.511 | 0.530 | -0.019 [-0.061, 0.023] | 0.370 | no (lower -0.061) |
| T4 | R@100 | 0.570 | 0.582 | -0.012 [-0.051, 0.026] | 0.541 | – |
| T4 | SetR@10 | 0.336 | 0.230 | 0.107 [0.022, 0.208] | 0.012 | – |
| overall | S@1 | 0.313 | 0.254 | 0.059 [0.034, 0.085] | 0.000 | – |
| overall | S@5 | 0.491 | 0.452 | 0.039 [0.013, 0.065] | 0.004 | – |
| overall | MRR@10 | 0.390 | 0.338 | 0.052 [0.031, 0.074] | 0.000 | – |
| overall | nDCG@10 | 0.426 | 0.382 | 0.044 [0.024, 0.066] | 0.000 | yes (lower 0.024) |
| overall | R@10 | 0.543 | 0.525 | 0.018 [-0.009, 0.045] | 0.204 | – |
| overall | R@50 | 0.684 | 0.655 | 0.029 [0.003, 0.056] | 0.030 | yes (lower 0.003) |
| overall | R@100 | 0.732 | 0.720 | 0.012 [-0.012, 0.036] | 0.335 | – |
| overall | SetR@10 | 0.336 | 0.230 | 0.107 [0.024, 0.208] | 0.015 | – |
| T3+T4 | S@1 | 0.313 | 0.254 | 0.059 [0.034, 0.085] | 0.000 | – |
| T3+T4 | S@5 | 0.491 | 0.452 | 0.039 [0.013, 0.065] | 0.004 | – |
| T3+T4 | MRR@10 | 0.390 | 0.338 | 0.052 [0.031, 0.073] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.426 | 0.382 | 0.044 [0.024, 0.065] | 0.000 | yes (lower 0.024) |
| T3+T4 | R@10 | 0.543 | 0.525 | 0.018 [-0.009, 0.045] | 0.188 | – |
| T3+T4 | R@50 | 0.684 | 0.655 | 0.029 [0.003, 0.056] | 0.025 | yes (lower 0.003) |
| T3+T4 | R@100 | 0.732 | 0.720 | 0.012 [-0.011, 0.036] | 0.334 | – |
| T3+T4 | SetR@10 | 0.336 | 0.230 | 0.107 [0.022, 0.208] | 0.015 | – |
| free_text | S@1 | 0.313 | 0.254 | 0.059 [0.033, 0.085] | 0.000 | – |
| free_text | S@5 | 0.491 | 0.452 | 0.039 [0.012, 0.066] | 0.006 | – |
| free_text | MRR@10 | 0.390 | 0.338 | 0.052 [0.030, 0.074] | 0.000 | – |
| free_text | nDCG@10 | 0.426 | 0.382 | 0.044 [0.023, 0.066] | 0.000 | yes (lower 0.023) |
| free_text | R@10 | 0.543 | 0.525 | 0.018 [-0.009, 0.045] | 0.199 | – |
| free_text | R@50 | 0.684 | 0.655 | 0.029 [0.003, 0.056] | 0.030 | yes (lower 0.003) |
| free_text | R@100 | 0.732 | 0.720 | 0.012 [-0.012, 0.036] | 0.335 | – |
| free_text | SetR@10 | 0.336 | 0.230 | 0.107 [0.024, 0.208] | 0.014 | – |
| macro | S@1 | – | – | 0.044 [0.020, 0.069] | 0.000 | – |
| macro | S@5 | – | – | 0.028 [0.002, 0.054] | 0.035 | – |
| macro | MRR@10 | – | – | 0.039 [0.019, 0.060] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.033 [0.012, 0.052] | 0.003 | yes (lower 0.012) |
| macro | R@10 | – | – | 0.007 [-0.020, 0.034] | 0.582 | – |
| macro | R@50 | – | – | 0.018 [-0.008, 0.045] | 0.182 | yes (lower -0.008) |
| macro | R@100 | – | – | 0.007 [-0.018, 0.032] | 0.603 | – |
| macro | SetR@10 | – | – | 0.107 [0.024, 0.210] | 0.012 | – |

## Comparison: cmp_bge-m3 - cmp_v1_v1query

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\cmp_v1_v1query-train.jsonl` (sha256 `e450ba4c2fe474d43f590ff9d4641d6a0e23d53437f58cddfe681202f71ffe2c`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | cmp_bge-m3 | cmp_v1_v1query | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.388 | 0.300 | 0.088 [0.053, 0.123] | 0.000 | – |
| T3 | S@5 | 0.575 | 0.478 | 0.097 [0.060, 0.133] | 0.000 | – |
| T3 | MRR@10 | 0.466 | 0.376 | 0.090 [0.060, 0.120] | 0.000 | – |
| T3 | nDCG@10 | 0.504 | 0.419 | 0.085 [0.055, 0.113] | 0.000 | yes (lower 0.055) |
| T3 | R@10 | 0.623 | 0.558 | 0.065 [0.028, 0.100] | 0.001 | – |
| T3 | R@50 | 0.777 | 0.715 | 0.062 [0.027, 0.097] | 0.001 | yes (lower 0.027) |
| T3 | R@100 | 0.818 | 0.757 | 0.062 [0.030, 0.095] | 0.000 | – |
| T4 | S@1 | 0.172 | 0.172 | 0.000 [-0.037, 0.037] | 1.000 | – |
| T4 | S@5 | 0.334 | 0.322 | 0.013 [-0.025, 0.053] | 0.593 | – |
| T4 | MRR@10 | 0.246 | 0.231 | 0.015 [-0.014, 0.046] | 0.317 | – |
| T4 | nDCG@10 | 0.280 | 0.262 | 0.019 [-0.011, 0.049] | 0.213 | no (lower -0.011) |
| T4 | R@10 | 0.393 | 0.366 | 0.027 [-0.016, 0.071] | 0.223 | – |
| T4 | R@50 | 0.511 | 0.517 | -0.006 [-0.048, 0.035] | 0.785 | no (lower -0.048) |
| T4 | R@100 | 0.570 | 0.571 | -0.001 [-0.040, 0.039] | 0.952 | – |
| T4 | SetR@10 | 0.336 | 0.228 | 0.109 [0.016, 0.227] | 0.039 | – |
| overall | S@1 | 0.313 | 0.255 | 0.058 [0.032, 0.085] | 0.000 | – |
| overall | S@5 | 0.491 | 0.424 | 0.067 [0.040, 0.096] | 0.000 | – |
| overall | MRR@10 | 0.390 | 0.326 | 0.064 [0.042, 0.087] | 0.000 | – |
| overall | nDCG@10 | 0.426 | 0.365 | 0.062 [0.040, 0.084] | 0.000 | yes (lower 0.040) |
| overall | R@10 | 0.543 | 0.492 | 0.052 [0.023, 0.080] | 0.000 | – |
| overall | R@50 | 0.684 | 0.646 | 0.038 [0.010, 0.065] | 0.007 | yes (lower 0.010) |
| overall | R@100 | 0.732 | 0.692 | 0.040 [0.014, 0.065] | 0.002 | – |
| overall | SetR@10 | 0.336 | 0.228 | 0.109 [0.017, 0.230] | 0.033 | – |
| T3+T4 | S@1 | 0.313 | 0.255 | 0.058 [0.032, 0.085] | 0.000 | – |
| T3+T4 | S@5 | 0.491 | 0.424 | 0.067 [0.039, 0.096] | 0.000 | – |
| T3+T4 | MRR@10 | 0.390 | 0.326 | 0.064 [0.041, 0.087] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.426 | 0.365 | 0.062 [0.039, 0.084] | 0.000 | yes (lower 0.039) |
| T3+T4 | R@10 | 0.543 | 0.492 | 0.052 [0.023, 0.080] | 0.001 | – |
| T3+T4 | R@50 | 0.684 | 0.646 | 0.038 [0.011, 0.066] | 0.008 | yes (lower 0.011) |
| T3+T4 | R@100 | 0.732 | 0.692 | 0.040 [0.014, 0.065] | 0.002 | – |
| T3+T4 | SetR@10 | 0.336 | 0.228 | 0.109 [0.016, 0.227] | 0.038 | – |
| free_text | S@1 | 0.313 | 0.255 | 0.058 [0.032, 0.085] | 0.000 | – |
| free_text | S@5 | 0.491 | 0.424 | 0.067 [0.039, 0.096] | 0.000 | – |
| free_text | MRR@10 | 0.390 | 0.326 | 0.064 [0.042, 0.087] | 0.000 | – |
| free_text | nDCG@10 | 0.426 | 0.365 | 0.062 [0.040, 0.084] | 0.000 | yes (lower 0.040) |
| free_text | R@10 | 0.543 | 0.492 | 0.052 [0.023, 0.080] | 0.001 | – |
| free_text | R@50 | 0.684 | 0.646 | 0.038 [0.011, 0.065] | 0.006 | yes (lower 0.011) |
| free_text | R@100 | 0.732 | 0.692 | 0.040 [0.014, 0.066] | 0.002 | – |
| free_text | SetR@10 | 0.336 | 0.228 | 0.109 [0.018, 0.228] | 0.034 | – |
| macro | S@1 | – | – | 0.044 [0.019, 0.069] | 0.001 | – |
| macro | S@5 | – | – | 0.055 [0.027, 0.082] | 0.000 | – |
| macro | MRR@10 | – | – | 0.053 [0.032, 0.074] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.052 [0.031, 0.072] | 0.000 | yes (lower 0.031) |
| macro | R@10 | – | – | 0.046 [0.018, 0.075] | 0.002 | – |
| macro | R@50 | – | – | 0.028 [0.001, 0.055] | 0.044 | yes (lower 0.001) |
| macro | R@100 | – | – | 0.030 [0.005, 0.056] | 0.020 | – |
| macro | SetR@10 | – | – | 0.109 [0.016, 0.229] | 0.035 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8680 unjudged (rate 0.9435) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.5432 [0.5109, 0.5751] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.3897 [0.3617, 0.4182] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 78.3775 [63.8861, 94.4800] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
