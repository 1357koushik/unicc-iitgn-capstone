# Evaluation report: v2_lexical on train

**PROVISIONAL: 8547 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-17T16:21:29Z |
| Harness | b4-1 commit `32a50b73da90374291fe86aecab1ff73d291c3d5` (benchmarks_v2 modified) |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\dense\runs\v2_lexical-train.jsonl` sha256 `1cce2566fce371b0b8ce393dcf3d73fd12bec8da0ad07fe10d2f2924da672766` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.lexical.eval_adapter:make", "options": {"k": 100}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [24.86, 23.96, 19.77] -> [23.41, 23.74, 20.46] |
| Service health | `{"build_id": "20261115T203653Z-bfacb4bb1c", "component": "lexical", "documents": 406840, "impact_bytes": 259774960, "impact_nnz": 20580052, "index_sha256": "814a1e73ff47fa2a8e9f7f15db14d258ea2ccf0f6685fbe9d17a3d6da7c8d5e1", "kinds": ["cve"], "ranking": {"bm25": {"b": 0.75, "implementation": "sqlite fts5 bm25()", "k1": 1.2}, "max_df_ratio": 1.0, "max_query_chars": 20000, "max_terms": 64, "stop_word` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['recall@50', 'ndcg@10'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.480 [0.440, 0.520] | 0.710 [0.673, 0.747] | 0.582 [0.547, 0.616] | 0.631 [0.598, 0.663] | 0.787 [0.753, 0.818] | 0.883 [0.857, 0.908] | 0.902 [0.877, 0.925] | – | 5526/6000 (0.921) |
| T4 | 320 | 0.250 [0.203, 0.300] | 0.456 [0.403, 0.509] | 0.331 [0.286, 0.377] | 0.373 [0.327, 0.418] | 0.506 [0.452, 0.561] | 0.635 [0.583, 0.688] | 0.648 [0.596, 0.699] | 0.386 [0.213, 0.574] | 3021/3200 (0.944) |
| **macro (slices)** | – | 0.365 [0.334, 0.396] | 0.583 [0.551, 0.616] | 0.457 [0.428, 0.485] | 0.502 [0.475, 0.530] | 0.646 [0.615, 0.678] | 0.759 [0.731, 0.788] | 0.775 [0.746, 0.803] | 0.386 [0.208, 0.573] | – |
| **overall** | 920 | 0.400 [0.368, 0.432] | 0.622 [0.590, 0.653] | 0.495 [0.466, 0.523] | 0.541 [0.514, 0.569] | 0.689 [0.659, 0.719] | 0.797 [0.771, 0.823] | 0.813 [0.788, 0.838] | 0.386 [0.209, 0.569] | 8547/9200 (0.929) |
| T3+T4 | 920 | 0.400 [0.368, 0.433] | 0.622 [0.590, 0.653] | 0.495 [0.467, 0.524] | 0.541 [0.514, 0.569] | 0.689 [0.659, 0.719] | 0.797 [0.771, 0.823] | 0.813 [0.788, 0.838] | 0.386 [0.204, 0.574] | 8547/9200 (0.929) |
| free_text | 920 | 0.400 [0.370, 0.433] | 0.622 [0.590, 0.652] | 0.495 [0.467, 0.523] | 0.541 [0.514, 0.569] | 0.689 [0.659, 0.718] | 0.797 [0.772, 0.822] | 0.813 [0.788, 0.838] | 0.386 [0.208, 0.574] | 8547/9200 (0.929) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5526 | 0.480 / 1.000 | 0.710 / 1.000 | 0.582 / 1.000 | 0.631 / 1.000 |
| T4 | 3021 | 0.250 / 1.000 | 0.456 / 1.000 | 0.331 / 1.000 | 0.373 / 1.000 |
| overall | 8547 | 0.400 / 1.000 | 0.622 / 1.000 | 0.495 / 1.000 | 0.541 / 1.000 |
| T3+T4 | 8547 | 0.400 / 1.000 | 0.622 / 1.000 | 0.495 / 1.000 | 0.541 / 1.000 |
| free_text | 8547 | 0.400 / 1.000 | 0.622 / 1.000 | 0.495 / 1.000 | 0.541 / 1.000 |

Pairs to judge: 8547 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 8 [8, 9] | 24 [23, 27] | 33 [30, 34] | 41 |
| T4 | 320 | 5 [5, 6] | 10 [9, 12] | 17 [12, 20] | 22 |
| overall | 920 | 7 [7, 7] | 22 [20, 24] | 31 [27, 33] | 41 |
| T3+T4 | 920 | 7 [7, 7] | 22 [20, 24] | 31 [27, 33] | 41 |
| free_text | 920 | 7 [7, 7] | 22 [20, 24] | 31 [27, 33] | 41 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Comparison: v2_lexical - v1_hybrid

Reference run `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\results\eval\runs\v1_hybrid-train.jsonl` (sha256 `208a6b201644b1392bed892b52dd74faa33f21c52a63f7b02c47831712408602`). Paired bootstrap over the same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower 0.025 percentile of the difference >= -margin (margin 0.01).

| Population | metric | v2_lexical | v1_hybrid | diff [95% CI] | p | non-inferior |
|---|---|---|---|---|---|---|
| T3 | S@1 | 0.480 | 0.287 | 0.193 [0.153, 0.233] | 0.000 | – |
| T3 | S@5 | 0.710 | 0.473 | 0.237 [0.197, 0.277] | 0.000 | – |
| T3 | MRR@10 | 0.582 | 0.366 | 0.216 [0.183, 0.251] | 0.000 | – |
| T3 | nDCG@10 | 0.631 | 0.414 | 0.218 [0.185, 0.251] | 0.000 | yes (lower 0.185) |
| T3 | R@10 | 0.787 | 0.568 | 0.218 [0.177, 0.260] | 0.000 | – |
| T3 | R@50 | 0.883 | 0.568 | 0.315 [0.277, 0.355] | 0.000 | yes (lower 0.277) |
| T3 | R@100 | 0.902 | 0.568 | 0.333 [0.293, 0.373] | 0.000 | – |
| T4 | S@1 | 0.250 | 0.147 | 0.103 [0.056, 0.150] | 0.000 | – |
| T4 | S@5 | 0.456 | 0.325 | 0.131 [0.075, 0.188] | 0.000 | – |
| T4 | MRR@10 | 0.331 | 0.219 | 0.112 [0.070, 0.155] | 0.000 | – |
| T4 | nDCG@10 | 0.373 | 0.256 | 0.117 [0.075, 0.160] | 0.000 | yes (lower 0.075) |
| T4 | R@10 | 0.506 | 0.376 | 0.130 [0.077, 0.184] | 0.000 | – |
| T4 | R@50 | 0.635 | 0.376 | 0.259 [0.209, 0.311] | 0.000 | yes (lower 0.209) |
| T4 | R@100 | 0.648 | 0.376 | 0.272 [0.221, 0.324] | 0.000 | – |
| T4 | SetR@10 | 0.386 | 0.146 | 0.239 [0.083, 0.417] | 0.004 | – |
| overall | S@1 | 0.400 | 0.238 | 0.162 [0.130, 0.193] | 0.000 | – |
| overall | S@5 | 0.622 | 0.422 | 0.200 [0.166, 0.233] | 0.000 | – |
| overall | MRR@10 | 0.495 | 0.315 | 0.180 [0.152, 0.207] | 0.000 | – |
| overall | nDCG@10 | 0.541 | 0.359 | 0.183 [0.156, 0.209] | 0.000 | yes (lower 0.156) |
| overall | R@10 | 0.689 | 0.501 | 0.188 [0.155, 0.220] | 0.000 | – |
| overall | R@50 | 0.797 | 0.501 | 0.296 [0.264, 0.327] | 0.000 | yes (lower 0.264) |
| overall | R@100 | 0.813 | 0.501 | 0.312 [0.281, 0.344] | 0.000 | – |
| overall | SetR@10 | 0.386 | 0.146 | 0.239 [0.083, 0.417] | 0.004 | – |
| T3+T4 | S@1 | 0.400 | 0.238 | 0.162 [0.132, 0.193] | 0.000 | – |
| T3+T4 | S@5 | 0.622 | 0.422 | 0.200 [0.168, 0.233] | 0.000 | – |
| T3+T4 | MRR@10 | 0.495 | 0.315 | 0.180 [0.153, 0.207] | 0.000 | – |
| T3+T4 | nDCG@10 | 0.541 | 0.359 | 0.183 [0.157, 0.209] | 0.000 | yes (lower 0.157) |
| T3+T4 | R@10 | 0.689 | 0.501 | 0.188 [0.155, 0.220] | 0.000 | – |
| T3+T4 | R@50 | 0.797 | 0.501 | 0.296 [0.264, 0.327] | 0.000 | yes (lower 0.264) |
| T3+T4 | R@100 | 0.813 | 0.501 | 0.312 [0.281, 0.344] | 0.000 | – |
| T3+T4 | SetR@10 | 0.386 | 0.146 | 0.239 [0.080, 0.413] | 0.003 | – |
| free_text | S@1 | 0.400 | 0.238 | 0.162 [0.132, 0.193] | 0.000 | – |
| free_text | S@5 | 0.622 | 0.422 | 0.200 [0.167, 0.233] | 0.000 | – |
| free_text | MRR@10 | 0.495 | 0.315 | 0.180 [0.153, 0.207] | 0.000 | – |
| free_text | nDCG@10 | 0.541 | 0.359 | 0.183 [0.157, 0.209] | 0.000 | yes (lower 0.157) |
| free_text | R@10 | 0.689 | 0.501 | 0.188 [0.155, 0.220] | 0.000 | – |
| free_text | R@50 | 0.797 | 0.501 | 0.296 [0.265, 0.327] | 0.000 | yes (lower 0.265) |
| free_text | R@100 | 0.813 | 0.501 | 0.312 [0.281, 0.343] | 0.000 | – |
| free_text | SetR@10 | 0.386 | 0.146 | 0.239 [0.080, 0.413] | 0.003 | – |
| macro | S@1 | – | – | 0.148 [0.118, 0.179] | 0.000 | – |
| macro | S@5 | – | – | 0.184 [0.150, 0.219] | 0.000 | – |
| macro | MRR@10 | – | – | 0.164 [0.137, 0.191] | 0.000 | – |
| macro | nDCG@10 | – | – | 0.167 [0.141, 0.194] | 0.000 | yes (lower 0.141) |
| macro | R@10 | – | – | 0.174 [0.141, 0.207] | 0.000 | – |
| macro | R@50 | – | – | 0.287 [0.255, 0.319] | 0.000 | yes (lower 0.255) |
| macro | R@100 | – | – | 0.303 [0.270, 0.334] | 0.000 | – |
| macro | SetR@10 | – | – | 0.239 [0.083, 0.417] | 0.003 | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 2, FAIL 2, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8547 unjudged (rate 0.9290) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.6890 [0.6594, 0.7191] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.4947 [0.4669, 0.5238] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 22.2051 [19.9253, 23.6570] | <= 3000 | target 1000 ms met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
