# Evaluation report: v1_hybrid on train

**PROVISIONAL: 8694 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-15T20:37:43Z |
| Harness | b4-1 commit `2963e15604d0021516e2e36147bee7c740a3398e` |
| Dataset | version v2.0 at `data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files verified) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `de8ad6b51b2307eb0ca829b75013c32726a8ec2c5662f459e596288b128bbf8f` |
| Run file | `results\eval\runs\v1_hybrid-train.jsonl` sha256 `208a6b201644b1392bed892b52dd74faa33f21c52a63f7b02c47831712408602` |
| Variant config | `{"adapter": "http_v1", "base_url": "http://127.0.0.1:8765", "endpoint": "/api/v1/search/hybrid", "mapping": {"abstain_when_empty": false, "abstained": null, "doc_id": "chunk_id", "doc_id_resolver": {"kind": "sqlite", "path": "~/data/sqlite/corpus_store.db", "sql": "select doc_id from corpus where chunk_id = ?"}, "doc_id_transform": "cve_prefix", "probability": null, "results": "results", "score": "rrf_score", "tier": null}, "request": {"top_k": 10}, "timeout_s": 120.0}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [2.81, 8.59, 7.87] -> [4.76, 4.27, 4.42] |
| Service health | `{"components": {"bm25": "available", "confidence_model": "available", "embedder": "available", "knowledge_graph": "starter_stub", "qdrant": "available", "reranker": "available", "sqlite": "available"}, "degraded_components": [], "status": "healthy"}` |
| Split / slices | train / all |
| Queries | 920 evaluated of 920 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['ndcg@10', 'success@1'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T3 | 600 | 0.287 [0.250, 0.323] | 0.473 [0.433, 0.513] | 0.366 [0.332, 0.400] | 0.414 [0.380, 0.447] | 0.568 [0.528, 0.608] | 0.568 [0.528, 0.608] | 0.568 [0.528, 0.608] | – | 5651/5993 (0.943) |
| T4 | 320 | 0.147 [0.109, 0.188] | 0.325 [0.272, 0.375] | 0.219 [0.180, 0.259] | 0.256 [0.215, 0.296] | 0.376 [0.322, 0.429] | 0.376 [0.322, 0.429] | 0.376 [0.322, 0.429] | 0.146 [0.037, 0.284] | 3043/3174 (0.959) |
| **macro (slices)** | – | 0.217 [0.191, 0.243] | 0.399 [0.367, 0.431] | 0.293 [0.267, 0.319] | 0.335 [0.309, 0.362] | 0.472 [0.440, 0.505] | 0.472 [0.439, 0.505] | 0.472 [0.439, 0.505] | 0.146 [0.037, 0.285] | – |
| **overall** | 920 | 0.238 [0.211, 0.265] | 0.422 [0.390, 0.453] | 0.315 [0.289, 0.341] | 0.359 [0.333, 0.385] | 0.501 [0.469, 0.533] | 0.501 [0.469, 0.533] | 0.501 [0.469, 0.533] | 0.146 [0.038, 0.280] | 8694/9167 (0.948) |
| T3+T4 | 920 | 0.238 [0.211, 0.266] | 0.422 [0.389, 0.453] | 0.315 [0.288, 0.342] | 0.359 [0.332, 0.386] | 0.501 [0.469, 0.535] | 0.501 [0.469, 0.535] | 0.501 [0.469, 0.535] | 0.146 [0.035, 0.280] | 8694/9167 (0.948) |
| free_text | 920 | 0.238 [0.211, 0.266] | 0.422 [0.390, 0.454] | 0.315 [0.288, 0.341] | 0.359 [0.332, 0.386] | 0.501 [0.470, 0.534] | 0.501 [0.470, 0.534] | 0.501 [0.470, 0.534] | 0.146 [0.035, 0.287] | 8694/9167 (0.948) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T3 | 5651 | 0.287 / 1.000 | 0.473 / 1.000 | 0.366 / 1.000 | 0.414 / 1.000 |
| T4 | 3043 | 0.147 / 1.000 | 0.325 / 1.000 | 0.219 / 1.000 | 0.256 / 0.998 |
| overall | 8694 | 0.238 / 1.000 | 0.422 / 1.000 | 0.315 / 1.000 | 0.359 / 0.999 |
| T3+T4 | 8694 | 0.238 / 1.000 | 0.422 / 1.000 | 0.315 / 1.000 | 0.359 / 0.999 |
| free_text | 8694 | 0.238 / 1.000 | 0.422 / 1.000 | 0.315 / 1.000 | 0.359 / 0.999 |

Pairs to judge: 8694 (export with `python -m benchmarks_v2.eval pool`).

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
| T3 | 600 | 3652 [3574, 3735] | 4966 [4743, 5192] | 5868 [5667, 5954] | 6370 |
| T4 | 320 | 3589 [3513, 3777] | 4832 [4614, 5383] | 5701 [5453, 5845] | 6076 |
| overall | 920 | 3626 [3572, 3723] | 4944 [4743, 5094] | 5844 [5660, 5938] | 6370 |
| T3+T4 | 920 | 3626 [3574, 3721] | 4944 [4789, 5094] | 5844 [5660, 5938] | 6370 |
| free_text | 920 | 3626 [3573, 3723] | 4944 [4789, 5094] | 5844 [5660, 5938] | 6370 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | – | 0 | 0 | – | – |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 1, FAIL 3, MISSING 19, NOT_APPLICABLE 2, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 8694 unjudged (rate 0.9484) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **MISSING** | n/a |  | population T1 not in report |
| T9_id_name_success1 | T9_id_name | **MISSING** | n/a |  | population T9_id_name not in report |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **MISSING** | n/a |  | population T2 not in report |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.5015 [0.4688, 0.5346] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.3148 [0.2884, 0.3418] | >= 0.75 |  |
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
| latency_free_text_p95 | free_text | **FAIL** | 4943.6767 [4788.9354, 5093.7433] | <= 3000 | target 1000 ms not met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |
