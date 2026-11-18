# Evaluation report: v2_full on dev

**PROVISIONAL: 607 top-10 documents are unjudged (--allow-unjudged).** Values count an unjudged document as giving no gain; the 'if unjudged relevant' column shows the other extreme.

| Item | Value |
|---|---|
| Created (UTC) | 2026-11-18T06:20:17Z |
| Harness | b4-1 commit `6e96ce378a131db0ac47ed06f7aef5b3b5071340` |
| Dataset | version v2.0 at `D:\Project Course\unicc-iitgn-capstone\data\benchmark\v2.0` |
| Manifest sha256 | `e6ad5d503efed4744756bec4718d6dbe9251a7514fed1508c732aff5ccb1c77d` (files not verified against manifest) |
| Query file sha256 | `fc80741866790dfe17f33b5c70552faa9f7f8c5ee8c92fb38db7257391fb0b74` |
| Qrels file sha256 | `51de6d3666201eac1af7cdca2a9e819821ed16e154c24670257b61c79d62fdea` |
| Run file | `results\v2\runs\v2_full-dev.jsonl` sha256 `0bd617205d618d3c2ecada5b2a35ecac951a1d518cc78a6900b4332f864e759e` |
| Variant config | `{"adapter": "inprocess", "factory": "threat_retrieval_engine.v2.system:make_v2", "options": {"k": 100, "rerank": true, "rerank_depth": 10}}` |
| Server | localhost.localdomain (Linux-3.10.0-1160.99.1.el7.x86_64-x86_64-with-glibc2.17), load [10.52, 19.13, 19.38] -> [7.51, 9.2, 12.8] |
| Service health | `{"candidates": 100, "component": "v2_full", "dense": {"blas": {"blas": [{"internal_api": "openblas", "num_threads": 4, "version": "0.3.29"}, {"internal_api": "openblas", "num_threads": 4, "version": "0.3.29.dev"}], "mechanism": "threadpoolctl", "requested": 4}, "cache_size": 4096, "disk_cache": {"identity": "5f8a78190f1be41a1f6b", "path": "/home/koushik.moram/team2/dense/qvec/qvec-5f8a78190f1be41a` |
| Split / slices | dev / all |
| Queries | 1489 evaluated of 1489 selected |
| Settings | min_grade=2, abstain_is_miss=True, calib_depth=10, ece_bins=10, false_accept_min_tier=PARTIAL, bootstrap=10000, seed=20261114, ci=0.95, ni_alpha=0.025, ni_margin=0.01, ni_metrics=['ndcg@10', 'success@1'] |

Intervals are 95% query-level bootstrap percentile intervals (10000 resamples, seed 20261114); macro intervals are stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.

## Ranking quality

| Population | n | S@1 | S@5 | MRR@10 | nDCG@10 | R@10 | R@50 | R@100 | SetR@10 | Unjudged@10 |
|---|---|---|---|---|---|---|---|---|---|---|
| T0 | 106 | 0.698 [0.613, 0.783] | 0.896 [0.840, 0.953] | 0.779 [0.712, 0.844] | 0.758 [0.709, 0.805] | 0.874 [0.822, 0.922] | 0.914 [0.869, 0.953] | 0.942 [0.904, 0.974] | 0.861 [0.802, 0.914] | 98/1060 (0.092) |
| T1 | 150 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 135/1500 (0.090) |
| T2 | 99 | 0.657 [0.566, 0.747] | 0.808 [0.727, 0.879] | 0.719 [0.638, 0.797] | 0.723 [0.647, 0.795] | 0.791 [0.711, 0.866] | 0.835 [0.760, 0.905] | 0.870 [0.800, 0.931] | 0.648 [0.444, 0.838] | 49/990 (0.049) |
| T3 | 300 | 0.553 [0.497, 0.610] | 0.810 [0.767, 0.853] | 0.658 [0.612, 0.702] | 0.785 [0.760, 0.808] | 0.869 [0.835, 0.900] | 0.948 [0.925, 0.969] | 0.972 [0.955, 0.987] | 0.891 [0.863, 0.917] | 103/3000 (0.034) |
| T4 | 160 | 0.450 [0.375, 0.525] | 0.731 [0.662, 0.800] | 0.571 [0.507, 0.635] | 0.660 [0.614, 0.704] | 0.723 [0.666, 0.779] | 0.838 [0.786, 0.885] | 0.861 [0.811, 0.906] | 0.785 [0.735, 0.833] | 73/1600 (0.046) |
| T5 | 120 | 0.567 [0.475, 0.658] | 0.825 [0.758, 0.892] | 0.667 [0.595, 0.737] | 0.777 [0.731, 0.821] | 0.870 [0.811, 0.924] | 0.962 [0.927, 0.992] | 0.979 [0.952, 0.998] | 0.870 [0.785, 0.945] | 7/1200 (0.006) |
| T6 | 154 | 0.571 [0.494, 0.649] | 0.721 [0.649, 0.792] | 0.638 [0.567, 0.705] | 0.666 [0.610, 0.721] | 0.708 [0.643, 0.772] | 0.779 [0.716, 0.837] | 0.809 [0.749, 0.865] | 0.790 [0.721, 0.854] | 59/1540 (0.038) |
| T7 | 0 | – | – | – | – | – | – | – | – | 0/0 |
| T8 | 120 | 0.600 [0.517, 0.683] | 0.883 [0.825, 0.933] | 0.719 [0.654, 0.781] | 0.766 [0.723, 0.806] | 0.936 [0.894, 0.972] | 0.969 [0.936, 0.994] | 0.982 [0.955, 1.000] | 0.924 [0.869, 0.972] | 30/1200 (0.025) |
| T9 | 120 | 0.542 [0.450, 0.633] | 0.742 [0.658, 0.817] | 0.637 [0.561, 0.712] | 0.672 [0.606, 0.738] | 0.611 [0.530, 0.693] | 0.622 [0.542, 0.702] | 0.638 [0.558, 0.717] | 0.435 [0.337, 0.535] | 53/1200 (0.044) |
| **macro (slices)** | – | 0.626 [0.601, 0.652] | 0.824 [0.803, 0.845] | 0.710 [0.688, 0.730] | 0.756 [0.740, 0.773] | 0.820 [0.802, 0.839] | 0.874 [0.857, 0.890] | 0.895 [0.879, 0.910] | 0.801 [0.771, 0.829] | – |
| **overall** | 1329 | 0.617 [0.591, 0.643] | 0.820 [0.800, 0.841] | 0.702 [0.682, 0.724] | 0.761 [0.745, 0.776] | 0.825 [0.807, 0.843] | 0.884 [0.868, 0.900] | 0.904 [0.890, 0.919] | 0.798 [0.772, 0.822] | 607/13290 (0.046) |
| temporal_holdout | 73 | 0.603 [0.493, 0.712] | 0.877 [0.795, 0.945] | 0.709 [0.620, 0.796] | 0.807 [0.748, 0.861] | 0.873 [0.800, 0.936] | 0.965 [0.927, 0.993] | 0.978 [0.945, 1.000] | 0.874 [0.788, 0.953] | 20/730 (0.027) |
| T3+T4 | 460 | 0.517 [0.472, 0.561] | 0.783 [0.746, 0.820] | 0.627 [0.590, 0.663] | 0.741 [0.718, 0.763] | 0.818 [0.789, 0.847] | 0.910 [0.886, 0.932] | 0.934 [0.912, 0.953] | 0.848 [0.822, 0.874] | 176/4600 (0.038) |
| T9_id_name | 45 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.972 [0.948, 0.990] | 0.981 [0.952, 1.000] | 0.993 [0.978, 1.000] | 0.993 [0.978, 1.000] | 0.936 [0.833, 1.000] | 26/450 (0.058) |
| free_text | 1179 | 0.568 [0.540, 0.597] | 0.797 [0.774, 0.819] | 0.664 [0.641, 0.688] | 0.730 [0.713, 0.747] | 0.803 [0.782, 0.822] | 0.869 [0.851, 0.886] | 0.892 [0.875, 0.908] | 0.790 [0.764, 0.815] | 472/11790 (0.040) |

### Sensitivity to unjudged documents

| Population | unjudged | S@1 value / if unjudged relevant | S@5 value / if unjudged relevant | MRR@10 value / if unjudged relevant | nDCG@10 value / if unjudged relevant |
|---|---|---|---|---|---|
| T0 | 98 | 0.698 / 0.726 | 0.896 / 0.896 | 0.779 / 0.799 | 0.758 / 0.773 |
| T1 | 135 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 0.883 |
| T2 | 49 | 0.657 / 0.727 | 0.808 / 0.859 | 0.719 / 0.786 | 0.723 / 0.776 |
| T3 | 103 | 0.553 / 0.580 | 0.810 / 0.833 | 0.658 / 0.683 | 0.785 / 0.801 |
| T4 | 73 | 0.450 / 0.512 | 0.731 / 0.787 | 0.571 / 0.634 | 0.660 / 0.703 |
| T5 | 7 | 0.567 / 0.567 | 0.825 / 0.825 | 0.667 / 0.667 | 0.777 / 0.777 |
| T6 | 59 | 0.571 / 0.617 | 0.721 / 0.760 | 0.638 / 0.681 | 0.666 / 0.696 |
| T8 | 30 | 0.600 / 0.625 | 0.883 / 0.883 | 0.719 / 0.737 | 0.766 / 0.777 |
| T9 | 53 | 0.542 / 0.542 | 0.742 / 0.783 | 0.637 / 0.661 | 0.672 / 0.655 |
| overall | 607 | 0.617 / 0.646 | 0.820 / 0.844 | 0.702 / 0.731 | 0.761 / 0.765 |
| temporal_holdout | 20 | 0.603 / 0.603 | 0.877 / 0.877 | 0.709 / 0.709 | 0.807 / 0.781 |
| T3+T4 | 176 | 0.517 / 0.557 | 0.783 / 0.817 | 0.627 / 0.666 | 0.741 / 0.767 |
| T9_id_name | 26 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 0.972 / 0.905 |
| free_text | 472 | 0.568 / 0.601 | 0.797 / 0.824 | 0.664 / 0.697 | 0.730 / 0.750 |

Pairs to judge: 607 (export with `python -m benchmarks_v2.eval pool`).

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
| T0 | 106 | 1701 [1685, 1709] | 1750 [1740, 1763] | 1764 [1751, 1776] | 1776 |
| T1 | 150 | 699 [636, 868] | 1545 [1535, 1561] | 1588 [1552, 1717] | 1717 |
| T2 | 99 | 1455 [1395, 1479] | 1562 [1550, 1630] | 1633 [1561, 1699] | 1699 |
| T3 | 300 | 1382 [1343, 1421] | 1561 [1551, 1570] | 1598 [1572, 1627] | 1664 |
| T4 | 160 | 1270 [1164, 1412] | 1573 [1556, 1596] | 1679 [1587, 1698] | 1698 |
| T5 | 120 | 1175 [1048, 1334] | 1548 [1529, 1587] | 1602 [1552, 1714] | 1714 |
| T6 | 154 | 1501 [1481, 1520] | 1563 [1555, 1579] | 1646 [1570, 1696] | 1696 |
| T7 | 160 | 1473 [1399, 1497] | 1559 [1553, 1564] | 1569 [1563, 1599] | 1599 |
| T8 | 120 | 1320 [1177, 1441] | 1554 [1546, 1563] | 1565 [1558, 1565] | 1565 |
| T9 | 120 | 1463 [1440, 1506] | 1551 [1544, 1568] | 1674 [1551, 1710] | 1710 |
| overall | 1489 | 1436 [1410, 1453] | 1679 [1646, 1699] | 1735 [1728, 1743] | 1776 |
| temporal_holdout | 73 | 1436 [1342, 1504] | 1591 [1556, 1686] | 1695 [1586, 1721] | 1721 |
| T3+T4 | 460 | 1372 [1316, 1400] | 1564 [1557, 1573] | 1615 [1583, 1679] | 1698 |
| T9_id_name | 45 | 1511 [1471, 1522] | 1551 [1544, 1682] | 1648 [1550, 1710] | 1710 |
| free_text | 1339 | 1455 [1437, 1466] | 1686 [1664, 1702] | 1737 [1729, 1744] | 1776 |

## Derived queries against their parents

| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |
|---|---|---|---|---|---|
| T6_vs_clean | ndcg@10 | 154 | 0 | -0.087 [-0.139, -0.037] | 0.001 |
| T6_vs_clean | success@1 | 154 | 0 | -0.065 [-0.136, 0.006] | 0.085 |

## Release gates: FAIL (provisional: unjudged documents waived)

Configuration `D:\Project Course\unicc-iitgn-capstone\.claude\worktrees\agent-a1b3dad6ded1cbfbe\benchmarks_v2\eval\gates.yaml`, status draft. Counts: PASS 4, FAIL 6, MISSING 6, NOT_APPLICABLE 9, WAIVED 1

| Gate | Population | Status | Observed | Threshold | Note |
|---|---|---|---|---|---|
| judgement_completeness | overall | **WAIVED** | 607 unjudged (rate 0.0457) | <= 0 | waived with --allow-unjudged: every result is provisional |
| T1_success1 | T1 | **PASS** | 1.0000 [1.0000, 1.0000] | >= 1.0 |  |
| T9_id_name_success1 | T9_id_name | **PASS** | 1.0000 [1.0000, 1.0000] | >= 1.0 |  |
| T0_ndcg_vs_v1 | T0 | **MISSING** | n/a |  | no comparison against v1_match in report (score --compare <v1_match run>) |
| T2_success5 | T2 | **FAIL** | 0.8081 [0.7273, 0.8788] | >= 0.9, lower >= 0.85 |  |
| T3T4_recall10 | T3+T4 | **FAIL** | 0.8178 [0.7886, 0.8471] | >= 0.9 |  |
| T3T4_mrr10 | T3+T4 | **FAIL** | 0.6275 [0.5902, 0.6632] | >= 0.75 |  |
| T6_within5_ndcg | T6 | **FAIL** | diff -0.0872 [-0.1387, -0.0373] | diff >= -0.05 |  |
| T6_within5_success1 | T6 | **FAIL** | diff -0.0649 [-0.1364, 0.0065] | diff >= -0.05 |  |
| T8_success1 | T8 | **FAIL** | 0.6000 [0.5167, 0.6833] | >= 0.8 |  |
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
| latency_free_text_p95 | free_text | **PASS** | 1685.8359 [1664.1187, 1701.7097] | <= 3000 | target 1000 ms not met |
| no_http_504 | overall | **PASS** | 0 | <= 0 |  |

## Warnings

- manifest lists no sha256 for qrels_with_round1_all.jsonl; not verified
- 1 equivalence units have members judged with different grades (the maximum grade is used)
