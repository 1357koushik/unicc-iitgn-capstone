# v2 on public cybersecurity retrieval benchmarks

Run 2026-11-18 on the IITGN server (12 parallel workers, all 48 hardware threads). Published numbers are taken from
the papers; we did not re-run those systems. Scripts: `scripts/external/`; tables with 95% bootstrap intervals:
`results/external/`.

## Benchmarks

| Benchmark | Source | Questions | Task for our engine |
|---|---|---|---|
| CTIConnect WIM | KDD 2026, CC-BY-4.0 | 308 | weakness description -> a CVE that instantiates it (any listed CVE counts) |
| CTIConnect ATD | same | 261 | CAPEC attack pattern -> ATT&CK technique |
| CTIConnect ATA | same | 160 | threat-report passage -> ATT&CK techniques |
| Text2TTP | AsiaCCS 2024 (QCRI) | 3,539 (2,017 manual + 1,522 TRAM) | threat-report sentence -> ATT&CK technique (top level) |
| CTID KEV mappings | MITRE CTID, KEV 07.28.2025, ATT&CK 16.1 | 419 CVEs, 1,183 mappings | NVD description of a KEV CVE -> mapped ATT&CK techniques |

Answers were checked against our corpus: 18 of 10,475 answer IDs are missing (17 questions, counted as misses), 176
retired ATT&CK IDs were redirected to their replacements. CTIConnect is scored over its own corpus (3,011 CVEs, 1,076
ATT&CK entries) at top 5, as the authors' code retrieves.

## Technique route

The mixed CVE + ATT&CK list cannot answer "which technique is this?": for a CVE description or a report sentence the
100 fused candidates are almost all CVEs (KEV: median 0 techniques among them). v2 now ranks techniques separately
(`threat_retrieval_engine/v2/techniques.py`, response field `attack_techniques`):

- Knowledge base from our ATT&CK build: 706 techniques, each with its description and its procedure examples
  (17,636 `uses` relationship texts, e.g. "APT29 used Mimikatz to dump credentials from LSASS memory"). CVE links,
  including the CTID KEV mappings stored in the build, are not used.
- Lists: keyword (BM25) + bge-large-en-v1.5 + Qwen3-Embedding-0.6B, best entry per technique, fused by reciprocal rank
  (k = 60). No reranker.
- Chosen on our own dev split (56 dev questions whose answers are ATT&CK techniques), not on the public sets:
  31 list combinations and 4 rerankers were compared (`results/external/techniques_selection.md`,
  `techniques_rerankers_dev.md`). The top combinations are within one question of each other on dev Recall@10; MRR
  and Hit@1 decided, then licence: SentSecBert (QCRI) improves dev by about one question but has no licence, so the
  served lists are the Apache/MIT-licensed ones. Every reranker (monoT5, SecureBERT 2.0 cross-encoder, int8
  bge-reranker, Qwen3-Reranker) lowered dev quality and cost 5-60 s per question on this CPU.
- Models tested and not served: SentSecBert_10k and monoT5 (QCRI Text2TTP, no licence stated; trained on Text2TTP
  data, so their Text2TTP scores are not comparable), SecureBERT 2.0 bi- and cross-encoder (Cisco, Apache-2.0),
  Qwen3-Reranker-0.6B (Apache-2.0).

## Results and published comparisons

| Benchmark | Metric | v2 before | v2 with technique route [95% CI] | Published (same data and metric) |
|---|---|---|---|---|
| Text2TTP | Recall@10 | 0.426 (as served) / 0.658 (ATT&CK only) | **0.906** [0.896, 0.915] | Text2TTP pipeline 0.921; Ladder 0.634; MITRE TRAM 0.458 |
| CTID KEV | Hits@10 | 0.002 / 0.251 | **0.730** [0.687, 0.771] | MiniLM 0.578; ATTACK-BERT 0.356 |
| CTID KEV | MRR@10 | 0.002 / 0.075 | **0.403** [0.366, 0.439] | MiniLM 0.252; ATTACK-BERT 0.136 |
| CTIConnect ATD | Hit@5 | 0.452 | **0.529** [0.467, 0.586] | vanilla RAG (text-embedding-3-large) 0.845*; + reranker 0.862*; best 0.985* |
| CTIConnect ATA | Hit@5 | 0.388 | **0.681** [0.606, 0.750] | 0.790*; + reranker 0.812*; best 0.890* |
| CTIConnect WIM | Hit@5 | 0.666 | 0.666 (CVE route, unchanged) | 0.845* |

\* CTIConnect publishes only category averages (4 linking tasks; 2 attribution tasks), not per task.

Text2TTP: 9 questions contain a whole knowledge-base entry; without them Recall@10 is still 0.906. The published
Text2TTP pipeline (0.921) uses models fine-tuned on Text2TTP data; ours uses none.

## Cost

Served configuration over HTTP on the server, 300 dev questions one at a time, technique route on: p50 0.52 s,
p95 0.70 s cold; p95 0.54 s warm; 300 of 300 HTTP 200 (`results/v2/latency/e2e-served-techniques.json`). The
technique stage takes about 0.3 s; `include_techniques: false` in the request or `TRE_TECHNIQUES=0` turns it off.
The CVE ranking (`top_matches`) is unchanged: the retriever code is not modified.

## Still open

- CTIConnect ATD/ATA remain below the published OpenAI-embedding RAG averages.
- Weakness description -> CVE (WIM) is unchanged at 0.666.
