# v2 on public cybersecurity retrieval benchmarks

Run 2026-11-18 on the IITGN server (12 workers x 4 threads, all 48 hardware threads; 4,687 questions in 5 min).
Served configuration: ID, name and nickname routes + keyword/dense fusion, reranker off. Scripts: `scripts/external/`;
full tables with 95% bootstrap intervals: `results/external/`. Published numbers are taken from the papers; we did
not re-run those systems.

## Benchmarks

| Benchmark | Source | Questions | Task for our engine |
|---|---|---|---|
| CTIConnect WIM | KDD 2026, CC-BY-4.0 | 308 | weakness description -> a CVE that instantiates it (any of the listed CVEs counts) |
| CTIConnect ATD | same | 261 | CAPEC attack pattern -> ATT&CK technique |
| CTIConnect ATA | same | 160 | threat-report passage -> ATT&CK techniques |
| Text2TTP | AsiaCCS 2024 (QCRI) | 3,539 (2,017 manual + 1,522 TRAM) | threat-report sentence -> ATT&CK technique (top level) |
| CTID KEV mappings | MITRE CTID, KEV 07.28.2025, ATT&CK 16.1 | 419 CVEs, 1,183 mappings | NVD description of a KEV CVE -> mapped ATT&CK techniques |

Answers were checked against our corpus: 18 of 10,475 answer IDs are missing (17 questions), 176 retired ATT&CK IDs
were redirected to their replacements, 2 Text2TTP sentences also appear in our ATT&CK descriptions. Missing answers
count as misses.

## Results and published comparisons

| Benchmark | Metric | v2 (our corpus, target kind) | v2 (benchmark's own corpus) | Published |
|---|---|---|---|---|
| CTIConnect WIM | Hit@5 | 0.104 | 0.666 | vanilla RAG, text-embedding-3-large, top-5: 0.845 (average of 4 linking tasks); + bge-reranker 0.862; best task-specific 0.985 |
| CTIConnect ATD | Hit@5 | 0.437 | 0.452 | same averages as above |
| CTIConnect ATA | Hit@5 | 0.388 | 0.388 | 0.790 (average of 2 attribution tasks); + reranker 0.812; best 0.890 |
| Text2TTP | Recall@10 | 0.658 | – | Text2TTP pipeline (BM25 + fine-tuned SecBERT + MonoT5) 0.921; Ladder 0.634; MITRE TRAM 0.458 |
| CTID KEV | Hits@10 / MRR | 0.251 / 0.075 | – | MiniLM 0.578 / 0.252; ATTACK-BERT 0.356 / 0.136 (SMSI, 45-CVE test split) |

As served (CVEs and ATT&CK searched together, one ranked list) the ATT&CK tasks score lower still: Text2TTP
Recall@10 0.426, KEV Hits@10 0.002, because CVE documents fill the 100 candidates (KEV: median 0 techniques among
them). CTIConnect does not define Hit Rate in the paper; the authors' code retrieves top 5 from one knowledge base per
task, and only category averages are published.

## What this shows

- On mapping text to ATT&CK techniques and on CWE-style weakness text to CVEs, v2 is below current published
  systems. It is above the older public tools (MITRE TRAM, Ladder) on Text2TTP.
- Causes, in order of size: (1) the served API ranks CVEs and ATT&CK in one list, so technique questions are crowded
  out; (2) ATT&CK documents are indexed with their description only, while Text2TTP's knowledge base uses 11,412
  procedure examples; (3) a general embedder (bge-large) against text-embedding-3-large or fine-tuned security models;
  (4) fusion weights tuned on our CVE-centred dev split.
- The served reranker-off order and fused search give the same scores here (the name routes rarely fire on these
  questions).
