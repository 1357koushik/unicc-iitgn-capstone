# Retrieval Engine v2 — Engineering Plan (Revision 4)

Scope: `threat_retrieval_engine/` only (retrieval, confidence scoring, PoC attachment).
Out of scope: `llm/`, `backend/`, `frontend/`, `network_sensor/`.
Status: plan only. Nothing here is implemented.
Measured on the IITGN server on 2026-11-14.

Revision 3 applied the owner's decisions. Revision 4 is a production-readiness review of Revision 3; its findings are listed in section 11 and fixed in place. The governing rule: **quality is the constraint, speed is what gets optimised within it, and nothing in scope is optional.**

---

## 0. Ground rules

1. **Quality is never traded for speed.** A faster option is chosen only when it is statistically no worse than the best option measured.
2. **Everything in this plan ships.** There is no "nice to have" tier and no cut list.
3. **No silent fallbacks.** If a component is degraded or unreachable, the response and the health endpoint say so. No feature ships switched off.
4. **No claim without an automated check.** Every work package ends with a script that prints pass or fail. An independent session re-runs those checks from a clean checkout. The owner reads one report and checks nothing by hand.
5. **No manual labelling by the owner.** Labelling is done by models with cross-checks (6.4).
6. **English only.**

---

## 1. Review record

### 1.1 Assumptions that held

| Claim | Evidence |
|---|---|
| SQLite FTS5 is usable | compiled into the `py312` SQLite 3.53; custom token characters and per-column BM25 weights both work |
| Exact vector search is fast enough | 357,000 × 1,024 float32 vectors: 39 ms median, 52 ms worst, 43 ms with a filter mask |
| Deploy by `git push` to the server | git 1.8.3 is installed |
| `bm25s` and OpenVINO install | both resolve to wheels that fit glibc 2.17 |

### 1.2 Assumptions that were wrong in Revision 1

| Revision 1 said | Measured or found | Consequence |
|---|---|---|
| Rerank 30 candidates in 700 ms with a mid-size model | the current reranker needs 8.7–10.7 s for 30 short passages, 20–22 s with today's text | the reranker's quality is kept and its cost is engineered down (4.6) |
| Re-embed overnight and compare five models on the full corpus | BGE-M3 embeds 6.6 documents per second: about 15 hours per pass | compare on a reduced corpus, then run the full pass for the winner as an unattended job (4.5) |
| ONNX Runtime or FAISS as fallbacks | neither installs on this glibc | OpenVINO or PyTorch dynamic quantization |
| "p95 1.5 s at 4 concurrent requests" | inference uses every core, so concurrent requests queue | single-request latency, throughput and a bounded queue (4.9) |
| An exact alias match is `EXACT` | aliases can be noisy or ambiguous | `EXACT` is for identifiers only (4.7) |
| Advisory summaries are independent text for any CVE | reviewed advisories mostly cover open-source packages; unreviewed ones copy NVD | restricted, filtered, and no longer the main slice (6.2) |
| Vendor and product come from NVD CPE data | 43% of the corpus is dated 2024–2026, where NVD enrichment is often missing | CVE List `affected` data as second source (4.2) |
| Team 1's normalizer can feed the build | it resolves one CVE at a time by scanning a year file | a streaming bulk pass (C1) |

### 1.3 What Revision 1 missed

1. **The real workload.** Team 3 sends the raw incident observation as the query, with `top_k=5`: a paragraph naming an actor, malware, CVEs, an IP and a domain.
2. **The contract in use.** Team 3 reads `composite_score`, `confidence_tier`, `citations[0]`, `stix_relationships`, `attribution`, `evidence_breakdown`. The backend and frontend call `/api/v1/pocs/find`.
3. **Timeouts do not stop work.** HTTP 504 is returned at 15 s, but the worker thread keeps running and blocks later requests.
4. **Ingestion drops and distorts data.** Near-duplicate removal is applied to CVE records; a KEV listing overwrites severity to HIGH; EPSS is kept only when the score is at least 0.5.
5. **No operations story, no scoring audit, no statistical rigour on the gates.**

### 1.4 Decisions taken in Revision 3

| Topic | Decision | Reason |
|---|---|---|
| Reranking | Keep full reranker quality. The serving configuration must be statistically no worse than the large reranker; speed comes from distillation, quantization and cascading, never from accepting a weaker ranking | owner: no quality compromise |
| "Ship without a reranker" | removed as a fallback | same |
| Embeddings | the model with the best dev quality wins; the full re-embed runs whenever the gain is statistically significant | 15 hours is machine time, not a reason to keep worse vectors |
| Alias coverage | sources are added until the nickname slice gate passes; the test list is never copied in | production quality |
| Duplicate removal | rewritten (4.2) | owner instruction |
| Query prefix | follow the embedding model's documented format (no prefix for BGE-M3); confirmed by an ablation whose result is binding | decided here, verified by measurement |
| OpenVINO | used as described; PyTorch dynamic quantization if it fails on this CPU | accepted |
| Tier meaning | `STRONG` ≥ 95% precision, `PARTIAL` ≥ 70%, `WEAK` ≥ 30% | `STRONG` is what a consumer may state as established, so it gets the strict bound |
| ATT&CK content | in scope and required | Team 3's real queries name actors and malware, and `stix_relationships` is a field they read; today it is filled from a fake stub |
| Language | English only | owner decision |
| Authentication | none required; the service is private and listens on localhost only | owner decision |
| Labelling | done by models: Sonnet as first judge, Opus as second judge and adjudicator, validated against items whose answer is known (6.4) | owner: no manual labelling |
| Live PoC lookup | enabled on the server in production, alongside the snapshot | owner: full production behaviour, nothing held back |
| Where PoC is tested | on the server: the PoC benchmark (recorded and live runs) and the acceptance run all execute there; the PC is used only to edit code | owner decision of 2026-11-14, replacing the earlier "PC only" rule: the server now has internet access, and it is where the code serves |
| Priorities | every work package is required | owner: everything production ready |

### 1.5 Still to be measured

Each item is resolved inside the named work package by a recorded measurement; none needs the owner.

| Question | Resolved in |
|---|---|
| Alias coverage of the nickname slice | C1 |
| Which serving configuration matches the large reranker | C5 |
| OpenVINO behaviour on this CPU | C5 |
| How many CVEs the old duplicate removal dropped | C1 reconciliation |
| Source licences | B1 |
| Portal session lifetime and keep-alive support | D4 |

---

## 2. Constraints and baseline

### 2.1 Constraints

| Constraint | Consequence |
|---|---|
| CPU only: 2 × Xeon Gold 6136, 48 threads, 251 GB RAM, CentOS 7.9, glibc 2.17 | cost is engineered down by distillation, quantization and caching; many modern wheels do not install |
| No Docker, no root, no cron, no tmux (`screen` available), shared machine | in-process components; a user-level supervisor |
| Internet only while the portal login is active | the service states its network status; local data covers every outage (4.8, D4) |
| Team 3 and the backend consume the API | fields in 1.3 keep their names; changes in meaning are documented and covered by a contract test |

### 2.2 Baseline of the current system

| What | Result |
|---|---|
| 29 known-answer queries | hit@1 11/29, hit@10 19/29, MRR 0.47 |
| Nicknames | rank 1 in 3 of 14; top 10 in 5 of 14 |
| Exact CVE ID via hybrid search | rank 1 in 0 of 2 |
| `/threats/match` latency | 8–15 s; 4 of 8 calls returned HTTP 504 |
| Stage cost, free text | retrieval and rerank 10.6 s; all else under 10 ms |
| Stage cost, CVE-ID query | exact lookup 5.7 s, then retrieval and rerank 6.9 s |
| Query `CVE-2014-0160` | ranks 2 and 3 are different CVEs marked STRONG at probability 1.0 |
| Three different PAN-OS CVEs | all STRONG at 0.99 |
| Query embedding (BGE-M3) | 130–200 ms median, up to 640 ms |

Corpus: 362,301 rows for 356,925 CVEs (NVD 356,382; EPSS 4,135; KEV 1,593; CVE List 191). Only the description is indexed. Zero rows mention "log4shell", "eternalblue" or "bluekeep". 149 KEV CVEs and 255 EPSS CVEs have no NVD row. 1,839 rejected records and 210 near-empty ones are indexed. There is no IOC, actor or ATT&CK content; the "graph" is an 8-node hardcoded stub.

---

## 3. Scoring audit

### 3.1 Main pipeline

| # | Score (where) | Used for | Verdict | What is wrong | Standard method |
|---|---|---|---|---|---|
| 1 | BM25, k1 1.5, b 0.75 (`bm25_index.py`) | lexical candidates | formula correct; setup not | pure-Python scoring; one field; untuned | BM25 with per-field weights in a real index; parameters tuned on dev |
| 2 | Cosine on BGE-M3 vectors (`vectorizer.py`) | dense candidates | correct in principle | boilerplate and the CVE ID are embedded; a prefix from another model family is added | embed clean content in the model's documented format |
| 3 | Weighted Reciprocal Rank Fusion, k 60 (`hybrid_search.py`) | merging lists | correct and standard | depth fixed at 50; weight untuned | keep RRF; tune depth and weights; never use the fused score as confidence |
| 4 | Reranker score with `normalize=True` (`reranker.py`) | ordering; confidence input | incorrect use | sigmoid saturates (unrelated CVEs at 0.99); treated as a probability | rank on raw logits; calibrate separately on in-domain data |
| 5 | `semantic_sim = dense_score or rerank_score` (`pipeline.py:487`) | reported similarity | incorrect | two scales in one field | one field per score |
| 6 | Logistic model, 12 features, Platt scaling (`confidence.py`) | `composite_score`, tier | method acceptable; model invalid | trained on near-verbatim pairs; artificial 1:3 prior; duplicated features; BM25 feature is a stand-in at serving time | features from the live pipeline; judged hard negatives; held-out calibration; reliability per query type |
| 7 | Tier cut-offs 0.65 / 0.45 / 0.10 | tier label | not justified | hand-picked | thresholds that meet stated precision on dev, frozen, confirmed on a sealed test |
| 8 | Layer 1 `EXACT` (`confidence.py`) | deterministic tier | right idea, wrong rules | fails for multi-CVE queries; parses `doc_id`; awards `EXACT` to an EPSS stub | per-identifier match against a primary key |
| 9 | Behavioural heuristic 0.2 / 0.4 / 0.2; degraded composite | probability for IOC and technique queries | not acceptable | hand weights presented as probability | deterministic lookup with a reason code; probability only from the calibrated model |
| 10 | Coverage ratios (`feature_extractor.py`) | features, `evidence_breakdown` | acceptable as features | substring entity detection; mislabelled "similarity" | computed from an entity index; named coverage |
| 11 | Final sort by probability, record class, dense score (`pipeline.py:546`) | result order | incorrect | sorting on a saturated value | order by ranking score; confidence reported, not sorted on |
| 12 | `corroboration_count` | evidence strength | incorrect | counts within one row | independent sources per CVE from provenance |
| 13 | EPSS from prose by regex; stored only if ≥ 0.5 | risk context | incorrect | 99% of EPSS discarded | score, percentile, date as columns for every CVE |
| 14 | Severity bands; KEV forces HIGH (`validator.py`) | filter, display | bands correct; override wrong | exploitation is not severity | CVSS as published with version and source; KEV separate |
| 15 | Near-duplicate removal at 0.90 (`duplicate_checker.py`) | ingestion | wrong tool | distinct CVEs can be dropped | identity by CVE ID and content hash (4.2) |
| 16 | Skip rerank at 70% of deadline, graph at 85% | degradation | idea correct | silent | per-stage budgets; skipped stages named in the response |
| 17 | Hit@k, MRR, nDCG, macro-F1 (`benchmarks/metrics.py`) | gates | formulas correct | 10 hand-matched queries | same metrics on an independent collection with intervals |

Relevance and risk stay separate: CVSS, EPSS and KEV never change match confidence.

### 3.2 PoC system

| # | Score (where) | Used for | Verdict | What is wrong | Standard method |
|---|---|---|---|---|---|
| 1 | Additive `confidence_score` (`poc_validator.py`) | ranking, labels | not validated | guessed weights on keyword presence; "rce" counts as proof | trust by provenance; a fitted classifier for unknown repositories |
| 2 | Label cut-offs 0.70 / 0.45 / 0.35 / 0.25 | labels | not justified | no measured precision | thresholds from a precision–recall curve |
| 3 | Stars ≥ 20 or ≥ 5 | "community validation" | weak | easily inflated | minor feature relative to repository age |
| 4 | Cross-source bonus | corroboration | incorrect | counts amplification | count independent curated listings only |
| 5 | Binary, obfuscation, scam penalties | safety | too shallow | description regex only | metadata checks (file tree, binary-only releases, account age, known-bad lists); any hit forces `SUSPICIOUS` |
| 6 | `evidence_rank`, sort by "updated" (`github_scraper.py`) | pre-ranking | incorrect | favours fresh spam; truncates before validation | gather, validate, then rank by relevance |
| 7 | `precision_score` | reported quality | misnamed | self-referential | measured precision offline; field renamed |
| 8 | Cache lifetime 6 h, 1 h for KEV | freshness | reasonable | one lifetime for all | lifetime by CVE age; negative lifetime; stale-while-refresh |
| 9 | No exploitation status | analyst decision | missing | links without meaning | `active`, `weaponized`, `poc_public`, `none_known` (CVSS Exploit Maturity and SSVC Exploitation vocabulary), with EPSS beside it |

---

## 4. Target design

### 4.1 Request flow

1. Admission: bounded inference slots and a short queue; beyond that HTTP 503 with `Retry-After`.
2. Parse once into identifiers, named entities and free text.
3. Identifier and entity routes answer from indexed tables.
4. Free text: lexical and dense candidates, fused.
5. Rerank.
6. Score: deterministic tier for identifiers, calibrated probability otherwise, abstention decision.
7. Attach structured facts, ATT&CK relationships and PoC information.
8. Every stage checks the remaining deadline; anything skipped is named in the response.

### 4.2 Document store and the rewritten duplicate handling

**Store.** A streaming pass over the raw feeds builds one row per CVE.

- Text fields: `title`, `description`, `vendor_product`, `weakness`, `aliases`, `kev_text`.
- `vendor_product` from NVD CPE data, else from the CVE List `affected` block, capped at 10 distinct pairs; coverage reported per year.
- Structured columns: CVSS (all versions with source), CWE, CPE list, KEV fields, EPSS for every CVE, references, state, dates, provenance.
- Rejected and reserved CVEs are stored and excluded from search. No severity override.

**Duplicate handling, replacing `duplicate_checker.py`.**

| Case | Old behaviour | New behaviour |
|---|---|---|
| Same CVE from the same source, same content | may be re-inserted | recognised by content hash; skipped |
| Same CVE from the same source, changed content | depends on similarity | updated in place; change recorded; vector refreshed |
| Same CVE from different sources | separate rows | merged into the CVE's row with per-source provenance |
| Different CVEs with near-identical text | later one silently dropped | both kept; linked by a `similar_group` ID used only to group siblings in results |
| Free-text documents (ATT&CK objects, any future reports) | dropped at 0.90 similarity | identity by source ID; near-duplicates linked to a canonical copy, never deleted |
| Any record not stored | silent | written to a `rejected_records` table with the reason |

Build check: for each feed, records read = stored + rejected with reason. A mismatch fails the build. The same check reports how many CVEs the old logic dropped.

### 4.3 Aliases

`aliases(cve_id, alias, source)` from Exploit-DB titles, Metasploit module names, nuclei template names, KEV names and CVE List titles, extended with further public exploit and advisory metadata until the nickname gate (6.7) passes. Benchmark query sources are never ingested, and the test list is never copied in; both rules are enforced by tests.

### 4.4 ATT&CK content

- MITRE ATT&CK Enterprise objects (groups, software, techniques, mitigations) are ingested as documents with `doc_kind`, searchable alongside CVEs.
- Their relationships form the graph that fills `stix_relationships`; every relationship carries its ATT&CK source ID. The hardcoded stub is deleted.
- Names and aliases from ATT&CK replace the hardcoded actor, malware and tool lists in the parser.
- CVE links come from CVE references inside ATT&CK objects and from the public KEV-to-ATT&CK mappings, subject to licence (B1).

### 4.5 Parsing, routing and candidate retrieval

**Parser.** One module replaces the three in `helpers.py`, `confidence.py` and `tokenizer.py`.

| Query contains | Handling |
|---|---|
| CVE ID(s) | primary-key lookup per ID; a well-formed ID that is absent returns `not_in_corpus` |
| CVE ID(s) inside a narrative | ID results first, then retrieval on the remaining text; both labelled |
| ATT&CK ID, group, software or technique name | entity lookup into ATT&CK documents and their relationships, plus retrieval |
| Hash, IP or domain | indexed entity lookup; no hit returns `UNSUPPORTED` with reason `no_ioc_data_in_corpus` |
| Free text | hybrid retrieval |

Model input is capped at 256 tokens; identifiers are parsed from the full text.

**Lexical.** FTS5 over the text fields with per-field weights, pre-tokenized by the domain tokenizer.

**Dense.** A float32 matrix read fully into memory at start (not lazily paged, so other users' jobs on the shared machine cannot push it out to disk), one BLAS product per query (measured 39 ms).

**Embedding model, chosen for quality.**

1. Export the existing vectors so a dense index exists from the first day.
2. On a reduced corpus (every benchmark target, every CVE sharing a vendor–product with a target, 50,000 random CVEs), compare BGE-M3 on clean text against strong English models (`bge-large-en-v1.5`, `bge-base-en-v1.5`, `e5-large-v2`, `gte-large`), each in its documented query format.
3. The model with the best dev Recall@50 and nDCG@10 wins. If it is significantly better than the existing vectors, the full re-embed runs (unattended under `screen`, checkpointed every 5,000 documents, resumable). Encode latency breaks ties only.

**Fusion.** RRF over 100 candidates per list; depth and weights tuned on dev.

### 4.6 Reranking at full quality

The large cross-encoder is too slow to serve directly, so its ranking quality is preserved by other means.

1. **Quality ceiling.** Run the large reranker offline on the dev set at depth 50. This is the reference every serving option is compared with.
2. **Teacher scores.** The train split alone (about 920 queries) is too small to distil a ranker. About 10,000 extra training queries are written by Sonnet for CVEs that appear in neither dev nor test, and the large reranker scores the top 20 candidates of every training query offline.
3. **Serving options built and measured:**
   - a small cross-encoder distilled from the teacher scores and fine-tuned on this domain;
   - the large reranker quantized to int8 with OpenVINO, applied to the top 5–10 after a fast first pass (cascade);
   - the distilled model followed by the quantized large model on the top 5;
   - a gradient-boosted ranker on retrieval features, as an additional input to any of the above.
4. **Selection rule.** A configuration qualifies only if it is non-inferior to the ceiling on nDCG@10 and Success@1 (paired bootstrap, margin 1 point). Among qualifying configurations the fastest is chosen. If the fastest qualifying one misses the latency target, it is still the one that ships, and the measured latency is reported.
5. Ranking uses raw logits. Text is clean, capped at 256 tokens, length-sorted, with the thread count fixed by measurement.

### 4.7 Confidence

- **Order** by ranking score; identifier results first.
- **`EXACT`** only when the result's CVE (or ATT&CK ID) equals an identifier in the query. No probability is attached.
- **Calibrated probability** otherwise: a logistic model over ranking score, margin to the next distinct document, dense cosine, lexical rank, retriever agreement, vendor–product overlap, alias hit, query length. Negatives come from this pipeline's own top results and are judged (6.4).
- **Prior.** Fitted and reported on a stated query mix (narratives 50%, short lookups 30%, unanswerable 20%) and per slice.
- **Tiers.** `STRONG` ≥ 95% precision, `PARTIAL` ≥ 70%, `WEAK` ≥ 30%, else `UNSUPPORTED`; thresholds found on dev, frozen, confirmed on the sealed test.
- **Abstention** with a reason code.
- **`composite_score`** keeps its name and now means calibrated probability of relevance; `evidence_breakdown` gains `rerank_logit`, `dense_cosine`, `lexical_rank`.
- **Removed:** behavioural heuristic, substring lists, stub graph, EPSS regex, legacy composite, severity override.

### 4.8 PoC

1. **Targets:** CVE IDs in the query plus CVEs of `EXACT` or `STRONG` results, at most 3.
2. **Attach** only where the result's CVE equals the PoC's CVE.
3. **Two sources, both active in production:**
   - a local index built from Exploit-DB, Metasploit metadata, nuclei templates and an aggregated GitHub PoC list, refreshed on a schedule whenever the network is up. Only the first three are curated. Repositories from the aggregated list are known to include fakes, so they still pass the classifier in item 8;
   - live lookup on GitHub, Mastodon and Bluesky for anything newer than the local index, with its own deadline, separate from the match deadline.
4. **Result merging:** local and live results are merged, de-duplicated by canonical URL, and labelled by trust tier.
5. **Exploitation status** per CVE (3.2 row 9) with EPSS and KEV beside it.
6. **Network state is explicit.** A circuit breaker recognises the captive portal (certificate mismatch or an `fgtauth` body). While sources are unreachable the response carries `live_sources: unreachable`, the local index and cache still answer, and live lookup resumes by itself when the network returns.
7. **GitHub:** relevance sort; gather, validate, then rank; forks and copies clustered. GitHub allows about 30 searches a minute, far below the service's query rate, so one shared rate limiter guards all live calls. When the budget is used up the response carries `live_sources: rate_limited` and the local index answers. The token is a dedicated one with no scopes, not a personal account's.
8. **Trust tiers:** `CURATED_EXPLOIT`, `LISTED_POC_REPO`, `LIVE_CANDIDATE`, `DISCUSSION`, `SUSPICIOUS`. Live candidates pass a classifier fitted on labelled repositories and thresholded for at least 95% precision. Any risk signal forces `SUSPICIOUS`.
9. **Safety:** descriptions stay flagged as untrusted; code is never downloaded or executed.
10. **Privacy:** a live lookup sends only a CVE ID to the outside service, never query text. This still reveals which CVEs are being investigated; it is documented, and outbound calls go only to an allow-list of hosts.
11. **Cache:** lifetime by CVE age, negative lifetime, stale-while-refresh. It moves to its own database file; today it is written into the corpus database at query time.
12. **X (Twitter)** needs a paid API and has no credentials, so the connector is removed and requests naming it are answered with `source_not_supported`. Nothing ships as a disabled switch.
13. `precision_score` is deprecated in favour of `labelled_poc_share`.

### 4.9 Latency and capacity

Quality gates take precedence. These are targets to optimise toward; the limits are hard.

| Stage | Target p95 | Basis |
|---|---|---|
| Identifier or entity route | 50 ms | indexed lookups |
| Query embedding | 250 ms | measured 130–200 ms median |
| Dense search | 60 ms | measured 39 ms |
| Lexical search | 30 ms | measured in C2 |
| Rerank | 500 ms | set by the qualifying configuration in C5 |
| **Free text, single request** | **target 1.0 s; hard limit 3.0 s** | |
| Throughput | at least 2 requests/s | bounded inference slots |
| Overload | HTTP 503, never 504, no work left running | admission control |

A response cache for repeated identical queries and a cache for query embeddings are part of the design; they reduce load without affecting results.

---

## 5. Production readiness

### 5.1 Requirements

| Area | Requirement |
|---|---|
| Admission control | bounded slots and queue; 503 with `Retry-After`; no abandoned work after a timeout |
| Index builds | versioned directory per build (store, vectors, manifest with corpus hash, model names, counts); service reads a `CURRENT` pointer |
| Updates | incremental by content hash; EPSS and KEV refresh update columns only; build, smoke benchmark, pointer swap, restart |
| Rollback | one command; rehearsed and timed |
| Supervision | restart-loop script under `screen`; `/health` reports build ID, models, network state and degraded components; `/ready` gates traffic |
| Network dependency | portal session lifetime measured; keep-alive used if the portal supports it without storing a password; network state exposed in `/health` |
| Scheduling | the server has no cron, so feed sync, PoC index refresh and the daily self-check run from a timer loop inside the supervisor |
| Freshness | `/health` reports corpus and PoC index age; responses carry the build date; a stale build is reported, not hidden |
| Startup integrity | the service refuses to start if document, vector and lexical-index counts differ, a checksum fails, or the calibrator was fitted for a different embedding model, reranker or fusion setting |
| Logging and metrics | one structured line per request (stage timings, route, tier, degraded stages; query text as a hash unless a debug flag is set); a `/metrics` endpoint with request counts, latency percentiles, queue depth, cache hit rates and tier shares |
| Security | no API key is required: the service is private, bound to localhost and reached through the SSH tunnel (owner decision; the existing optional key check stays in the code, unused); query length limit; no pickle loading; all retrieved and PoC text treated as untrusted data; `.env` readable by its owner only |
| Input hardening | the parser regexes and the lexical query builder are fuzz-tested with long and malformed input; user text can never reach the lexical index as query syntax |
| Supply chain | dependencies pinned and audited for known vulnerabilities; models pinned to a revision with checksums; model and dataset licences recorded |
| API compatibility | `alpha` is still accepted but ignored and reported as such (Team 3 always sends 0.5, which would otherwise override the tuned fusion); `allowed_sources` matches a CVE that has any listed source; `top_k` counts documents, not rows; the deprecated routes Team 3 falls back to stay; responses carry `schema_version` |
| Dev and prod parity | code is edited on Windows, served on CentOS 7 with Python 3.12, and also built by other teams from `Dockerfile.retrieval` on Python 3.11 at port 8000. All three are kept working: no platform-specific paths, the Docker image and compose service updated and tested, CI on Linux |
| Source control | work on a `team2/retrieval-v2` branch, one pull request per work package, reviewed by the verification session before merge; other teams' tests must stay green |
| Testing | unit tests; integration test on a 2,000-document fixture that runs in CI; contract test built from Team 3's client; a 200-query smoke benchmark before every index swap |
| Rollout | v2 beside v1 on another port; both answer the benchmark and Team 3's integration script; switch after the gates pass |
| Packaging | `pip install -e .`, pinned lock file, mirrored wheels, deploy by `git push` to a bare repository on the server |

### 5.2 Behaviour on failure

| Failure | Behaviour |
|---|---|
| Index files inconsistent, or calibrator mismatch, at start | refuses to start; the previous build stays current |
| A model fails to load at start | `/ready` stays false; no traffic is served |
| A stage errors or runs out of budget during a request | the request is answered from the remaining stages, the stage is named in the response, and the tier is capped at `PARTIAL` because calibration no longer holds |
| Queue full | HTTP 503 with `Retry-After` |
| Network down or portal login lapsed | `live_sources: unreachable`; local index and cache answer; automatic recovery |
| GitHub rate limit reached | `live_sources: rate_limited`; local index answers; retry after the reset time |
| Corpus older than the freshness threshold | served, with the age in the response and in `/health` |
| Disk full or log write fails | the request is still served; `/health` reports the fault |
| Process crash | the supervisor restarts it; `/ready` gates traffic until models are loaded |

### 5.3 Definition of "production ready"

All of the following are produced by scripts, not by inspection:

1. Every release gate in 6.7 and 6.8 passes on the sealed test.
2. The server acceptance script passes after deploy: service starts from a clean checkout; health reports the expected build; one query per route returns the expected shape; overload returns 503; a simulated network outage is reported and recovered from; PoC local and live lookups both answer.
3. The contract test passes against v2.
4. Rollback has been executed once and timed.
5. An independent verification session has re-run items 1–4 and its report matches.

---

## 6. Benchmarks

### 6.1 Principles

1. The primary slice mirrors what Team 3 sends.
2. Query text is independent of corpus text; expansion sources are never query sources.
3. Splits are by CVE; a temporal slice holds out the most recent 90 days.
4. Scoring at document level with equivalence sets.
5. 95% bootstrap intervals on every number; paired bootstrap for comparisons.
6. Runs on the server CPU, recording commit, build ID, dataset hash and load average; latency runs repeated three times, median reported.
7. The frozen v1 system is always compared.

### 6.2 Retrieval collection

| Slice | Query source | Ground truth | Size |
|---|---|---|---|
| T0 Observation narratives (primary) | incident paragraphs in the style of Team 3's cases, written by a model from vendor and CISA incident write-ups (never from NVD text), then verified by a second model; Team 3's own benchmark cases are included as a fixed subset | the CVEs the write-up is about are known from authoring; further relevant documents are added by pooled judging | 600 |
| T1 Identifier | generated: case variants, IDs in sentences, multiple IDs, malformed and non-existent IDs | the IDs | 300 |
| T2 Nickname | named vulnerabilities compiled independently of the alias table | CVE set | 250 |
| T3 Advisory wording | reviewed GitHub advisories only | the advisory's CVE | 1,500 |
| T4 Detection-rule wording | IDS and Sigma rule titles with a CVE reference | the referenced CVE | 800 |
| T5 Product and version | product, version and flaw type; CVEs with complete product data | CVE set | 300 |
| T6 Noisy | typos, missing spaces, abbreviations, pasted log fragments applied to T0, T2, T3 | inherited | 400 |
| T7 Unanswerable | off-topic; security topics absent from the corpus; IOC-only; non-existent IDs | must abstain | 400 |
| T8 Confusable | targets with sibling CVEs in the same product | target only | 300 |
| T9 Actor, software and technique | questions about ATT&CK groups, software and techniques | from ATT&CK relationships | 300 |

Stated in every report: T3 over-represents open-source packages; T0 and T4 balance it. Model-written narratives are cleaner than human ones; T6 exists to offset that.

### 6.3 Splits and power

| Slice group | Train | Dev | Sealed test |
|---|---|---|---|
| T3, T4 | 40% | 20% | 40% |
| T0, T2, T5, T6, T7, T8, T9 | — | 40% | 60% |
| T1 | — | 50% | 50% |

Every gated slice has at least 150 test queries; a proportion near 0.9 then has a 95% interval of about ±5 points. Gates are stated on the point estimate with a floor on the lower bound.

### 6.4 Labelling by models

No human labelling is required. Validity comes from cross-checks.

1. **Known-item labels** come from the source itself (advisory or rule to CVE).
2. **Narrative authoring (T0).** Opus writes each narrative from an incident write-up. A separate Sonnet pass, shown only the narrative, must identify the target; narratives it cannot resolve, or that share more than 60% of tokens with the corpus text, are discarded.
3. **Relevance judging.** The top 10 of every variant is pooled. Sonnet judges each query–document pair against a written rubric (relevant, related, not relevant). Opus judges the same pairs independently.
   - Judging runs in rounds, because later systems surface documents earlier ones did not: round 1 after C3 (v1, lexical, dense, fused), round 2 after C6, round 3 on the sealed-test outputs before E1.
   - Until round 1, tuning uses the known-item labels from step 1 and from T0 authoring.
   - A document in a top 10 that has not been judged is never counted as not relevant. It is judged before any gate is evaluated.
4. **Agreement.** Cohen's kappa between the two judges must reach 0.75. Below that, the rubric is revised and the round repeated. Disagreements are settled by a Opus adjudication pass that sees both rationales.
5. **Judge accuracy on known answers.** A control set of 500 pairs whose labels are certain (source-linked positives and constructed negatives) is mixed in unmarked. Each judge must score at least 95% on it, or its labels are not used.
6. **PoC repository labels.** Positives from curated listings, malicious examples from public fake-PoC reports, the remainder judged by Sonnet with Opus adjudication under the same agreement and control-set rules.
7. **Stated limitation.** Without a human audit, errors shared by both judges go undetected. The control-set accuracy and the kappa are published with the results so a reader can weigh this.

### 6.5 Metrics

| Area | Metrics |
|---|---|
| First stage | Recall@10, @50, @100 per retriever and fused |
| Final ranking | Success@1, MRR@10, nDCG@10 (graded for T0, T5, T9); per slice and macro-average |
| Reranker fidelity | difference from the quality ceiling, with interval |
| Abstention | false-accept rate on T7; risk–coverage curve |
| Calibration | expected calibration error, Brier score, reliability diagram, observed precision per tier, overall and per slice |
| Latency and capacity | p50, p95, p99 per stage and end to end; throughput; 1, 4, 16 concurrent; cold start; memory |
| Robustness | each retriever off; index one day stale; network down |
| Recency | every ranking metric repeated on CVEs published in the last 90 days |
| Determinism | the same query against the same build returns the same order (ties broken by document ID) |

### 6.6 Ablations

Lexical only; dense only; fused; each reranking configuration against the ceiling; aliases on and off; structured fields on and off; depth 50, 100, 200; existing against re-embedded vectors; each embedding model; v1.

### 6.7 Release gates (sealed test)

| Gate | Target |
|---|---|
| T1 Success@1 | 100% |
| T9 Success@1 for ID and exact-name queries | 100% |
| T0 nDCG@10 | at least 15 points above v1; interval excludes zero gain |
| T2 Success@5 | at least 90%; lower bound at least 85% |
| T3 + T4 Recall@10 and MRR@10 | at least 90% and 0.75 |
| T6 | within 5 points of the clean versions |
| T8 Success@1 | at least 80% |
| T7 false-accept rate | at most 1% |
| Serving reranker against ceiling | non-inferior within 1 nDCG@10 point |
| `STRONG` observed precision | at least 95%; lower bound at least 90% |
| Expected calibration error | at most 0.05 overall and per gated slice |
| Single-request free-text p95 | within the hard limit; target reported |
| HTTP 504 on the full suite | none |

Thresholds are frozen after the first dev run and before the sealed test is opened. A gate that fails is fixed, not relaxed. If three documented attempts fail, the package stops and reports the evidence; only the owner can change a gate, and the change is recorded in this file with its reason.

### 6.8 PoC benchmark

- About 400 CVEs: with a Metasploit module or Exploit-DB entry; KEV-listed without a public exploit; recent CVEs with none.
- About 600 labelled repositories (6.4 step 6).
- Run on the server, in two modes that are both reported:
  - **Live run** against the real sources. The script first checks that the portal login is active and refuses to start otherwise; if the login lapses mid-run it stops cleanly and resumes from the last completed CVE. Requests are paced inside GitHub's search rate limit.
  - **Recorded run** that replays the HTTP responses captured by the live run, so results can be reproduced later without the network.
- Labels come from models (6.4 step 6); no hand labelling.

| Gate | Target |
|---|---|
| Attach correctness (PoC CVE equals result CVE) | 100% |
| CVE-level recall of a true PoC, for CVEs with a curated exploit | at least 95% |
| Precision of items labelled PoC | at least 95% |
| False attachment on CVEs with no public exploit | at most 2% |
| Known fake repositories labelled `SUSPICIOUS` | at least 90% |
| Exploitation-status accuracy | at least 95% |
| `/match` latency with live sources unreachable | unchanged within noise |
| Server acceptance run (5.3 item 2) | passes |

---

## 7. Work packages

"Opus" is Opus 5.5, "Sonnet" is Sonnet 5.5. Sonnet where the specification is mechanical and complete, and for first-pass bulk judging; Opus where design, statistics or adjudication is needed. Size: S about one session, M two to three, L four or more. All packages are required.

### 7.1 Which model and effort for each part

Model IDs: Opus is `claude-opus-5-5`, Sonnet is `claude-sonnet-5-5`. Owner decision (2026-11-14): Opus and Sonnet only. Opus at high effort for the packages that set overall quality, Opus at medium for moderate design work, Sonnet for mechanical work. Set the model and effort at the start of the session that implements the package.

**Part A — Foundation**

| Package | What it does | Model | Effort |
|---|---|---|---|
| A1 | Freeze v1 and save the baseline | Sonnet | low |
| A2 | Packaging, lock file, deploy path, run script | Sonnet | medium |

**Part B — Benchmark**

| Package | What it does | Model | Effort |
|---|---|---|---|
| B1 | Download the benchmark sources | Sonnet | medium |
| B2 | Assemble the test collection, splits and leakage tests | Opus | high |
| B2a | Write the incident narratives | Opus | medium |
| B2b | Verify the narratives | Sonnet | medium |
| B3a | Relevance judging, first judge | Sonnet | medium |
| B3b | Second judge, agreement report, adjudication | Opus | medium |
| B4 | Evaluation harness and statistics | Opus | high |
| B5 | Load and latency harness | Sonnet | medium |
| B6 | Run v1 through the new benchmark | Sonnet | low |

**Part C — Retrieval engine and scoring**

| Package | What it does | Model | Effort |
|---|---|---|---|
| C1 | Document store, rewritten duplicate handling, aliases | Opus | high |
| C2 | Lexical index (FTS5) | Opus | medium |
| C3 | Dense search and embedding model comparison | Opus | high |
| C3b | Full re-embed job | Sonnet | low |
| C4 | Query parser and router | Opus | medium |
| C5g | Training queries for distillation | Sonnet | medium |
| C5a | Quality ceiling and teacher scores (long runs) | Sonnet | medium |
| C5b | Distil, quantize and select the reranker | Opus | high |
| C6 | Pipeline rewrite | Opus | high |
| C7 | Confidence, calibration and tiers | Opus | high |
| C8 | Contract test, API compatibility, docs, CI, Docker | Opus | medium |
| C9 | ATT&CK documents and graph | Opus | medium |

**Part D — Operations**

| Package | What it does | Model | Effort |
|---|---|---|---|
| D1 | Versioned builds, incremental update, rollback | Opus | medium |
| D2 | Logging, health, supervisor, runbook | Sonnet | medium |
| D3 | Side-by-side run with v1, Team 3 integration | Opus | medium |
| D4 | Portal session and network state | Opus | medium |
| D5 | Feed sync script and scheduler | Opus | medium |

**Part S — Security**

| Package | What it does | Model | Effort |
|---|---|---|---|
| S1 | Fuzzing, dependency audit, pinning, localhost check | Opus | high |

**Part P — PoC**

| Package | What it does | Model | Effort |
|---|---|---|---|
| P1 | PoC targets, attach rule, separate deadline | Opus | medium |
| P2 | Local PoC index and exploitation status | Sonnet | medium |
| P3 | Live GitHub rework and candidate classifier | Opus | high |
| P4 | Circuit breaker, portal detection, cache | Opus | medium |
| P5a | Repository labels: first judge | Sonnet | medium |
| P5a | Repository labels: second judge and adjudication | Opus | medium |
| P5b | PoC benchmark, live and recorded | Opus | high |
| P6 | Server acceptance script | Sonnet | medium |

**Part V and E — Verification and release**

| Package | What it does | Model | Effort |
|---|---|---|---|
| V1 | Independent re-run of every acceptance check | Opus | high |
| E1 | Sealed-test run and final report | Opus | medium |

Totals: 11 packages on Opus at high effort, 13 on Opus at medium, 13 on Sonnet, and P5a split between the two.

Cross-checks use two different models so their errors are independent: relevance labels and PoC repository labels are judged first by Sonnet and then independently by Opus, with Opus adjudicating disagreements after seeing both rationales; Opus writes the narratives and Sonnet verifies them.

When a package fails its acceptance script:

1. Twice on Sonnet: rerun it on Opus at medium.
2. Twice on Opus at medium: rerun at high.
3. Twice on Opus at high: stop and report, as rule 8 requires.

The verification package V1 always runs on Sonnet at high, in a fresh session that did not write the code it checks.

### 7.2 Full table with dependencies

| WP | Work | Model | Effort | Size | Needs | Where |
|---|---|---|---|---|---|---|
| A1 | Tag v1; store baseline outputs | Sonnet | low | S | — | server |
| A2 | Packaging, lock file, bare-repo deploy, run script, thread settings | Sonnet | medium | M | — | PC + server |
| B1 | Source collectors with licence notes and manifests | Sonnet | medium | M | A2 | PC |
| B2 | Collection assembly: slices, overlap filter, equivalence sets, splits, leakage tests, dataset card | Opus | high | L | B1 | PC |
| B2a | T0 narrative authoring | Opus | medium | M | B1 | PC |
| B2b | T0 narrative verification pass | Sonnet | medium | S | B2a | PC |
| B3a | Relevance judging in three rounds, first judge, including control set | Sonnet | medium | M | B6, C3 (round 1); C6 (round 2); E1 inputs (round 3) | PC |
| B3b | Second judge, agreement report, adjudication | Opus | medium | M | B3a | PC |
| B4 | Evaluation harness: metrics, intervals, non-inferiority tests, reports, variant registry | Opus | high | M | B2 | PC + server |
| B5 | Load and latency harness | Sonnet | medium | S | A2 | server |
| B6 | v1 through the new suite | Sonnet | low | S | B4, B5 | server |
| C1 | Document store: bulk normalization, rewritten duplicate handling, reconciliation, aliases, structured KEV, EPSS, CVSS | Opus | high | L | A2 | PC |
| C2 | FTS5 index with field weights and shared tokenizer | Opus | medium | M | C1 | PC + server |
| C3 | Dense: export vectors, exact search with masks, reduced-corpus model comparison, decision | Opus | high | L | B4, C1 | server |
| C3b | Full re-embed with the winning model (about 15 h on the server CPU, unattended) | Sonnet | low | S | C3 | server or PC GPU |
| C4 | Parser and router; identifier, entity, alias and IOC routes | Opus | medium | M | C1, C9 | PC |
| C5g | About 10,000 training queries for distillation, for CVEs outside dev and test | Sonnet | medium | M | B2, C1 | PC |
| C5a | Quality ceiling and teacher scores (unattended runs) | Sonnet | medium | S | B4, C2, C3, C5g | server or PC GPU |
| C5b | Distillation, quantization, cascade; non-inferiority selection; latency budget | Opus | high | L | C5a | server |
| C6 | Pipeline rewrite: admission control, staged deadlines, fusion tuning, caches, response assembly | Opus | high | L | C2–C5b | PC + server |
| C7 | Confidence: features, judged negatives, calibrator, tiers, abstention | Opus | high | L | B3b, C6 | server |
| C8 | Contract test, API compatibility (`alpha`, `allowed_sources`, `schema_version`, old routes), docs, replacement of obsolete tests, CI fixture, Docker image and compose service | Opus | medium | M | C6, C7 | PC |
| C9 | ATT&CK documents, graph, entity names for the parser | Opus | medium | M | C1 | PC + server |
| D1 | Versioned builds, incremental update, pointer swap, rollback | Opus | medium | M | C1–C3 | PC + server |
| D2 | Structured logging, health manifest, supervisor script, runbook | Sonnet | medium | S | C6 | server |
| D3 | Side-by-side run, Team 3 integration script, rollback rehearsal | Opus | medium | M | C8, D1 | server |
| D4 | Network dependency: session lifetime, keep-alive, health reporting | Opus | medium | S | A2 | server |
| D5 | Feed sync as a script (the current updater is a notebook), timer loop in the supervisor, freshness reporting, daily self-check | Opus | medium | M | C1, D1 | server |
| S1 | Security pass: fuzzing of parser and lexical query builder, dependency audit, model and data pinning, file permissions, outbound allow-list, check that the service listens on localhost only | Opus | high | M | C6, P4 | PC + server |
| P1 | PoC targets, attach rule, separate deadline | Opus | medium | S | C6 contract | PC + server |
| P2 | Local PoC index builder, scheduled refresh, exploitation status | Sonnet | medium | M | B1 | server |
| P3 | Live GitHub rework, result merging, trust tiers, candidate classifier | Opus | high | L | P2, P5a | PC + server |
| P4 | Circuit breaker, portal detection, cache lifetimes, self-recovery | Opus | medium | S | P1 | PC + server |
| P5a | PoC repository labels (judge, second judge, adjudication) | Sonnet + Opus | medium | M | P2 | PC + server |
| P5b | PoC benchmark: live run and recorded run | Opus | high | M | P5a | server |
| P6 | Server acceptance script for PoC and the whole service | Sonnet | medium | S | P1–P4, D2 | server |
| V1 | Independent verification after phases B, C and P: clean checkout, re-run every acceptance script, written report | Opus | high | M | each phase | PC + server |
| E1 | Sealed-test run and final report | Opus | medium | S | all | server |

### Acceptance criteria

- **A1.** Tag and results file exist; the saved script reproduces 2.2 within noise.
- **A2.** A clean checkout installs offline from mirrored wheels; the service starts with no `PYTHONPATH`; one command starts a pushed commit on the server.
- **B1.** Collectors are re-runnable and write a manifest (URL, date, licence, count).
- **B2, B2a, B2b.** Dataset card with sizes, overlap distribution, split hashes; leakage tests pass; no sealed-test document in train or dev; every T0 narrative passed verification.
- **B3a, B3b.** Kappa at least 0.75; each judge at least 95% on the control set; adjudication log stored; after each round no top-10 document of any evaluated variant is unjudged.
- **B4.** One command evaluates a named variant; metric code is tested on synthetic rankings with known answers.
- **B5.** One command gives stage percentiles and throughput at 1, 4, 16 concurrent.
- **B6.** Baseline report committed.
- **C1.** One searchable row per non-rejected CVE; feed reconciliation passes with zero unexplained records; the number of CVEs the old logic dropped is reported; T2 alias coverage is reported.
- **C2.** Lexical Recall@50 at or above v1 on every slice; p95 at most 30 ms.
- **C3, C3b.** Exact search matches brute force on 1,000 queries; p95 at most 60 ms; model choice recorded with numbers; if re-embedding ran, vector count equals document count.
- **C4.** T1 and T9 identifier gates pass on dev; route p95 at most 50 ms; the three old parsers are removed.
- **C5g.** No training query targets a CVE in dev or test (checked by a test).
- **C5a, C5b.** Ceiling and teacher scores stored; the chosen configuration is non-inferior within 1 point; table of all configurations committed.
- **C6.** Dev gates pass except those owned by C7; no 504; overload gives 503 and leaves nothing running; every row of the failure table in 5.2 has a test; thread pools of the numeric libraries are pinned and the setting is recorded.
- **C7.** Calibration and tier gates pass on dev, overall and per slice; thresholds stored with the dataset hash.
- **C8.** Docs describe v2; contract test covers every field Team 3 reads and replays Team 3's exact request (`alpha=0.5`, `top_k=5`); the Docker image builds and answers on port 8000; fixture test runs in CI.
- **C9.** `stix_relationships` contains only relationships traceable to an ATT&CK ID; hardcoded lists are gone.
- **D1.** A one-day update embeds only changed documents; swap and rollback are one command each.
- **D2.** One log line per request; health shows build ID and network state.
- **D3.** Team 3's script passes against v2; rollback timed.
- **D4.** Session lifetime measured and recorded; network loss and recovery both appear in `/health` within one minute.
- **D5.** A sync with no changes rebuilds nothing; a sync with changes produces a new build that passes the smoke benchmark before the swap; corpus age is visible in `/health`.
- **S1.** Fuzz corpus of 10,000 malformed queries causes no error, hang or slow request; dependency audit clean or each finding recorded with a decision; every model loads only from a pinned revision; the service is not reachable from another host.
- **P1–P5b.** Every gate in 6.8 passes on the server, in both the live and the recorded run.
- **P6.** The acceptance script passes on the server after deploy.
- **V1.** The verification report reproduces every acceptance result; any mismatch reopens the package.
- **E1.** Sealed test opened once; report compares v1 and v2 per slice with intervals.

### Rules for every implementing session

1. No tuning on the sealed test and no reading its per-query results before E1.
2. Every reported number carries commit, build ID and dataset hash.
3. No GPU use on the server.
4. v1 data is deleted only after E1 passes and the owner approves the deletion.
5. `network_sensor/` and the root-level `test_network_sensor*.py` belong to another team.
6. Data, model files and credentials are never committed. No password is stored on the server.
7. A design choice here is overturned only by a measurement recorded in the package report.
8. A failing gate is fixed, never relaxed, skipped or hidden behind a default-off switch. After three documented failed attempts the session stops and reports; it does not change the gate.
9. A session never marks its own package verified; V1 does.

---

## 8. Order

A1, A2 → B1, B2, B2a, B2b, B4, B5, B6 → C1 → C9, C2, C3 → B3 round 1 → C3b → C4 → C5g → C5a → C5b → C6 → B3 round 2 → C7 → C8 → D1, D2, D3, D4, D5 → S1 → E1.

PoC track in parallel from B1, tested on the server: P2 → P1 → P4 → P5a → P3 → P5b → P6.

V1 runs after B6, after C8, after P6 and after S1. B3 round 3 runs on the sealed-test outputs immediately before E1.

Critical path: B2 (collection) and C1 (document store).

### 8.1 Compute budget

Latency benchmarks must not share the machine with these jobs, so they are scheduled, not run ad hoc. CPU figures follow from the measured rates (6.6 documents per second for embedding, about 0.3 s per reranked pair, 8–15 s per v1 query).

| Job | Work | Server CPU estimate |
|---|---|---|
| B6: v1 through the suite | about 5,150 queries | 14 h |
| C3: embedding model comparison | 5 models × about 75,000 documents | 12 h |
| C3b: full re-embed | 357,000 documents | 15 h |
| C5a: quality ceiling | about 1,560 dev queries × 50 pairs | 6.5 h |
| C5a: teacher scores | about 11,000 queries × 20 pairs | 18 h |
| C5b: distillation training | small model, 3 passes | 3–6 h |
| **Total unattended** | | **about 70 h** |

The owner's laptop has an RTX 3050 (4 GB). The offline batch jobs (C3, C3b, C5a, C5b) may run there, which should cut them from hours to minutes each; that figure is an expectation, not a measurement. Conditions: the same scripts run on CPU with no GPU present; a 1,000-item sample is computed both ways and must agree (cosine at least 0.999 for vectors, identical ranking for teacher scores) before GPU output is used. Serving, and every quality and latency benchmark, stay on the server CPU.

### 8.2 Effort

Roughly 100 implementing sessions across 38 work packages (S about 1, M about 2.5, L about 5), plus the unattended compute above. This is an estimate from the sizes in section 7.

---

## 9. Risks

| Risk | Response |
|---|---|
| No configuration matches the large reranker inside the latency target | the fastest non-inferior configuration ships and its latency is reported; quality is not reduced |
| Alias sources lack common nicknames | sources are added until the T2 gate passes |
| Both judges share a blind spot | control set and kappa are published; rubric revised when either threshold fails |
| Shared-server load distorts latency | load recorded; three runs; median |
| Portal login lapses | reported in health and responses; local index and cache answer; live lookup recovers by itself; D4 keep-alive |
| `composite_score` changes meaning for Team 3 | documented; contract test; side-by-side run |
| OpenVINO fails on this CPU | PyTorch dynamic quantization |
| CentOS 7 is past end of life, so the host gets no security patches | outside this project's control; the service is bound to localhost and reached through SSH; recorded as a deployment risk |
| Distilled model overfits the model-written training queries | selection uses dev slices from independent sources only; non-inferiority is tested per slice |
| ATT&CK or mapping licence restricts use | B1 records it; only permitted data is ingested |

---

## 10. Dependencies outside the code

Three things cannot be completed by Team 2's code alone.

1. **Internet on the server.** The server reaches the internet only while a person's portal login is active, and that login expires. The code detects this, reports it and keeps answering from local data. The permanent fix is an IT request: exempt the server from the portal for the hosts live PoC lookup, feed sync and model download need (`api.github.com`, `infosec.exchange`, `defcon.social`, `public.api.bsky.app`, and the feed and model hosts).
2. **Team 3 and the backend.** Nothing changes in how they call the service: same routes, same request, no API key. Two fields keep their names but change behaviour, and they should be told: `alpha` is ignored, and `composite_score` is now a calibrated probability (4.7).
3. **Raw feeds.** The NVD, CVE List, KEV and EPSS downloads live under `knowledge_foundation/feeds/` on the owner's PC and are refreshed by a Team 1 notebook. D5 turns that into a script that runs on the server; until then the feeds must be copied there once.

---

## 11. Production-readiness review (Revision 4)

Revision 3 was checked against the code and against a production checklist: correctness of the plan itself, API contracts, security, reliability, operations, data freshness, evaluation validity, compute cost and delivery. Each finding below is fixed in the section named.

### 11.1 Flaws in the plan's own logic

| Finding | Why it mattered | Fix |
|---|---|---|
| Circular dependency: narrative ground truth came from judging system output, but that output did not exist when the retrievers and reranker were tuned | tuning would have had no labels, or labels biased toward the first system | known-item labels first; judging in three rounds; unjudged documents never count as wrong (6.2, 6.4) |
| Distillation had about 920 training queries | far too few to train a ranker; the "full quality" promise would have failed | about 10,000 training queries for CVEs outside dev and test (4.6, C5g) |
| No compute budget | about 70 hours of unattended jobs would have collided with latency benchmarks | scheduled budget, with the laptop GPU as an optional accelerator for offline jobs (8.1) |
| "A failing gate is fixed, never relaxed" had no exit | an unreachable gate would have stalled the project silently | three documented attempts, then stop and report; only the owner changes a gate (6.7) |
| The aggregated GitHub PoC list was treated as trusted | it contains fake PoCs | those repositories pass the classifier like any live candidate (4.8) |
| v1 data deletion was automatic after release | deletion is irreversible | requires owner approval (rules) |

### 11.2 Contracts the plan would have broken

| Finding | Evidence | Fix |
|---|---|---|
| Team 3 always sends `alpha=0.5` | `llm/workflows/investigator.py` | `alpha` accepted but ignored, and reported (5.1) |
| Revision 4 first proposed enforcing an API key, which Team 3 and the backend do not send | no client sets `X-API-Key` | dropped by owner decision: the service is private and bound to localhost, so no key is required (5.1) |
| Other teams build the service from `Dockerfile.retrieval` (Python 3.11, port 8000) | `docker-compose.yml` | image and compose service kept working and tested (5.1, C8) |
| `allowed_sources` had no meaning once a CVE is one document | request schema | matches a CVE with any listed source (5.1) |
| `/pocs/find` defaults to a source list that includes X | request schema | X removed; a request naming it gets `source_not_supported` (4.8) |

### 11.3 Production gaps

| Area | Gap | Fix |
|---|---|---|
| Reliability | vectors memory-mapped on a shared machine could be paged out | loaded fully into memory (4.5) |
| Reliability | no defined behaviour per failure | failure table, each row tested (5.2) |
| Reliability | PoC cache is written into the corpus database at query time | own database file (4.8) |
| Correctness | a calibrator could silently outlive the models it was fitted on | startup refuses mismatched components (5.1) |
| Correctness | no startup consistency check between store, vectors and lexical index | refuses to start on mismatch (5.1) |
| Operations | "scheduled refresh" assumed cron, which the server does not allow | timer loop in the supervisor (5.1, D5) |
| Operations | feed updates depend on a notebook | scripted sync (D5) |
| Operations | logs only, no metrics, no freshness signal | `/metrics`, corpus age in `/health` (5.1) |
| Security | user text could reach the lexical index as query syntax; regexes untested on hostile input | fuzzing and quoting (5.1, S1) |
| Security | dependencies and models unpinned and unaudited | pinning, checksums, audit (S1) |
| Security | GitHub token is a personal one | dedicated token with no scopes (4.8) |
| Privacy | live PoC lookups reveal which CVEs are being investigated | only CVE IDs leave; documented; host allow-list (4.8) |
| Capacity | GitHub allows about 30 searches a minute | shared rate limiter with a visible `rate_limited` state (4.8) |
| Delivery | no branch or review discipline in a repository shared by several teams | branch, one pull request per package, review before merge (5.1) |
| Delivery | code edited on Windows, served on CentOS 7, built in Docker on Python 3.11 | all three kept working; CI on Linux (5.1) |
| Evaluation | recent CVEs and run-to-run stability were not measured | recency and determinism added (6.5) |

### 11.4 Accepted limits

These remain true after the fixes and are stated so nobody is surprised.

1. Labels are made by models. Errors shared by both judges are not caught; the agreement and control-set scores are published.
2. Narrative queries are model-written, so they are cleaner than real analyst text. The noisy slice and Team 3's own cases offset this only partly. Real queries should replace them once the service is in use.
3. The server runs an operating system that no longer receives security patches.
4. Live PoC lookup works only while the portal login is active, until IT grants an exemption.
5. The latency target may be missed if full reranker quality needs more time. In that case quality is kept and the measured latency is reported.

---

## 12. Implementation log

Findings from completed packages that later packages must act on.

| From | Finding | Owner |
|---|---|---|
| A1 | v1 baseline reproduced exactly (hit@1 11/29, hit@10 19/29, MRR 0.474; identical ranks in two runs). Run 1 latency was disturbed by A2; run 2 is the v1 latency reference | B6 |
| A2 | Qdrant embedded mode takes a file lock, so v1 and v2 cannot run on the same `~/data/qdrant_storage` at once. A second process starts with dense search unavailable, yet `/health` reports `healthy` with no degraded components: a silent fallback | C3 (v2 dense search no longer uses Qdrant), C6 and D2 (health must report every unavailable component), D3 (side-by-side run needs separate data) |
| A2 | Importing the package sets `OMP_NUM_THREADS` and related variables to 16 when unset. This also affects other teams' processes that import `threat_retrieval_engine` | C8: apply thread settings only when the service starts, not on import |
| A2 | Each release has its own venv (about 2.5 minutes and several GB). Old releases `9df0aa19f` and `444444db1` are left on the server | D1: release pruning |
