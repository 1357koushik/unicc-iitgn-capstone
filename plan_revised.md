# Team 2 Remediation Plan — `threat_retrieval_engine/` (revision 2)

> **Revision 2 summary.** (1) Acceptance criteria that encoded a single hand-picked number or an assumed model property were replaced by criteria derived from labelled data, a stated decision rule, or a measurement (R1, R16, R4, R19, R22, R27, R33, R35, R40, Stage E). (2) The latency inconsistency is resolved by one deadline contract (V2) that R4, R32, R34, R35, R45 and Stage D all reference. (3) The "32 GB RAM or a GPU" requirement is removed and replaced by a profiling step (V1). (4) Every finding is now tagged with the evidence class it actually has after checking it against the supplied source archive (§1, ledger), one claim was refuted, two were corrected, and the read-only audit constraint is separated from remediation execution. (5) Internal contradictions between items were resolved (§1.4). Changes are listed in Appendix A.

## 1. Scope and assumptions

**Inspected scope.** All files under `threat_retrieval_engine/` (api, search_engine, poc_intelligence, benchmarks, models — 7,090 lines), plus the surfaces that determine whether Team 2's behaviour is observable and correct: `verify/` (11 test modules), `scripts/` (dataset builder, training, sealed-test and full-corpus evaluators, M4 comparison), `config/retrieval_config.yaml`, `deployment/**`, `docker-compose.yml`, `.env.example`, `requirements-*.txt`, `backend/api/main.py`, `llm/workflows/investigator.py`, `frontend/app.js`, and `docs/` (API reference, benchmarks, confidence contract and scoring guide). Corpus metadata was read only via bounded SQL aggregates (row counts, source distribution, table list); the Qdrant store was measured, not opened.

**Material limitations (of the audit, not of the plan).** No full-corpus indexing, retraining, or complete-corpus evaluation was run in the audit. The original text attributed this to RAM, but the host's RAM and the process's peak memory were never measured, so "insufficient RAM" is an unmeasured statement (see V1). The corpus is 362,301 records with a 4.48 GB Qdrant store. Live network calls to GitHub/X/Mastodon/BlueSky were not made, so connector behaviour is assessed statically plus from the existing mocked tests. Two bounded local checks were executed: (a) `resolve_confidence` on production-shaped candidate dictionaries with the shipped artifact; (b) read-only SQLite/Qdrant metadata inspection. Label quality is assessed from the dataset builder and the stored pairs, not from fresh manual annotation — re-annotation is therefore an explicit plan item, not a claim.

**Constraint scope (new).** The read-only constraint (no indexing, retraining, live network calls, or repository edits) governed *the audit that produced this plan*. It does **not** govern execution. Remediation runs under a separate authorization: Phase V and Phases 0–7 may build indexes, run profilers, make network calls with test credentials, and modify the repository. Every "not executed" or "not measured" statement in this document describes the audit and is converted into a work item below; none is a standing limitation on the remediation.

**Assumption stated explicitly.** The graded deliverable is the running FastAPI service (`threat_retrieval_engine.api.main:app`) and the two documented tasks (CVE enrichment ≥90 % precision; PoC/exploit discovery ≥70 % precision), with confidence scoring as a supporting mechanism. Where documentation and code disagree, the code is treated as the implementation and the doc as a contract to be reconciled.


### 1.1 Evidence classes

| Class | Meaning | May it justify a fix? |
|---|---|---|
| **C** Confirmed-static | The defect follows from reading code in the supplied archive (`threat_retrieval_engine/`). This establishes behaviour, not frequency or impact. | Yes, for the mechanism. Severity needs a reproduced impact. |
| **A** Confirmed-artifact | The value was read directly from a shipped artifact (`models/confidence_model.json`, `benchmarks/*.json`). | Yes. |
| **U** Unverified-out-of-archive | Relies on files that are not in the archive (`verify/`, `scripts/`, `docs/`, `config/`, `deployment/`, `backend/`, `llm/`, `frontend/`, `data/`). May be true; the plan's own evidence does not establish it. | Only after V0 checks it against the full repository. |
| **H** Hypothesis | A plausible cause or impact that has not been reproduced. | No. It may not be a premise of another item until V0/V1 reproduces it. |

Rule: an item's severity is justified by its *reproduced* impact. Where impact is hypothesised, the severity below is provisional and says so.

### 1.2 Verification ledger (this revision's source check)

Method: read the archive's source and JSON artifacts; recomputed the arithmetic quoted in the plan; grepped for each cited construct. No code was executed against the corpus. "Checked" means the cited construct exists and behaves as described.

| Item | Class | What the source check found | Effect on this plan |
|---|---|---|---|
| R1 | C + A (mechanism); H (impact on labelled data) | `_extract_bm25_norm_score` falls through to `rrf_score`, the only lexical-ish key `run_query` sets. Artifact: `bm25_norm_score` weight 9.318368, intercept −9.488811, scaler mean 0.56645 / scale 0.385094. Recomputed rank-1 RRF (1/61): z ≈ −22.8, p ≈ 1e−10, shown as 0.0 after `round(...,4)`. **Additional defect:** `dense_score` is overloaded (see R1). | Mechanism kept. Acceptance rewritten (R1). |
| R2 | C (code); H (frequency) | Names are function-local, so the early use raises `UnboundLocalError`. But with `hydrate=True`, `_record` returns a populated `meta` whenever the SQLite row exists, so the branch is reached only if the chunk row is absent from SQLite or `text` is empty. | Severity provisional (R2). |
| R3 | C (import chain); U (Dockerfile, requirements) | `mastodon_scraper.py` imports `bs4` at module top; `poc_finder` instantiates all four sources; `api/main.py` imports `get_poc_finder` at top. The image/requirements half is outside the archive. | Split into C and U parts (R3). |
| R4 | C, with a **correction** | Sync `run_query` inside `async def` confirmed. But sources are run with `asyncio.gather`, so one CVE costs about one source timeout (10 s default), not "4 × 10 s". CVEs are processed sequentially: N_CVE × ≈10 s. | Text corrected (R4). |
| R5 | C | Cache key is `cve_id` only; `set` is unconditional; the stored response is already filtered by `min_confidence`/`max_results`. | Kept. |
| R6 | C (prefix certification); A (`baseline_after.json` top match `CVE-2017-0144_EPSS`); U (corpus counts, API sample) | `match_layer1` certifies on `doc_id` prefix alone. | Split to resolve a circular dependency (§1.4). |
| R7 | C | Exact hits get `dense_score=1.0`, `rrf_score=1.0`. **Additional:** hybrid hits with no dense score get `0.5`. | Kept; additions in R7. |
| R8 | C (query-entity merge); U (bundle absence) | `chunk_actors`/`chunk_ttps`/`chunk_malware` include `query_ent.*`. Starter graph confirmed (3 actor-kind nodes, 3 techniques, 2 tools, 5 edges). The archive has no `data/`, so "bundle does not exist" cannot be confirmed here. | Kept; absence claim downgraded to U. |
| R9 | C | Fallbacks confirmed: `"2023-01-01T00:00:00Z"`, `"Threat Intelligence Report (...)"`, `"Threat Intel"`; `published_date: str` non-optional. | Kept. |
| R10 | C (global MinHash LSH at 0.90 over `chunk.text`); H (that CVE List V5 is mostly dropped); U (corpus counts) | | Impact claim downgraded to H until a re-ingestion count exists. |
| R11 | C | `validator.py` line ~736 sets `severity="HIGH"` for KEV rows; line ~815 sets HIGH/MEDIUM from EPSS. | Kept. |
| R12 | C for raw-text rerank; **REFUTED** for "returned list can exceed top_k" | `scored_candidates[:top_k]` (pipeline L467) enforces the cap after merging. Rerank input is bounded by `search_k + exact ≤ max(4·top_k,20)+top_k` (≈25 pairs at `top_k=5`), not "the whole candidate set" of the corpus. | Item narrowed (R12). |
| R13 | C | `alpha` never forwarded; `MatchText` in both filter builders; `seen.add` precedes the source check. | Kept. |
| R14 | C | No `/health`, `/ready`, `/search/hybrid`, `/entities/lookup`; zero-vector lambda and empty-BM25 fallbacks confirmed. | Kept. |
| R15 | C | `INSERT OR IGNORE`; the only `CREATE` statement in `vector_database.py` is `corpus` (no `entity_index`, no secondary index). | Kept. |
| R16 | A | 8 of 12 weights are 0.0 **and** the same 8 features have scaler mean 0 / scale 1, i.e. they had zero variance in the training data. Mechanism in the original ("regularised to zero") is wrong: they were unlearnable, not shrunk. `ioc_coverage` and `inter_ioc_cov` carry identical weights (0.152307): collinear duplicates. | Item reframed (R16). |
| R17 | C | Arithmetic confirmed: with IOC and TTP present `w_sem = 0.20/0.80 = 0.25`. | Kept. |
| R18 | A (artifact values 0.187858 / 0.059493 / 0.039035); U (docs values) | | Docs half is U. |
| R19, R21–R23, R25, R27 | U | Rely on `scripts/`, `docs/`, `data/labels/`. R23's "never calls the model" claim is consistent with the baselines but cannot be confirmed here. | Check in V0. |
| R20 | C | `helpers.classify_confidence_tier` still returns `EXACT ≥ 0.85`; `calculate_composite_score`, `classify_confidence_tier`, `jaccard_similarity` imported in `pipeline.py` and unused; `resolve_confidence` never inspects reranker availability. | Kept. |
| R24 | C | `p95_idx = int(len(latencies)*0.95)` → max for n=10; `retrieval_mode` only builds a label. | Kept. |
| R26 | C | `calculate_precision` counts items labelled by the same validator. The docstring already says "not an externally measured precision rate". | Kept. |
| R28 | C (default `True`; no quota in `api/main.py`); U (backend proxy) | | Kept. |
| R29 | C (partial) | BlueSky `response.json()` follows the status check and sits outside the request's `try`. Other connectors not individually re-checked. | Keep; finish check in V0. |
| R30 | C | `exact_cve = cve.lower() in lower_text`; no connector writes `code_evidence`. | Kept. |
| R31 | C | Relative defaults confirmed. **Scope extension:** `pipeline.initialize` also uses CWD-relative `./data/mitre/enterprise-attack.json`. | Scope widened (R31). |
| R32 | A (31–75 s in the 2026-10-15 baselines); **H (cause)** | CVE-free queries are also 34–75 s, so PoC is not the sole cause (A). A *different* artifact, `benchmark_results.json` (2026-09-30), shows 23–176 ms for the same query ids, with repeated tier-template-like scores (0.4 ×5, 0.125 ×3). The embedded (path-mode) Qdrant client and per-query pure-Python BM25 scoring are candidate causes. | Diagnosis reclassified H; V1 added. |
| R33 | C (no persistence; `except` → empty index); H ("minutes", "multiple GB") | | Figures replaced by V1 measurements. |
| R34 | C | PoC call inside the timed citation block; `logger.debug` swallow; `poc_discovery_ms` counted within `citation_ms`. | Kept. |
| R35 | C (partial) | `check_same_thread=False` single connection; `query: str` unbounded; `top_k ≤ 50`. | Kept. |
| R36 | C | `allow_origins=["*"]` with `allow_credentials=True`; no auth dependency. | Kept. |
| R37–R39, R40–R43, R45 | U | Rely on `backend/`, `llm/`, `frontend/`, `deployment/`, `verify/`, `docs/`, `config/`. | Check in V0 before work starts. |
| R44 | C (helpers/confidence duplicate regex and vocabularies; dead imports); U (rest) | | Partly checked. |

### 1.3 Additions found during verification

| ID | Class | Finding | Where handled |
|---|---|---|---|
| N1 | C | `dense_score` carries four meanings (dense cosine, `0.5` default, cross-encoder probability after rerank at L365, forced `1.0` for exact hits at L355). `_extract_reranker_score` falls back to `dense_score`, so serve-time `reranker_score` is non-zero while training had it constant at 0. | R1, R7 |
| N2 | H | `QdrantClient(path=...)` (embedded mode) over 362,301 × 1024 vectors. Whether embedded mode scans exhaustively and holds vectors in process memory at this size must be profiled; it would bear on both latency and the memory requirement. | R32, V1 |
| N3 | C | `./data/mitre/enterprise-attack.json` is resolved against CWD. | R31 |
| N4 | H | `exact_lookup` uses `qdrant.scroll(limit=top_k)` with no ordering. For a CVE mentioned in many chunks, the primary-ID record may not be among the first `top_k` points returned. | R7 (repro in V0) |
| N5 | C | Per-CVE PoC cost is ≈ one source timeout (sources concurrent); across CVEs it is sequential. | R4, R34 |
| N6 | A | Three result files with different latencies exist (23–176 ms on 2026-09-30; 31–75 s on 2026-10-15). The change between them is unexplained and must be bisected, not assumed. | R32, R44 |

### 1.4 Contradictions in the original plan, and how this revision resolves them

| # | Contradiction | Resolution |
|---|---|---|
| X1 | **Latency.** R32 targets 200 ms; R34 moves PoC out of the path; R45 sets a 30 s client timeout and tests with a 60 s stub, while the reported latencies reach ≈75 s. A 60 s stub passing proves nothing about a 75 s service. | One deadline contract (V2): server deadline `D_match`, client timeout `T_client_match > D_match`, separate `D_poc`. Tests are parameterised on those values, not on 60 s or on the observed 34–75 s. |
| X2 | **Circular dependency.** R6 depends on R10; R10 depends on R6. | R6 is split: **R6a** (evidence-record selection, no ingestion change) and **R6b** (structured EPSS/KEV fields, after R10/R11). R10 depends on R6a only. |
| X3 | **Sample size.** R21 asks for 150–300 queries with a 70/30 sealed split (45–90 sealed), but R23 asks for 200+ end-to-end queries and R24 for ≥100 items per gate. | Sample size is set by power calculation (R21), and the *sealed* split must itself meet it. See the table in R21. |
| X4 | **Citation integrity.** R27 validation says 100 %, R27 acceptance says ≥ 99 %, Stage D says 100 %. | Resolvability and verbatim-substring fidelity are deterministic: 100 %, any failure is a bug. Groundedness is human-adjudicated and statistical: reported with CI against a pre-registered target. |
| X5 | **Task-1 pass rule.** R23 says "report point estimate and lower bound against 0.90"; Completion #7 says "≥ 0.90 … reported with a lower confidence bound". Ambiguous when the point is ≥ 0.90 and the bound is below. | Pass iff the one-sided 95 % Clopper-Pearson lower bound ≥ 0.90. Point ≥ 0.90 with bound < 0.90 is **inconclusive**, not pass. The same rule applies to PoC with 0.70. |
| X6 | **Stage A "can run now" vs its success criteria.** Stage A requires `/health`, the docs test, and all documented paths, which depend on R14, R42, R3. | Stage A runs twice: A0 now (record failures; red is expected and is the baseline) and A1 as a gate after Phases 0, 1 and 7. |
| X7 | **Stage D prerequisites omit fixes that change what it measures.** Stage D measures Task-1 description precision, but R6 (EPSS stub returned as evidence), R9 and R12 change the returned evidence; they were not prerequisites. | Stage D prerequisites: Stages B and C, and R1, R2, R6a, R7, R9, R12. R23 dependencies updated. |
| X8 | **Hardware.** Stage E: "≥ 32 GB RAM or a GPU". A GPU does not help CPU-resident structures (Python BM25 postings, embedded-Qdrant memory). | Removed. V1 measures and specifies CPU RAM and GPU VRAM separately. |
| X9 | **Documented 200 ms SLA vs an end-to-end pipeline that includes cross-encoder rerank and graph expansion.** Never stated which scope the SLA covers. | V2 requires the SLA scope to be declared (core `/match` path, PoC excluded) and the value to be derived from V1 or formally re-baselined. |

---

## 2. Prioritized remediation roadmap

Phase V (verification and measurement) comes first because several later criteria depend on numbers that have not been measured. Phases 0–1 are prerequisites for everything that reports numbers. Stage C / Phase 3 (evaluation-set construction) should start immediately in parallel because it is the long pole and blocks Phase 2's threshold work.

### Phase V — Verification and measurement gate (runs before any fix; turns assumptions into records)

**V0 — Reproduce or retire every finding**
- **Problem:** the original plan mixes confirmed defects with hypotheses and with claims about files it did not include; downstream items inherit that uncertainty.
- **Proposed correction:** for every item, write the smallest reproduction (a failing test for a defect; a measurement record for an impact), run it on the **unmodified commit**, and record the result in `results/verification_ledger.csv` (item, class C/A/U/H, command, observed output, commit hash). Check every **U** item against the full repository. Items whose reproduction fails are closed as "not reproduced", not fixed.
- **Dependencies:** none.
- **Validation:** each Critical item has a test that fails on the unmodified commit. That test becomes the "fails when reverted" test required elsewhere.
- **Acceptance:** every item has a class; no H or U item is a premise of another item; ledger is committed. Severity of each item is re-stated from the reproduced impact.
- **Effort:** M.

**V1 — Resource and latency profile**
- **Problem:** the plan asserts a hardware requirement, a startup cost, and a latency diagnosis without measurements.
- **Proposed correction:** on each target host, record (a) **peak RSS and wall time per phase**: process start, SQLite open, Qdrant open, BM25 build, embedder load, reranker load, first query, steady state; (b) **per-stage latency distribution** over a query set with network disabled and caches warm: query encode, dense search, BM25, fusion, hydration, rerank, graph, scoring, PoC; (c) **scaling**: repeat (a) at several corpus fractions, fit memory and time against corpus size, extrapolate to 362,301, and confirm at full scale only if the extrapolation fits the host; (d) **CPU RAM and GPU VRAM recorded separately** if a GPU is used. Tools: `psutil` / `/usr/bin/time -v`, `tracemalloc` for Python structures, `py-spy` for hotspots, `torch.cuda.max_memory_allocated`. Bisect the 2026-09-30 vs 2026-10-15 latency difference (N6).
- **Dependencies:** none (read-only; can start immediately).
- **Validation:** repeat the run; run-to-run variation is recorded and used as the noise floor for later "no latency change" assertions.
- **Acceptance:** `results/profile_<host>_<commit>.json` exists; every latency, startup, RSS and hardware figure in R32, R33, R35 and Stage E cites it. The hardware requirement is stated as *"measured peak X GB RAM (+ Y GB VRAM if GPU) with Z % headroom"* with the headroom factor and its reason written down.
- **Effort:** M.

**V2 — Latency and deadline contract (decision record)**
- **Problem:** R32 (200 ms), R34 (PoC out of path), R45 (30 s client timeout, 60 s stub) and the observed 31–75 s describe four different things.
- **Proposed correction:** one config file defines, and one document justifies:
  - `D_match`: server-side hard deadline for synchronous `/match` (retrieval, rerank, scoring; **PoC excluded**). Set from V1: at or above the measured p99 of the core path at the design concurrency plus a stated margin, and at or below the product's interactive requirement. If both cannot hold, that is a product decision (change the requirement or the architecture); it is **not** resolved by choosing a test value.
  - Behaviour at `D_match`: one defined outcome, chosen once and documented (for example HTTP 504, or 200 with `deadline_exceeded=true` and `degraded_components`). No request hangs.
  - `T_client_match` (Team 3 client timeout) `= D_match +` an explicit client margin (network round-trip, serialisation, scheduling). Invariant: `T_client_match > D_match`.
  - `D_poc`: deadline for PoC enrichment, separate, off the `/match` path. Worst case ≈ `N_CVE × per-source timeout` while CVEs are processed sequentially, so cap `N_CVE` per request or process CVEs concurrently.
  - Scope of the documented 200 ms figure (X9) is declared, and either met by the measured core path or formally re-baselined.
- **Dependencies:** V1.
- **Validation:** CI static test asserts `T_client_match > D_match` from config; deadline behaviour tests are in R45 and Stage D.
- **Acceptance:** the contract exists in one place; R4, R32, R34, R35, R45 and Stage D reference it and contain no absolute latency literals of their own. The observed 31–75 s are recorded as *symptom measurements of the current build*, not design inputs.
- **Effort:** S (after V1).

---

### Phase 0 — Blocking correctness and boot integrity (do first; nothing else is trustworthy until these land)

**R1 — Critical — Runtime feature contract is violated; Layer 2 collapses to `UNSUPPORTED` for every non-L1 candidate**
- **Status:** mechanism confirmed (C + A); impact on *labelled* data not yet measured (H, measured in V0 and R16).
- **Location:** `api/feature_extractor.py::_extract_bm25_norm_score` and `_extract_reranker_score`; `api/pipeline.py::ThreatRetrieverEngine.run_query` (candidate assembly and `resolve_confidence` call); `api/confidence.py::ConfidenceModel.predict_proba`; consumers `scripts/train_confidence_model.py::extract_dataset_features`, `scripts/evaluate_sealed_test.py::main` (U: outside the archive).
- **Problem:** the same feature name carries incompatible definitions. Training and sealed evaluation define `bm25_norm_score = |Q∩D| / |Q|` (token containment; scaler mean 0.566, scale 0.385; U for the formula, A for the scaler). Production never computes it: the candidate dict holds only `rrf_score` (≈1/(60+rank) ∈ [0.008, 0.033]), which `_extract_bm25_norm_score` accepts as a fallback (C). The artifact has a 9.318 weight on that one feature with intercept −9.489, so a rank-1 hybrid hit gives `z ≈ −22.8` and `p ≈ 1e−10` (recomputed). A second, independent mismatch (N1): `dense_score` is overloaded (dense cosine; `0.5` when absent; cross-encoder probability after rerank; forced `1.0` for exact hits), and `_extract_reranker_score` falls back to it, so at serve time `reranker_score` is populated while in training it was constant 0 (artifact scaler: mean 0, scale 1).
- **Evidence:** `models/confidence_model.json` (`weights`, `scaler`, `intercept`); `benchmarks/baseline_after.json`: `bench_02_eternalblue_strong` expected `STRONG`, predicted `UNSUPPORTED`, score 0.0068. The original plan also cites a runtime check on a "reranker 0.92" pair returning 0.0; that check's inputs are not in the archive and are re-run in V0.
- **Proposed correction:** define one lexical-feature contract and compute it in one place: either (a) `bm25_norm_score = bm25_score / max(bm25_score over this query's candidate set)` computed in the retrieval layer and passed explicitly, or (b) drop the feature and train on scores production actually has (`rrf_score`, dense cosine, rerank probability, channel coverages). Give each score its own key (`dense_cosine`, `rerank_prob`, `rrf_score`) and remove the aliasing fallbacks. Persist per-feature training support (min/max or quantile bounds) in the artifact. At serve time, a feature vector outside that support returns an explicit `out_of_support` / degraded status instead of a silent 0.0.
- **Dependencies:** none (first item).
- **Validation (revised):**
  1. *Parity (deterministic; no labels needed).* For a sample of pairs that exercises every feature branch (sample size chosen for branch coverage, not statistical power), compute features through the training path and through `run_query`. Schemas identical; per-feature `max|Δ| ≤ 1e−6` (floating-point tolerance). This is the one hard numeric gate.
  2. *Support guard.* Synthetic vectors outside the stored support must yield the documented out-of-support status; in-support vectors must not.
  3. *Labelled evaluation (reported; gating only against thresholds pre-registered before the held-out run).* On held-out labelled (query, candidate) pairs from R21/R22: AUROC and log-loss of the repaired model versus (i) a lexical-only baseline and (ii) the current artifact served unchanged; reliability curve and ECE with bootstrap CI over groups; the fraction of labelled-*relevant* non-L1 candidates scored below the lowest tier threshold, with CI, next to the same fraction for labelled-irrelevant ones. Until the R21 set exists these are *reported, not gating*.
  4. *Ordering sanity (threshold-free).* A candidate whose text equals the query text must outscore a randomly drawn same-corpus candidate in every sampled case. This catches the known collapse without asserting any probability value.
  5. *Monotonicity.* Not a universal gate (a learned model need not be monotone in one feature). If the design chooses sign-constrained coefficients for lexical/semantic features, test the constraint on the weights and check partial dependence; otherwise report partial dependence and review non-monotone regions.
  6. *Retired:* "a 0.9-rerank, high-overlap pair scores ≥ 0.45". It is one hand-picked point; 0.45 is the PARTIAL boundary of tier thresholds that R19 shows are themselves unvalidated. It may remain as a non-gating, labelled-illustrative regression example.
- **Acceptance (revised):** (a) one lexical-feature definition exists and the parity gate passes; (b) no score key is aliased across meanings; (c) the artifact stores its training support and the guard is exercised by tests; (d) on labelled held-out data the repaired model is not worse than the lexical-only baseline on log-loss and AUROC beyond bootstrap CI, with calibration reported with CI; (e) no assertion fixes a specific probability value for a specific hand-picked pair.
- **Effort:** M.

**R2 — High (provisionally Critical) — `run_query` references names it imports later in the same function; Engine 1 can silently lose exact matches**
- **Status:** defect confirmed (C); frequency unmeasured (H). With `hydrate=True`, `exact_lookup._record` returns a populated `meta` whenever the SQLite row exists, so the broken branch is reached only when the chunk is missing from SQLite (Qdrant/SQLite divergence, see R15) or its `text` is empty. Severity becomes Critical only if V0 shows that condition occurs in the deployed stores.
- **Location:** `api/pipeline.py::ThreatRetrieverEngine.run_query`, Engine 1 loop vs the later `from vector_database import fetch_chunk_metadata, fetch_text`.
- **Problem:** the import statement binds both names as function-local for the entire function, so the earlier `m.metadata or fetch_chunk_metadata(...)` and `meta.get("text") or fetch_text(...)` raise `UnboundLocalError` whenever metadata is `{}` or text is empty. The surrounding `except Exception` downgrades it to a warning, so exact matches are dropped without an error signal.
- **Evidence:** `search_engine/exact_lookup.py::_record` sets `metadata=meta or {}`, and `vector_database.fetch_chunk_metadata` returns `None` for a missing row — both produce the falsy case. The only pipeline-level test (`verify/test_pipeline_poc_enrichment.py`) mocks `exact_lookup` to `[]`, so it never reaches the branch.
- **Proposed correction:** hoist all imports to module scope; remove the broad `except` around the exact-match assembly or narrow it and re-raise on programming errors; treat metadata absence as an explicit, typed outcome.
- **Dependencies:** none.
- **Validation:** unit test with an `ExactMatch` whose metadata is `{}` and whose chunk row is absent from SQLite; assert the response still contains the match with a `null`-safe citation and that no `UnboundLocalError` path is reachable (`python -W error`).
- **Acceptance:** exact matches are never silently discarded; the warning-only code path is gone; a missing-row case produces a typed, visible outcome (and a counter), not a swallowed exception.
- **Effort:** S.

**R3 — Critical — The retrieval container cannot be relied on to start (undeclared imports)**
- **Location:** `requirements-retrieval.txt`, `deployment/docker/Dockerfile.retrieval`, `poc_intelligence/sources/mastodon_scraper.py` (top-level `from bs4 import BeautifulSoup`), `poc_intelligence/sources/*.py` (`import httpx`).
- **Status:** the import chain is confirmed (C): `mastodon_scraper.py` imports `bs4` at module top, `poc_finder` instantiates all four sources, `api/main.py` imports `get_poc_finder` at top level. That the image does not install `bs4` is U (Dockerfile/requirements are outside the archive); confirm in V0 by building the image.
- **Problem:** `bs4` is not declared (U) and not installed by the image (U); `httpx` is only transitive via `qdrant-client` (U). `api/main.py` imports `get_poc_finder` in its top-level import chain, so a missing `bs4`/`httpx` propagates through all three fallback branches and aborts app import — uvicorn exits instead of degrading.
- **Evidence:** `Dockerfile.retrieval` installs only `requirements-retrieval.txt` + `fastapi uvicorn python-multipart`; `requirements-retrieval.txt` lists `torch, FlagEmbedding, transformers, qdrant-client, pydantic, pydantic-settings, aiosqlite, datasketch, ftfy, pyyaml, numpy`; `mastodon_scraper.py` imports bs4 at module import.
- **Proposed correction:** declare `httpx` and `beautifulsoup4` (pinned) in `requirements-retrieval.txt`; move optional-connector imports inside the connector's `__init__`/`search` so a missing optional dependency yields `status="not_configured"` rather than a boot failure; add `HEALTHCHECK` and a `/health` endpoint (see R14).
- **Dependencies:** none.
- **Validation:** build the image from a clean cache and run `python -c "import threat_retrieval_engine.api.main"` plus a container start with no `.env`; Stage A gate.
- **Acceptance:** image starts, `/health` returns component status, and removing an optional connector dependency degrades that source only.
- **Effort:** S.

**R4 — Critical — Synchronous pipeline work inside `async def` handlers stalls the event loop, including outbound OSINT calls**
- **Location:** `api/main.py::match_threat_query` (calls `orchestrator.run_query` directly), `api/pipeline.py::run_query` (`poc_finder.find_pocs_sync` per CVE), `poc_intelligence/poc_finder.py::find_pocs_sync`.
- **Problem:** `run_query` is fully synchronous (Qdrant, BM25, CPU cross-encoder, then `find_pocs_sync` which blocks on a `ThreadPoolExecutor` future). Running it in the event-loop thread serialises all concurrent requests; `find_pocs_sync` additionally blocks the loop while waiting on network I/O. *Correction (N5):* the four sources are queried concurrently (`asyncio.gather`), so one CVE costs about one source timeout (10 s by default), not 4 × 10 s; CVEs in the query are processed sequentially, so the worst case is ≈ `N_CVE × 10 s`.
- **Evidence:** `match_threat_query` is `async def` and returns `orchestrator.run_query(...)` with no `run_in_executor`; `run_query` calls `poc_finder.find_pocs_sync(cve, max_results=5)` inside the timed citation block; `find_pocs_sync` uses `future.result()` with no timeout.
- **Proposed correction:** make the route `def` (threadpool) or wrap in `asyncio.to_thread`/`run_in_executor`; move PoC enrichment out of the match path (see R34) or await `find_pocs` natively; add a request-level deadline propagated to all sub-calls.
- **Dependencies:** none.
- **Validation (revised):** stage-stub test (B/D): replace the heavy stage with a stub of fixed duration `s`; for `k` concurrent requests and a configured worker bound `W` (V2), assert wall time ≤ `s·⌈k/W⌉ + ε` (ε from the V1 noise floor) and that a concurrent trivial request (e.g. `/health`, R14) completes in a time independent of `s`. Use a fake clock or a scaled `s`; do not use real tens-of-seconds sleeps. Add a static check that no network call executes on the event-loop thread.
- **Acceptance:** throughput scales as the bound above predicts; the event loop stays responsive while a request is in flight; no synchronous network call executes on the loop; the request deadline `D_match` (V2) is propagated to sub-calls.
- **Effort:** M.

**R5 — Critical — PoC cache is keyed on CVE only and caches failures**
- **Location:** `poc_intelligence/poc_cache.py::PoCCache.get/set`, `poc_intelligence/poc_finder.py::find_pocs`.
- **Problem:** the key is `cve_id`; `sources`, `max_results`, and `min_confidence` are not part of it, so a `sources=["github"]` request poisons later "all sources" requests (and vice versa) for up to 6 h. A run in which every source errored is also stored, so a transient outage is frozen for the full TTL.
- **Evidence:** `find_pocs` calls `self.cache.get(cve_clean)` and returns `model_copy(deep=True)` with only result filtering/slicing; `set(cve_clean, response)` is called unconditionally after the aggregation step, including when `source_statuses` are all `error`/`timeout`.
- **Proposed correction:** key on `(cve_id, sources_sorted, max_results, min_confidence_bucket)` or cache the raw per-source payload keyed by `(cve_id, source)` and compose responses at read time; skip `set` when no source returned a success status; store `retrieved_at` per source.
- **Dependencies:** none.
- **Validation:** Stage B — two requests with different `sources` must not share a cache entry; an all-error run must not be retrievable; TTL expiry test with an injected clock.
- **Acceptance:** cached responses are identical to what an uncached request with the same parameters would return.
- **Effort:** M.

**R6 — Critical — `EXACT` is assigned to metadata stubs, and the "vulnerability description" returned may be an EPSS one-liner** *(split in this revision to remove the R6↔R10 circular dependency)*
- **Status:** certification-by-prefix confirmed (C); an EPSS record returned as the top EXACT match confirmed in `benchmarks/baseline_after.json` (A: `CVE-2017-0144_EPSS`); corpus stub counts and the API sample are U.
- **R6a (no ingestion change; do first):** evidence-record selection. L1 may certify *identity*; the record returned as primary evidence must prefer a substantive description record over a metadata stub, using the record class already derivable from `doc_id` suffix/`source_org`. Expose `evidence_record_class`. Dependencies: none. Effort: M.
- **R6b (after R10 and R11):** structured enrichment. Attach severity/EPSS/KEV as structured fields of the identity rather than as competing "documents". Dependencies: R10, R11. Effort: M.
- **Location:** `api/confidence.py::match_layer1`; `api/pipeline.py` candidate merge/sort and `build_citation` call; ingestion `validator.parse_epss_csv` / `parse_cisa_kev_csv`.
- **Problem:** L1 triggers on `doc_id` prefix alone, so `CVE-2022-30190_EPSS` (text: "…has an EPSS exploitation probability score of …") resolves to `EXACT`, probability 1.0. All same-CVE records then tie at 1.0 and the winner is decided by forced `dense_score = 1.0` plus sort order, with no preference for a complete authoritative description.
- **Evidence:** certify-by-prefix code path; `docs/API_REFERENCE.md`'s own sample response returns `doc_id: "CVE-2017-0144_EPSS"`, `text_snippet: "…EPSS exploitation probability score of 0.97…"`, `composite_score: 0.9625`; `benchmarks/baseline_after.json` maps `bench_03_follina_partial` (`expected PARTIAL`) to `EXACT` via the `_EPSS` record; corpus query shows 4,135 EPSS and 1,593 KEV stub rows.
- **Proposed correction:** introduce record-class awareness: L1 may certify *identity*, but the *evidence* selection must prefer a substantive description record (NVD/CVE List V5) over metadata stubs; return `EXACT` on identity with an explicit `evidence_record_class` field, and expose severity/EPSS/KEV as structured metadata attached to the identity rather than as competing "documents".
- **Dependencies:** R6a: none. R6b: R10, R11. (R10 depends on **R6a** only.)
- **Validation:** Stage B/C — for every CVE in a fixture that has both a stub record (`_EPSS`/`_KEV`) and a description record (fixture built to include all such cases, not an arbitrary 50), R6a: the returned primary citation is the description record. R6b: EPSS/KEV values appear as structured fields. The primary citation text is never a stub sentence (checked by record class, not by string matching).
- **Acceptance:** no `EXACT` match returns a metadata-stub text as its primary evidence; enrichment fields are populated structurally after R6b.
- **Effort:** L (R6a M + R6b M).

---

### Phase 1 — Retrieval, evidence, provenance, and contract correctness

**R7 — High — "Exact match" (Engine 1) and Layer 1 use different notions of identity, and evidence scores are fabricated**
- **Location:** `search_engine/exact_lookup.py::exact_lookup/_qdrant_lookup`; `api/pipeline.py` Engine 1 assembly (`dense_score = 1.0`, `rrf_score = 1.0` for exact hits).
- **Status:** C for the synthesised scores (`1.0` for exact; `0.5` for hybrid hits lacking a dense score, pipeline L289); N4 (unordered `scroll(limit=top_k)` may omit the primary-ID record when many chunks mention the CVE) is H and is reproduced in V0 before any change.
- **Problem:** Engine 1 matches the Qdrant `cves` payload, which includes incidental body-text mentions, while L1 requires a `doc_id` prefix match. A document that merely mentions the queried CVE is labelled "exact", gets `dense_score = 1.0` and `rrf_score = 1.0`, and therefore reports `evidence_breakdown.semantic_similarity = 1.0` and `ioc_similarity`/`cve_similarity` values that were never measured.
- **Evidence:** `exact_lookup` builds `MatchAny` over `payload["cves"]`; `_record` sets `exact_score`/`dense_score` to 1.0; `pipeline` copies them into the candidate; `feature_extractor._extract_bm25_norm_score` then reads `rrf_score = 1.0`; `docs/API_REFERENCE.md` shows `ioc_similarity: 1.0` for a corpus that contains zero IPs (verified: 0 IPs, 0 hashes).
- **Proposed correction:** separate `identifier_match_kind` (`PRIMARY_ID` / `MENTION` / `HASH`) from score fields; never synthesise 1.0 similarities; compute evidence values from the same extractor used for scoring and mark unavailable channels as `null`, not `0`/`1`.
- **Dependencies:** R1.
- **Validation:** Stage B — a mention-only document must be `MENTION`, with `semantic_similarity` equal to the measured rerank/dense value; assert no field equals 1.0 unless measured.
- **Acceptance:** `evidence_breakdown` values are reproducible from stored features; no constant-injected similarity survives.
- **Effort:** M.

**R8 — High — Graph expansion attributes query entities to documents, and the "ATT&CK graph" is a hand-written 8-node stub**
- **Location:** `api/pipeline.py` Engine 3 (`chunk_actors = raw_ent.get(...) + query_ent.threat_actors`, same for TTPs/malware); `search_engine/mitre_graph.py::MitreAttackGraph.expand`; asset `data/mitre/enterprise-attack.json`.
- **Problem:** query-side entities are merged into the document's entity set before expansion, so `stix_relationships` shown for a candidate can be entirely query-derived — an unsupported association presented as document evidence. Additionally the enterprise ATT&CK bundle is absent, so `_build_starter_attack_graph()` (3 actors, 3 techniques, 2 tools) is used and the "STIX graph" is effectively fabricated lookup tables.
- **Evidence:** the merge passes `query_ent.*` into `expand` (C). The pipeline loads `./data/mitre/enterprise-attack.json` relative to the CWD and falls back to the starter graph when the file is absent (C). That the file is absent in the deployed environment is U (the archive has no `data/`); confirm in V0.
- **Proposed correction:** expand document entities and query entities separately; label each relationship with its source (`DOCUMENT` vs `QUERY_CONTEXT`) and never present query-derived edges as document provenance; ship the real bundle (or make absence an explicit `graph_status="unavailable"` rather than a toy substitute).
- **Dependencies:** none.
- **Validation:** Stage B — a candidate whose entities are empty while the query names APT29 must return zero `DOCUMENT` relationships; with the real bundle, assert node/edge counts equal the counts recorded in the pinned bundle's manifest (version and hash stored), and spot-check known actor→technique pairs against the same pinned version. (A fixed floor such as ">10k" is not used: counts change between ATT&CK releases.)
- **Acceptance:** every returned relationship is traceable to document entities or explicitly labelled query context; the toy graph is gone or unreachable in production.
- **Effort:** M.

**R9 — High — Citations fabricate publication dates, titles, and source organisations**
- **Location:** `api/helpers.py::build_citation`.
- **Problem:** missing `published_date` becomes `"2023-01-01T00:00:00Z"`, missing title becomes `"Threat Intelligence Report ({chunk_id})"`, missing `source_org` becomes `"Threat Intel"`. These are indistinguishable from real provenance downstream, and the fabricated date is visible in the project's own API example.
- **Evidence:** the fallback branches in `build_citation`; `CitationSchema.published_date: str` is non-optional; `docs/API_REFERENCE.md` sample carries exactly `2023-01-01T00:00:00Z`.
- **Proposed correction:** make provenance fields nullable (or `"UNKNOWN"` with a `provenance_status` flag), remove the synthetic date, and assert in tests that no date is invented.
- **Dependencies:** none.
- **Validation:** Stage A/B — citation with an empty metadata row must serialise `published_date: null` and `provenance_status: "MISSING"`; grep the codebase for the literal `2023-01-01`.
- **Acceptance:** zero synthetic provenance values anywhere in the response.
- **Effort:** S.

**R10 — High — Cross-source deduplication destroys provenance; `sources_found` is documented but not implemented**
- **Location:** `search_engine/duplicate_checker.py::DuplicateChecker.is_duplicate` (MinHash on raw `chunk.text`); `validator.parse_*` (per-source `source_org`); `docs/dev/confidence_contract.md` §2.2 (sources_found); `verify/test_confidence_contract.py::test_metadata_separation` (validates a local dict, no implementation).
- **Problem:** global 0.90-Jaccard dedup across sources drops records whose text is a near-copy of an earlier source. NVD descriptions derive from CVE List V5 CNA text, so CVE List V5 records are largely discarded. There is no `sources_found`, no per-CVE source set, and no corroboration signal — the multi-source requirement is unmet.
- **Evidence:** corpus aggregate: `NVD 356,382 / EPSS 4,135 / CISA 1,593 / CVE_LIST_V5 191`; `sources_found` appears only in docs and in a test-local dictionary; `ConfidenceResolution` has no such field.
- **Proposed correction:** dedup within source (not across), or key dedup on `(doc_id, text_hash)` and merge duplicates into one record carrying a `sources: {NVD: FOUND, CISA: NOT_FOUND, …}` set; implement `sources_found` in the response with the documented `FOUND/NOT_FOUND/UNAVAILABLE` semantics; expose a `corroboration_count`.
- **Status:** the dedup mechanism (one global MinHash LSH at 0.90 over `chunk.text`) is C. That CVE List V5 records are *largely discarded* is H (the 191-row count is U and is also consistent with a small input); V0 re-ingests a bounded sample and counts what dedup drops, per source.
- **Dependencies:** R6a (not R6b: R6b depends on this item).
- **Validation:** Stage B/E — on a bounded re-ingestion, report per-source rows in versus rows dropped by cross-source dedup; assert that every dropped duplicate is represented in the surviving record's `sources` set (nothing is lost, only merged); for a CVE sample drawn at random with a recorded seed, assert `sources_found` equals independent lookups against the raw feeds (agreement required: 100 %, since this is a deterministic lookup).
- **Acceptance:** provenance survives ingestion; `sources_found` is populated from data, not from a literal.
- **Effort:** L.

**R11 — High — Severity is fabricated from exploitation likelihood**
- **Location:** `search_engine/validator.py::parse_cisa_kev_csv` (`severity="HIGH"` unconditionally) and `parse_epss_csv` (`"HIGH" if epss_score >= 0.8 else "MEDIUM"`).
- **Problem:** KEV membership says nothing about CVSS severity, and EPSS is an exploitation-probability percentile. Both overwrite the `severity` payload field, which is indexed and used for filtering. This is precisely the severity/exploitation-likelihood conflation the contract forbids.
- **Evidence:** the two assignments above; `vector_database.store_chunks` writes `chunk.entities.severity` into the Qdrant payload and creates a `severity` payload index.
- **Proposed correction:** KEV and EPSS records carry `severity="UNKNOWN"` plus dedicated `cisa_kev: true` / `epss_score` fields; severity is only ever derived from CVSS base scores; add a payload index on the new fields.
- **Dependencies:** none.
- **Validation:** Stage B/E — ingest 20 KEV rows whose CVSS is LOW and assert payload severity is `LOW`/`UNKNOWN`, not `HIGH`; assert filters on `cisa_kev`/`epss_score` work.
- **Acceptance:** `severity` is a pure function of CVSS; exploitation signals are separate fields.
- **Effort:** M.

**R12 — High — Reranker is fed text that differs from what was embedded (narrowed; one sub-claim refuted)**
- **Status:** raw-text rerank confirmed (C). **Refuted:** "the returned list can exceed `top_k`": `scored_candidates[:top_k]` (pipeline L467) caps the response after exact matches are merged. **Narrowed:** rerank input is bounded by `search_k + exact ≤ max(4·top_k, 20) + top_k` (≈25 pairs at `top_k=5`, ≈250 at `top_k=50`), not "the whole candidate set"; whether that depth is right is an empirical question.
- **Location:** `api/pipeline.py` Engine 2.5 (`content = f"{title}: {text}"`), `search_engine/reranker.py::rerank` (`top_k=max(top_k*2, len(candidate_map))`).
- **Problem:** ingestion embeds `enriched_text` (title + section + CVEs + malware + TTPs) and `reranker.rerank_hybrid_results` reranks on `enriched_text`, but the pipeline reranks raw `text` plus title, so identifiers and TTPs that make a passage recognisable are absent. Also, exact matches are reranked and then have their rerank score discarded and replaced by 1.0 (pipeline L355).
- **Evidence:** the two code sites; `vector_database.fetch_chunk_metadata` returns `enriched_text` and the pipeline does not use it.
- **Proposed correction:** rerank on `metadata["enriched_text"]` (fallback `text`); choose the rerank depth `candidate_k` by a sweep on the R21 set (NDCG/recall versus latency from V1) and document the chosen value; keep the existing top-k cap and add a regression test for it; stop overwriting measured rerank scores with 1.0 (see R7).
- **Dependencies:** none for the text change; R21 for the depth choice.
- **Validation:** Stage B — spy test that the reranker receives `enriched_text`; assert `len(top_matches) ≤ top_k` for randomised candidate sets (regression guard, not a defect repro); the rerank-depth sweep reports NDCG@10 and p95 stage latency for each depth.
- **Acceptance:** rerank input matches the embedded representation; the chosen depth is justified by the sweep, not by a funnel-shape assumption.
- **Effort:** S.

**R13 — High — `alpha` is accepted and ignored; source filtering is inconsistent and can permanently drop matches**
- **Location:** `api/schemas.py::MatchRequest.alpha`; `api/pipeline.py::run_query` (parameter unused); `search_engine/hybrid_search.py::build_qdrant_filter` (`MatchText`); `search_engine/exact_lookup.py::_record` (marks `seen` before the source check).
- **Problem:** the documented dense/sparse weighting control has no effect, so any tuning or ablation using it is invalid. Source filtering uses full-text matching in Qdrant and case-sensitive substring matching in SQLite, so the same request returns different candidate sets. In exact lookup a filtered-out chunk is still added to `seen`, so it can never be recorded via a second identifier.
- **Evidence:** `run_query` never forwards `alpha` to `HybridSearcher.search`; `build_qdrant_filter` uses `MatchText` for `source_org`; `_record` does `seen.add(chunk_id)` before the `allowed_sources` test.
- **Proposed correction:** either implement `alpha` (weighted RRF) or remove it from the contract; use keyword `MatchAny` on a normalised source list; move the `seen` insert after the filter passes.
- **Dependencies:** none.
- **Validation:** Stage B — `alpha=0` vs `alpha=1` must produce different rankings when implemented, or the field must be absent; identical filter results across engines on a 500-chunk fixture; a chunk rejected by source filter is still retrievable by another identifier.
- **Acceptance:** no public parameter is a no-op; filter semantics are identical across engines.
- **Effort:** S.

**R14 — High — Documented endpoints and health/readiness signals are missing; degradation is silent**
- **Location:** `api/main.py` (routes); `api/pipeline.py::initialize` (`query_encoder = lambda q: [0.0]*1024`, `bm25 = BM25Index()` on failure); README and `docs/API_REFERENCE.md`.
- **Problem:** `/api/v1/search/hybrid`, `/api/v1/entities/lookup`, and `GET /api/v1/health` are documented but absent, so consumers cannot distinguish "no results" from "dense index unavailable". If BGE-M3 or BM25 fails to load, retrieval silently degrades to zero vectors/empty lexical results with only a log line.
- **Evidence:** route list in `api/main.py` (only `/match` aliases and `/pocs/find`); the two fallbacks in `initialize`; no `health` string in the module; docker-compose has no healthcheck.
- **Proposed correction:** add `/health` (per-component: qdrant, bm25, embedder, reranker, confidence model, graph) and `/ready`; return component status in `pipeline_profile` or a `degraded_components` field; make zero-vector fallback an explicit `degraded` state rather than a silent lambda.
- **Dependencies:** R3.
- **Validation:** Stage A/D — start with the BGE model directory renamed and assert `/health` reports `embedder: unavailable` and `/match` marks `degraded_components: ["embedder"]`; compose healthcheck turns green only when all required components are up.
- **Acceptance:** no component can fail silently; documented endpoints exist or are removed from docs.
- **Effort:** M.

**R15 — Medium — Qdrant and SQLite diverge on re-ingestion; `entity_index` is referenced but never created**
- **Location:** `search_engine/vector_database.py::store_chunks` / `setup_sqlite`; `search_engine/exact_lookup.py::_sqlite_lookup`.
- **Problem:** Qdrant uses `upsert` while SQLite uses `INSERT OR IGNORE`, so re-ingesting a changed chunk updates the vector/payload but keeps the old text — search returns the new payload with stale evidence text. `entity_index` is queried first and never created, so every IOC lookup falls back to `entities_json LIKE '%"value"%'`, a full scan of 362,301 rows.
- **Evidence:** verified tables are only `corpus` and `poc_cache`; `entity_index exists: False`; the `LIKE` fallback in `_sqlite_lookup`; `INSERT OR IGNORE` in `store_chunks`.
- **Proposed correction:** use `INSERT … ON CONFLICT(chunk_id) DO UPDATE` (and delete stale Qdrant points on reset), create `entity_index(entity_value, chunk_id)` during setup with a backfill migration, and add the `corpus(doc_id)` index there too (currently only created ad hoc by the dataset builder).
- **Dependencies:** none.
- **Validation:** Stage B — re-ingest a chunk with modified text; assert Qdrant payload and SQLite text agree; `EXPLAIN QUERY PLAN` for an IOC lookup must show an index scan.
- **Acceptance:** stores cannot diverge; no full-table scan on the exact-lookup path.
- **Effort:** M.

---

### Phase 2 — Confidence model, calibration, and thresholds

**R16 — High — The "12-feature calibrated model" is effectively a one-feature lexical model, and eight features had zero variance in training**
- **Status:** confirmed from the artifact (A).
- **Location:** `models/confidence_model.json`; `scripts/train_confidence_model.py` (U).
- **Problem:** 8 of 12 weights are exactly 0.0: `has_cve`, `has_ttp`, `cve_coverage`, `ttp_coverage`, `reranker_score`, `inter_cve_cov`, `inter_ttp_cov`, `inter_reranker`. The same 8 have scaler mean 0 and scale 1 — scikit-learn's replacement for zero variance — so they were **constant 0 in the training data** (training queries have CVE tokens masked and no reranker score; consistent with R21). They were therefore *unlearnable*, not "regularised to zero". The original claim that the reranker "has zero influence" and the original acceptance ("reranker weight materially non-zero") both assume the data had a chance to show otherwise; it did not. Whether the reranker carries independent predictive value is **untested, not answered**. Separately, `ioc_coverage` and `inter_ioc_cov` carry identical weights (0.152307) because one is a rescaling of the other: collinear duplicates.
- **Evidence:** the artifact's `weights` and `scaler`; `training_samples: 2560`.
- **Proposed correction:** fix the data first (R21/R22 provide CVE-bearing queries and real candidate rerank scores). Then fit on the serve-time feature set and decide each feature's inclusion with evidence, not by a minimum weight:
  - Every feature must have non-zero variance in the training set, or be excluded and listed as "not available at train time".
  - Inclusion rule: keep a feature when removing it worsens grouped-CV log-loss (or AUROC) by more than the bootstrap CI over groups, **or** when the degraded-mode contract needs it. Otherwise drop it, or keep it with a documented "no independent signal" note. A feature that contributes nothing is not forced into the model.
  - Remove collinear duplicates (`inter_*` that equal the base feature in the cases that occur).
  - If the reranker adds no confidence signal, record that. It does not by itself decide whether the reranker stays in the *ranking* path; that is decided by NDCG gain versus the latency cost measured in V1.
- **Dependencies:** R1, R21, R22.
- **Validation:** Stage B/D — grouped (by query/CVE) nested CV; per-feature drop-column ΔlogLoss and permutation importance with bootstrap CI; correlation/VIF table; per-feature training-variance check; R1 parity gate.
- **Acceptance (revised):** (a) every feature in the artifact has non-zero training variance; (b) every retained feature has an ablation result with CI, and every dropped or near-zero one has a recorded reason; (c) the weight vector and ablation table ship with the artifact so a dead feature is visible; (d) **no minimum weight is required for any feature**.
- **Effort:** L.

**R17 — High — The behavioural heuristic structurally caps at `WEAK` whenever both IOC and TTP are present in the query**
- **Location:** `api/confidence.py::resolve_confidence`, Option B branch (`active_weight = 0.40*has_ioc + 0.20*has_ttp + 0.20`).
- **Problem:** presence flags are query-side only. In a corpus with zero IPs and near-zero TTPs, a query containing an IP and a technique reserves 0.60 of the 0.80 budget for channels that cannot match, so `w_sem = 0.25` and the maximum achievable score is 0.25 → `WEAK` even for a perfect semantic match. This re-introduces the missing-observable penalty the architecture claims to have eliminated, just inverted.
- **Evidence:** the Option B arithmetic; `benchmarks/baseline_after.json` shows `bench_02` (IP + T1021.002) at `0.0068`; the bounded check shows the same formula producing 0.975 only because the provided `candidate_score` was 0.95 with `w_ttp = 0.5`.
- **Proposed correction:** renormalise over channels that are *matchable* against this corpus (or over channels actually present in the candidate), or restrict behavioural scoring to semantic + TTP-with-document-evidence; publish the theoretical maximum for each query profile so the cap is visible.
- **Dependencies:** R1 (shared scoring contract).
- **Validation:** Stage B — a behavioural query with a perfect semantic match must be able to reach `STRONG`; assert the documented maximum per profile equals the observed maximum.
- **Acceptance:** no query profile is mathematically barred from `STRONG` by absent corpus channels.
- **Effort:** S.

**R18 — High — Conflicting model metrics across docs, result artefacts, and the exported artifact**
- **Location:** `models/confidence_model.json::metadata.cv_metrics`, `data/labels/m4_comparison.json`, `data/labels/sealed_test_results.json`, `docs/BENCHMARKS.md`, `docs/dev/confidence_scoring.md`.
- **Problem:** three different OOF log-loss values describe the same model (0.187858 in the artifact, 0.1512 in the docs and `m4_comparison.json`); Brier 0.059493 vs 0.0449; ECE 0.039035 vs 0.05184. `sealed_test_results.json` still reports Task-1 precision 100 % with CI [100,100], which the docs themselves retract in favour of 79.38 %.
- **Evidence:** the four artefacts above; docs §10.2 explicitly replaces the [100,100] interval; no script reconciles the artifact metadata with the reported table.
- **Proposed correction:** make one evaluation run the single source of truth: a machine-generated metrics file referenced by the docs, with the artifact embedding the exact run id; delete or regenerate stale artefacts; add a CI check that docs numbers match the metrics file.
- **Dependencies:** R21–R23 (new evaluation), R16.
- **Validation:** Stage A — a script recomputes the reported metrics from stored predictions and diffs against docs; mismatch fails the build.
- **Acceptance:** exactly one number per metric exists in the repository.
- **Effort:** M.

**R19 — High — Tier thresholds are unvalidated and the 90 % precision gate is not met even by the project's own sealed evaluation**
- **Location:** `api/confidence.py::classify_confidence_tier`; `docs/dev/confidence_contract.md` §7; `docs/BENCHMARKS.md` §3.1.
- **Problem:** 0.65/0.45/0.10 are asserted, not derived. On the sealed set the `STRONG` band has 80.0 % empirical precision (160 TP / 200) — below the 90 % requirement — and the prior-shift analysis shows everything collapsing to `WEAK` at 1:20 and to `UNSUPPORTED` at 1:100 prevalence. A band whose precision is below its nominal meaning is a mislabelled gate, not a calibrated tier.
- **Evidence:** the band table (200 pairs, 160 positives, 40 hard negatives); the prior-shift section (204 pairs shift to `WEAK` at 1:20; all 640 to `UNSUPPORTED` at 1:100).
- **Proposed correction:** select thresholds on a prevalence-matched, independent validation set with an explicit operating point (precision target per tier), add abstention (`INSUFFICIENT_EVIDENCE`) instead of a misleading `UNSUPPORTED` probability, and document the expected precision per band with confidence intervals.
- **Dependencies:** R16, R21, R22.
- **Validation:** Stage D — thresholds are selected on the **validation** split only, against a stated operating point (a per-tier precision target, with the tier→target table written down before selection); the sealed split is then used **once** to report per-band precision with Clopper-Pearson CI, reliability curve, and ECE. `STRONG` precision ≥ 0.90 uses the X5 pass rule (one-sided 95 % lower bound ≥ 0.90) or an explicitly renegotiated gate.
- **Acceptance:** every threshold has a measured precision/recall trade-off and a documented operating point.
- **Effort:** L.

**R20 — Medium — Dead/duplicated scoring APIs and an unimplemented degraded-mode trigger**
- **Location:** `api/helpers.py::calculate_composite_score`, `classify_confidence_tier`, `jaccard_similarity`; `api/confidence.py` (`degraded` set only when the model is missing).
- **Problem:** `helpers.classify_confidence_tier` still exposes `EXACT ≥ 0.85`, contradicting `confidence.classify_confidence_tier` (no `EXACT`). The legacy composite scorer and Jaccard helper are imported into `pipeline.py` and never called. The contract says a reranker outage must trigger degraded mode; the implementation only reacts to a missing model.
- **Evidence:** the two same-named functions with different thresholds; `pipeline.py` imports `calculate_composite_score`, `classify_confidence_tier`, `jaccard_similarity` without use; `resolve_confidence` never inspects reranker availability.
- **Proposed correction:** delete the legacy scorer/classifier/Jaccard helper (or rename and mark deprecated), remove the dead imports, and implement the documented degraded trigger for reranker failure with `degraded=True`, cap at `STRONG`.
- **Dependencies:** R1.
- **Validation:** Stage A — grep proves one tier function exists; Stage B — force `reranker=None` and assert `degraded=True` and tier cap.
- **Acceptance:** one tier implementation; degraded mode reachable by both documented triggers.
- **Effort:** S.

---

### Phase 3 — Evaluation and ground truth (start immediately; blocks all numeric claims)

**R21 — Critical — The evaluation set measures document re-identification, not relevance to a realistic query**
- **Location:** `scripts/build_calibration_dataset.py::extract_nvd_query` / `extract_cisa_query`; every confidence metric downstream.
- **Problem:** positive queries are the target document's own first sentences (≤180 chars) with CVE tokens stripped, so the query is a near-copy of the evidence. High AUC/log-loss gains reflect lexical containment, and the model's utility for analyst queries is untested. The project's own "harder paraphrased" probe drops to 16.88 % top-1 / MRR 0.2258, which is the realistic signal.
- **Evidence:** `extract_nvd_query` selects sentences from `text` and truncates; the same `text` is stored as the positive's `text`; `retrieval_eval_full_corpus.py` reports 79.38 % vs 16.88 % for the two formulations.
- **Proposed correction:** build a task-based evaluation set of queries authored independently of corpus text (analyst-style descriptions, vendor/product + symptom, partially specified identifiers, multi-CVE incidents), with ground truth = acceptable CVE/document set, double-annotated with adjudication, frozen and split into **development** and **sealed** parts before any tuning. **Size is set by power, not by a round number (X3):** the *sealed* part alone must be large enough to support the Task-1 pass rule (X5). Required n for a one-sided 95 % Clopper-Pearson lower bound to clear the target with 80 % power:

  | Target | Assumed true precision | Required n | Max errors allowed |
  |---|---|---|---|
  | 0.90 (Task 1) | 0.97 | 76 | 3 |
  | 0.90 (Task 1) | 0.95 | 179 | 11 |
  | 0.90 (Task 1) | 0.93 | 549 | 43 |
  | 0.70 (PoC) | 0.85 | 49 | 9 |
  | 0.70 (PoC) | 0.80 | 119 | 27 |
  | 0.70 (PoC) | 0.78 | 193 | 47 |

  (Computed with exact binomial/beta quantiles; queries assumed independent. Recompute for the true design, e.g. if one query yields several graded items.) The original "150–300 queries with a 70/30 sealed split" gives 45–90 sealed queries, which is underpowered unless true Task-1 precision is already ≈ 0.97. The total size is therefore `n_sealed / sealed_fraction`, with the assumed true precision stated and justified (for example from a pilot).
- **Dependencies:** none — start now.
- **Validation:** Stage C — inter-annotator Cohen's κ on relevance labels, with the threshold fixed in the annotation protocol *before* labelling (0.70 is a common convention for "substantial" agreement, not a derived value; if κ falls short, the guideline is revised and the set re-annotated, the bar is not lowered); query–document lexical overlap distribution reported against the current set; a leak check for long verbatim spans (10 tokens is a convention; also report the distribution of longest-common-span and a paraphrase-similarity score, since a leak shorter than 10 tokens can still be a near-copy).
- **Acceptance:** the sealed split meets the power-derived n above; the frozen set contains no verbatim span over the pre-registered length; κ meets the pre-registered threshold; set is hashed before any tuning.
- **Effort:** XL.

**R22 — High — Negative construction is mostly trivial and the class prior is unrealistic**
- **Location:** `scripts/build_calibration_dataset.py::find_adjacent_negative` / `find_bm25_distractor_negative` / cross-CVE EPSS/KEV block; `split_and_fold_dataset`.
- **Problem:** 2 of 3 negatives per query (adjacent CVE id; a random EPSS/KEV one-liner for another CVE) are lexically disjoint from the query; only the BM25 distractor is hard. The fixed 1:3 ratio also ignores operational prevalence (the docs' own analysis shows the consequences).
- **Evidence:** adjacent negatives come from a different product's description; EPSS/KEV negatives are templated one-liners; every group has exactly 1 positive and 3 negatives.
- **Proposed correction:** mine negatives from the actual retrieval top-k at multiple depths, include same-product/same-CWE/same-vendor and paraphrase-level confusables, report metrics per negative strategy, and evaluate under prevalence-matched reweighting.
- **Dependencies:** R21.
- **Validation:** Stage D — per-strategy AUC and precision; report the headline metric on the hard-negative-mined subset and on the full set; report at 1:3 and at the operational prevalence (estimated from query logs or a stated assumption; 1:20 is an illustration, not a measured prevalence). No "≤ 50 % of signal" cap is imposed; instead the headline number must be computed on a set whose negatives come from the retrieval top-k.
- **Acceptance:** per-strategy and hard-negative results are reported separately; the headline metric is not computed on trivially separable negatives alone.
- **Effort:** L.

**R23 — Critical — Task-1 precision has never been measured as specified**
- **Location:** `scripts/evaluate_sealed_test.py::main` (Task-1 block); `scripts/retrieval_eval_full_corpus.py`; artefacts `data/labels/sealed_test_results.json`, `data/labels/full_corpus_retrieval_eval.json`.
- **Problem:** the 100 % figure comes from a 4-candidate pool in which the positive is the query's own source text, with `y_pred_binary` hard-coded to 1 — precision is `mean(y_true) = 1.0` by construction. The 79.38 % figure is BM25-only top-1 document match over the corpus; it never invokes the confidence model (despite reporting "deciding layer: Layer 2") and it measures document identity, not description precision.
- **Evidence:** `top_m2_pred.append(1)  # Retrieved top candidate`; the pool is the group's 4 pairs; `retrieval_eval_full_corpus.py` only calls `bm25.search` and `match_layer1`, never `model.predict_proba`.
- **Proposed correction:** define Task-1 precision operationally (returned description is correct *and* complete for the queried CVE, judged by an annotator against the CVE record), measure it on the Stage-C set through the real service, and report the actual pipeline's precision with CI.
- **Dependencies:** R21, R1, R6a, R9, R12 (they change what a response returns).
- **Validation:** Stage D — the sealed set from R21 (size per its power table, replacing the arbitrary "200+") through the HTTP service; per-item adjudication; Clopper-Pearson CI.
- **Acceptance:** pass iff the one-sided 95 % lower bound ≥ 0.90 (X5). Point ≥ 0.90 with a lower bound below 0.90 is reported as **inconclusive**. A single reproducible number from end-to-end responses exists; the invalid artefacts are deleted.
- **Effort:** L.

**R24 — High — The benchmark harness cannot support the claims it prints**
- **Location:** `benchmarks/evaluate.py`.
- **Problem:** classification gates run on 10 queries; "P95" is `sorted(latencies)[int(n*0.95)]` = the maximum for n=10; `--retrieval` only changes a label (`engine.initialize` ignores the mode); latency includes synchronous network PoC discovery; `actual_tiers` are the original labels while the docs reinterpret them post hoc (`bench_03..07`, `docs/BENCHMARKS.md` §4).
- **Evidence:** `p95_idx = int(len(latencies)*0.95)`; `initialize_engine(retrieval_mode=...)` returns `mode_label` and discards the mode; `run_query` performs PoC discovery; the "Confusion Matrix (Calibrated After)" row shows expected `WEAK` → predicted `EXACT` four times.
- **Proposed correction:** separate offline classification evaluation from online latency measurement; use an interpolated percentile with n chosen so the tail quantile is estimable (≥ 100 for p95, ≥ 1,000 for p99, or report the order statistic and its bootstrap CI); implement real retrieval-mode switching or delete the flag; disable PoC discovery during evaluation; never reinterpret labels — re-annotate in a new dataset version with an audit trail.
- **Dependencies:** R21.
- **Validation:** Stage D — a harness self-test with synthetic predictions reproduces known metrics; latency measured with network disabled and reported per stage.
- **Acceptance:** every printed gate states its n and uses a statistic valid for that n; classification gates use the sealed set from R21; no test-set label is altered by prose.
- **Effort:** M.

**R25 — High — The "label audit" checks structure, not meaning, and the dataset card overstates it**
- **Location:** `scripts/build_calibration_dataset.py::run_random_audit`; `data/labels/dataset_card.md` §5.
- **Problem:** the audit verifies that the label matches the `doc_id` prefix, that the masked query contains no CVE token, and that `negative_type` is valid — all self-consistency checks. It never asks whether the query is a plausible analyst query or whether the document is the right answer. The card reports "0 errors / 0.0 %" as if semantic correctness were established.
- **Evidence:** the four checks in `run_random_audit`; `audit_passed` derived solely from them.
- **Proposed correction:** rename it "structural validation", and add a real blind audit (2 annotators × 100 pairs, adjudication, κ reported) covering query plausibility, document correctness, and negative validity.
- **Dependencies:** R21.
- **Validation:** Stage C — κ ≥ 0.70 and a reported error rate with CI; the dataset card cites the audit file by hash.
- **Acceptance:** the card states what was actually checked; no "0 errors" claim without semantic annotation.
- **Effort:** M.

**R26 — High — PoC "precision" is circular and untested against ground truth**
- **Location:** `poc_intelligence/poc_validator.py::calculate_precision`; `poc_intelligence/poc_finder.py` (`precision_score`).
- **Problem:** the metric is the share of returned items that the same heuristic labelled `HIGH_RELEVANCE_POC_CANDIDATE`/`POSSIBLE_POC`. It cannot fail by construction and says nothing about the 70 % requirement. No labelled PoC set exists, and fork/duplicate filtering is untested.
- **Evidence:** the label-membership sum in `calculate_precision`; `PoCFindResponse.precision_score` description acknowledging "not a measured production precision claim"; the README badge claims "Relevance Yield ≥70 % Benchmark" with no artefact.
- **Proposed correction:** build a labelled PoC evaluation set (size from the R21 power table for the 0.70 target, per source if per-source claims are made; stratified by CVE popularity, labelled `exploit-implementation` / `advisory-or-detection` / `discussion` / `irrelevant`), measure precision@k with CI, and report per-source and per-label breakdowns; rename the current field to `relevance_yield`.
- **Dependencies:** none (can run in parallel with R21).
- **Validation:** Stage D — precision with Clopper-Pearson CI against 0.70 using the X5 pass rule (lower bound ≥ 0.70); per-source precision with its own CI (per-source claims need per-source n); duplicate/fork rate.
- **Acceptance:** a real precision estimate replaces the circular metric; the badge claim is either supported or removed.
- **Effort:** L.

**R27 — Medium — Citations, traceability, and end-to-end quality are not evaluated at all**
- **Location:** `benchmarks/` (no citation or groundedness metric); README's RAGAS/DeepEval claim.
- **Problem:** there is no measurement that returned `text_snippet`/`doc_id`/`page` actually supports the cited claim, no check that citations resolve to stored chunks, and no end-to-end evaluation of the match→investigation path. The README's "Hallucination Citation Integrity 100 %" row is "Pending Evaluation Run".
- **Evidence:** `metrics.py` implements only Hit@k/MRR/NDCG/macro-F1/precision-recall; no citation tests in `verify/`.
- **Proposed correction:** add a citation-integrity test (every citation id resolves to a stored chunk; snippet is a verbatim substring of that chunk's text) and a groundedness evaluation on the Stage-C set (claim→evidence support rate, adjudicated).
- **Dependencies:** R9, R21.
- **Validation:** Stage D — **resolvability** (every citation id resolves to a stored chunk) and **substring fidelity** (snippet is a verbatim substring of that chunk) are deterministic: required 100 %, and any failure is a bug to fix, not a rate to tolerate (resolves X4). **Groundedness** (does the evidence support the claim) is human-adjudicated and statistical: report the supported fraction with a Clopper-Pearson CI over a sample sized for the target chosen in advance, using the R21 power approach.
- **Acceptance:** resolvability and substring fidelity are 100 % on the sealed set, with zero itemised failures; groundedness is reported with CI against its pre-registered target.
- **Effort:** M.

---

### Phase 4 — Source connectors and failure handling

**R28 — High — Paid X requests are enabled by default and the PoC endpoint has no quota**
- **Location:** `poc_intelligence/sources/x_scraper.py::__init__` (`X_ALLOW_PAID_REQUESTS` default true); `api/main.py::find_pocs_for_cve`; `backend/api/main.py::find_pocs_endpoint`.
- **Problem:** with a bearer token present, the default configuration spends money per request; neither the Team 2 endpoint nor the backend proxy enforces a per-user or per-window quota, and the backend proxy has no caching guard of its own. A single authenticated user can drive repeated billable searches.
- **Evidence:** `_env_bool("X_ALLOW_PAID_REQUESTS", True)`; no rate-limit dependency on either route; login rate limiting exists only for auth.
- **Proposed correction:** default `X_ALLOW_PAID_REQUESTS=false`; add per-user quota and a global token bucket for outbound paid calls; surface `status="cost_protection"` in the API as a first-class state.
- **Dependencies:** R5 (cache correctness reduces spend).
- **Validation:** Stage B/D — N rapid requests exceed the quota and return 429 with `Retry-After`; with the default env, no X request is attempted.
- **Acceptance:** cost cannot be incurred without an explicit opt-in and a quota.
- **Effort:** S.

**R29 — Medium — Connector robustness and status-contract drift**
- **Location:** `poc_intelligence/sources/bluesky_scraper.py` (`response.json()` outside the try, `record.get("embed", {})` type assumptions, no 401 branch), `mastodon_scraper.py` (top-level bs4, hardcoded instances, query hardcodes `" poc"`), `api/schemas.py::SourceStatusSchema` (enum), `poc_finder.py`.
- **Problem:** malformed JSON from BlueSky raises out of `search_with_status`, and `embed` may be a string; status strings actually emitted (`invalid_input`, `cost_protection`, `unavailable`, `malformed_response`) are not in the documented enum, so consumers cannot switch exhaustively. Query construction hides a precision/recall choice (mandatory "poc" token) from `coverage_limitations`.
- **Evidence:** the code sites above; `SourceStatusSchema.status` description lists nine values that do not include these four.
- **Proposed correction:** wrap parsing and type checks; add 401 handling; move instance lists and query templates to config; extend the status enum (or map to documented values) and document which states mean "no data" versus "failure".
- **Dependencies:** R3.
- **Validation:** Stage B — fuzz each connector with malformed JSON, wrong types, 401/403/429/5xx and assert a typed status, never an exception.
- **Acceptance:** no connector raises; every emitted status is documented.
- **Effort:** M.

**R30 — Medium — Dead evidence signal and substring CVE matching in PoC validation**
- **Location:** `poc_intelligence/poc_validator.py` (`has_code_evidence = bool(candidate.raw_metadata.get("code_evidence"))`, `exact_cve = cve.lower() in lower_text`); connectors never set `code_evidence`.
- **Problem:** the "implementation evidence" channel has a dead sub-signal, while `exact_cve` is a substring test — querying `CVE-2024-3400` matches a post about `CVE-2024-34001`. Both push precision in opposite directions without being measured.
- **Evidence:** no connector writes `code_evidence`; the membership test is plain `in`.
- **Proposed correction:** match with the word-boundary CVE regex; populate `code_evidence` from GitHub code-search results (already collected as evidence text) or delete the branch; add regression cases for the prefix-collision.
- **Dependencies:** R26 (so the change is measured).
- **Validation:** Stage B — `CVE-2024-3400` must not match `CVE-2024-34001`; a code-search hit must raise the score via the intended channel.
- **Acceptance:** no false positive from prefix collision; each scoring channel is reachable.
- **Effort:** S.

**R31 — Medium — PoC cache paths depend on the working directory and expired rows accumulate**
- **Location:** `poc_intelligence/poc_cache.py::DEFAULT_DB_PATH`, `DEFAULT_NORMALIZED_CVES_DIR`; `_ensure_table`; and (N3) `api/pipeline.py::initialize`, which resolves `./data/mitre/enterprise-attack.json` against the CWD.
- **Problem:** `./data/sqlite/corpus_store.db` resolves against CWD while `vector_database` anchors to the repo root, so running uvicorn from another directory silently creates a second cache DB. No cleanup of expired rows.
- **Evidence:** the relative defaults; the repo-root anchoring in `vector_database._REPO_ROOT`.
- **Proposed correction:** resolve both paths from a single settings object anchored at the package root; add a periodic delete of expired rows.
- **Dependencies:** none.
- **Validation:** Stage A — start the server from a different CWD and assert the same DB file is used; expired rows removed after the sweep.
- **Acceptance:** one deterministic cache location independent of CWD.
- **Effort:** S.

---

### Phase 5 — Performance, memory, and resource architecture

**R32 — Critical (symptom) — End-to-end latency is 31–75 s per query in the 2026-10-15 baselines; cause not yet established**
- **Status:** the symptom is read from artifacts (A); every causal statement in the original plan is a hypothesis (H) until V1 profiles it.
- **Location:** `api/pipeline.py::run_query`, `search_engine/hybrid_search.py`, `search_engine/bm25_index.py::search`, `search_engine/vector_database.py::setup_qdrant`, `search_engine/vectorizer.py`, `search_engine/reranker.py`.
- **Problem:** per-query latencies in `baseline_before.json` / `baseline_after.json` are 31–75 s, including queries with no CVE (34–75 s), so PoC discovery is not the sole cause (A). `benchmarks/benchmark_results.json` (2026-09-30) records 23–176 ms for the same ten query ids with repeated tier-template-like scores (0.4 ×5, 0.125 ×3), so the earlier figure is either a different or stubbed engine, or the system regressed (N6). The reported "P95 75,444 ms" is the maximum of ten observations (R24), not a percentile.
- **Candidate causes to test (all H):** (1) embedded `QdrantClient(path=...)` over 362,301 × 1024 vectors (N2); (2) per-query pure-Python BM25 posting traversal; (3) CPU cross-encoder over ≈25 pairs (a bounded count, per R12's narrowing); (4) CPU thread contention or fp16 on CPU; (5) first-request initialisation inside `run_query` (benchmark harness calls `initialize()` lazily); (6) query-time `max_length`/padding in the embedder (the 8192 setting was found in the *ingestion* path; the query path was not checked); (7) PoC network time, bounded by ≈ `N_CVE × 10 s` (N5). Causes are ranked by V1's per-stage profile, not by argument.
- **Proposed correction:** run V1; define the budget in V2; then apply only the interventions the profile supports, chosen from (for example) a different Qdrant deployment mode or ANN index, a persisted lexical index (R33), rerank depth from the R12 sweep, ONNX/quantised or GPU inference for model stages, query-embedding and result caches, moving rerank/PoC off the core path. Interventions are listed after, not before, the measurement.
- **Dependencies:** V1, V2, R4, R12.
- **Validation:** Stage D/E — per-stage p50/p95/p99 from V1's protocol, network disabled, with n large enough for the quantile reported (R24); CI regression guard on a fixed hardware profile using V1's noise floor.
- **Acceptance:** the measured core-path latency meets `D_match` (V2) at the percentile V2 names, on the V1 host, with a per-stage budget traceable to the profile — or V2's SLA is formally re-baselined with the approval trail recorded.
- **Effort:** XL.

**R33 — High — BM25 is rebuilt from scratch on every start over 362,301 documents**
- **Location:** `search_engine/bm25_index.py::build_from_sqlite`; `api/pipeline.py::initialize`.
- **Problem:** startup tokenises every `enriched_text`, holding `_term_freqs`, `_doc_len` and postings for the whole corpus in Python objects, on every process start, with no persistence or incremental update (C). The cost in time and RAM is unmeasured (H) and is taken from V1; the original "minutes" and "multiple GB" were estimates. Failure is caught and replaced by an empty index, silently disabling lexical retrieval.
- **Evidence:** `SELECT chunk_id, enriched_text FROM corpus` with no LIMIT, per-row `tokenize` and dict insertion; `initialize` wraps it in `try/except` producing `BM25Index()`.
- **Proposed correction:** persist the index (e.g. an inverted-index file or SQLite FTS5) and load it lazily/with `mmap`; or switch the lexical side to SQLite FTS5/BM25 so no in-memory build is needed; make an empty index a startup failure for the retrieval profile that requires it.
- **Dependencies:** R14.
- **Validation:** Stage E — measure cold-start time and RSS with the persisted index versus current (V1 protocol); assert ranked lexical results are identical (same ids, same order up to documented tie-breaking) on a fixed sample of queries drawn from the R21 query types.
- **Acceptance:** cold start within the restart-time budget the deployment requires, and RSS within the memory limit derived in V1 — both written down before the change, not chosen afterwards.
- **Effort:** L.

**R34 — High — PoC discovery is coupled into `/match`, making the core retrieval path depend on four external services**
- **Location:** `api/pipeline.py::run_query` (PoC block) and `poc_intelligence/poc_finder.py::find_pocs_sync`.
- **Problem:** a match request performs up to 4 × N_CVE outbound scrapes synchronously, so availability, latency, rate limits, and cost of third-party platforms determine whether threat matching works. Failures are swallowed at `logger.debug`, so the caller cannot tell enrichment failed.
- **Evidence:** the PoC block inside `run_query`; the `except Exception: logger.debug(...)` around it; `poc_discovery_ms` counted inside `citation_ms` (double-counted in the profile). Latency is ≈ `N_CVE × per-source timeout` because sources run concurrently but CVEs sequentially (N5).
- **Proposed correction:** make enrichment opt-in (`include_pocs=false` by default for `/match`) or return a job handle; run it asynchronously with its own deadline; report `poc_status` per CVE; fix the latency accounting so `citation_ms` excludes PoC time.
- **Dependencies:** R4.
- **Validation:** Stage B/D — with all PoC sources blackholed versus reachable, `/match` latency differs by less than the run-to-run noise floor from V1 (not "unchanged"); `poc_status` reports `unavailable`; latency components sum to `total_ms` within a tolerance stated from timer resolution.
- **Acceptance:** core matching is independent of OSINT availability; latency accounting is additive; PoC enrichment runs under `D_poc` (V2).
- **Effort:** M.

**R35 — High — No concurrency control, request deadlines, or input bounds; one shared SQLite connection**
- **Location:** `search_engine/vector_database.py::setup_sqlite` (`check_same_thread=False`), `api/main.py` (no size limits), `api/schemas.py::MatchRequest` (query unbounded, `top_k ≤ 50`).
- **Problem:** a single SQLite connection is shared across FastAPI worker threads while the PoC cache writes to the same file; a long query string or `top_k=50` multiplies rerank cost without limit; no request deadline exists. Under concurrency this risks `database is locked` and unbounded queueing.
- **Evidence:** `check_same_thread=False` with one connection; `query: str` with no `max_length`; no timeout middleware; PoC cache opens separate write connections to the same DB.
- **Proposed correction:** connection pool or per-thread connections with a busy timeout; `max_length` on query text; bounded `top_k` with documented cost; per-request deadline and a concurrency semaphore around embedding/rerank.
- **Dependencies:** R4, R32.
- **Validation:** Stage D — load test at the design concurrency (from expected Team 3 usage and the V2 worker bound `W`), at 2×, and beyond `W`: zero `database is locked`; p99 within `D_match` up to `W`; graceful 429/503 beyond the semaphore. (The original "32 concurrent" was not derived from any stated usage.)
- **Acceptance:** the service degrades predictably under load instead of stalling or erroring.
- **Effort:** M.

---

### Phase 6 — Security and deployment hardening

**R36 — High — Permissive CORS on a credential-bearing, unauthenticated internal service**
- **Location:** `api/main.py` CORS middleware (`allow_origins=["*"]`, `allow_credentials=True`); absence of auth on Team 2 routes.
- **Problem:** `*` combined with credentials is invalid per the CORS spec and a browser will reject it, while signalling a permissive posture; more importantly, `/match` and `/pocs/find` are unauthenticated and drive paid outbound calls, so anyone who can reach port 8000 can consume budget and CPU.
- **Evidence:** the middleware block; no dependency on any auth scheme in `api/main.py`; the backend, by contrast, has session/JWT/roles.
- **Proposed correction:** replace `*` with an explicit allowlist; add service-to-service auth (shared token or mTLS) for `/match` and `/pocs/find`; keep a local-dev bypass behind an env flag.
- **Dependencies:** none.
- **Validation:** Stage A/D — preflight from a non-allowlisted origin fails; unauthenticated request returns 401; compose-internal calls succeed with the token.
- **Acceptance:** no wildcard-with-credentials; every route requires authentication in non-dev mode.
- **Effort:** M.

**R37 — Medium — Error detail leakage and unvalidated proxy input**
- **Location:** `backend/api/main.py::find_pocs_endpoint` (`HTTPException(502, f"...{str(exc)}")`, `body = await req.json()` then `body.get(...)`), `api/main.py` (unhandled exception → 500).
- **Problem:** internal exception text reaches the client; a non-object JSON body raises `AttributeError` → 500; the proxy forwards arbitrary payloads to Team 2 without schema validation, so error semantics differ between direct and proxied calls.
- **Evidence:** the `str(exc)` interpolation; raw `await req.json()`; no `PoCFindRequest` model on the backend route.
- **Proposed correction:** validate with the shared Pydantic model, return a correlation id plus a generic message, and log the detail server-side only.
- **Dependencies:** none.
- **Validation:** Stage B — malformed body returns 422; forced internal error returns a generic 502 with a reference id and no stack text.
- **Acceptance:** no internal detail in responses; one schema for direct and proxied calls.
- **Effort:** S.

**R38 — Medium — CWD-relative paths and deployment drift**
- **Location:** `backend/api/main.py` (`StaticFiles(directory="frontend")`), `poc_intelligence/poc_cache.py`, `deployment/docker/Dockerfile.*`, `backend/api/main.py` PoC fallback import of `threat_retrieval_engine`.
- **Problem:** two services resolve resources relative to the working directory; the backend image does not copy `threat_retrieval_engine/` or its dependencies, so the in-process PoC fallback (`backend/api/main.py:708`) can never work in the container and always ends in a 502 whose cause is swallowed by `except Exception: pass`.
- **Evidence:** `Dockerfile.backend` copies only `backend/`, `llm/`, `frontend/`; the fallback import; the `except ... pass` before it.
- **Proposed correction:** anchor all paths to a settings object; either install Team 2 as a proper package in the backend image or delete the fallback and return a typed `503 service_unavailable` with the upstream error recorded.
- **Dependencies:** R3.
- **Validation:** Stage A — run both containers and exercise `/api/v1/pocs/find` with Team 2 stopped: expect a typed 503, not a silent 502.
- **Acceptance:** no CWD-dependent path; every fallback is either functional or removed.
- **Effort:** S.

**R39 — Medium — The retrieval dependency set is unpinned and incomplete**
- **Location:** `requirements-retrieval.txt` (all `>=`), `pyproject.toml`.
- **Problem:** floating versions make the 4.48 GB index, the embedding model revision, and the numeric behaviour of the confidence model irreproducible; `httpx`, `beautifulsoup4`, `scipy`, `scikit-learn` are used but undeclared. There is no lockfile and no separation between service and research dependencies.
- **Evidence:** the requirement file contents; imports in `sources/*.py`, `scripts/retrieval_eval_full_corpus.py`, `scripts/train_confidence_model.py`.
- **Proposed correction:** pin exact versions, add a lockfile, split `requirements-retrieval.txt` (service) from `requirements-research.txt` (training/evaluation), and pin the model revision/hash.
- **Dependencies:** none.
- **Validation:** Stage A — two clean installs produce identical `pip freeze`; the service boots from the pinned set alone.
- **Acceptance:** reproducible environment; every imported third-party package is declared.
- **Effort:** S.

---

### Phase 7 — Tests, documentation, and configuration reconciliation

**R40 — High — Twelve documented test modules do not exist; the retrieval core is untested**
- **Location:** `verify/` (actual files: PoC tests plus `test_confidence_contract.py` and `test_pipeline_poc_enrichment.py`); README repository-structure section.
- **Problem:** `test_bm25_index.py`, `test_hybrid_search.py`, `test_reranker.py`, `test_validator.py`, `test_vectorizer.py`, `test_vector_database.py`, `test_mitre_graph.py`, `test_tokenizer.py`, `test_duplicate_checker.py`, `test_exact_lookup.py`, `test_ingestion_pipeline.py`, `test_api_single_endpoint.py` are all absent, so tokenisation, fusion, dedup, exact lookup, storage, and the HTTP contract have no regression protection.
- **Evidence:** existence check returned MISSING for all twelve; no `conftest.py`/`pytest.ini`; only `test_poc_*`, `test_x_source.py`, `test_confidence_contract.py`, `test_pipeline_poc_enrichment.py` exist.
- **Proposed correction:** add the missing unit tests (tokenizer atomic tokens and IPv4 validation; BM25 IDF/TF edge cases and empty index; RRF rank arithmetic and duplicate handling; exact-lookup mention versus primary; dedup threshold behaviour across sources; storage round-trip and re-ingestion; graph loading with a real bundle fixture), plus an API contract test that posts a production-shaped request and validates the response schema.
- **Dependencies:** R1, R2, R7, R10, R12 (tests encode the corrected contracts).
- **Validation:** Stage A1 — `pytest verify -q` green in a clean env; a branch-coverage report is produced and published. Coverage is **not** gated at a fixed percentage (70 %/80 % were not derived from risk); instead (a) every item's reproduction from V0 is a test, (b) every Critical/High fix has a fails-when-reverted test, (c) coverage may not decrease from the first measured baseline.
- **Acceptance:** every module in `search_engine/` has direct tests; the README list matches the directory; the coverage baseline is recorded.
- **Effort:** L.

**R41 — High — Existing confidence tests are tautological and cannot fail**
- **Location:** `verify/test_confidence_contract.py::test_train_serve_feature_parity`, `test_metadata_separation`; `verify/test_pipeline_poc_enrichment.py`.
- **Problem:** the parity test calls the same function twice on the same dictionary that already contains `bm25_norm_score: 0.72`, so it proves only determinism; the metadata-separation test validates a hand-written `sources_found` dictionary that no code produces; the pipeline test asserts `query_threat_id.startswith("query_")` and `poc_discovery_ms >= 0.0` and never checks that a PoC was attached, despite its name.
- **Evidence:** the three test bodies; the parity test's two identical calls; the pipeline test's two assertions after mocking `exact_lookup` to `[]`.
- **Proposed correction:** replace with tests that construct the candidate dictionary exactly as `run_query` does (no injected `bm25_norm_score`), assert a non-degenerate probability and a tier consistent with the score, assert `sources_found` comes from ingestion, and assert PoC attachment by content.
- **Dependencies:** R1, R10.
- **Validation:** Stage A — mutation check: reverting R1 must make the new tests fail.
- **Acceptance:** at least one test fails when each Critical fix is reverted.
- **Effort:** M.

**R42 — High — Documentation asserts contracts the code does not implement**
- **Location:** root `README.md` (request with `query_threat_id`/`query_text`/`observables`, `match_category: STRONG_MATCH`, Qdrant RRF/Neo4j/LlamaIndex stack, `/health`, `/search/hybrid`, `/entities/lookup`, benchmark table, repository tree), `docs/API_REFERENCE.md` (`top_k ≤ 100` vs schema `le=50`), `docs/BENCHMARKS.md` (reproduction commands), `docs/dev/confidence_scoring.md` (`threat_retrieval_engine/llm/workflows/investigator.py` path).
- **Problem:** a consumer following the docs sends `query_text` and gets a 422 (the schema requires `query`); `match_category` does not exist (the field is `confidence_tier`); `top_k=100` is rejected; the reproduction commands reference `scripts/evaluate.py`, `benchmarks/evaluate_confidence.py`, `confidence_model.joblib`, `golden_results.json`, `confidence_calibration_results.json` — none of which exist; the investigator path is wrong.
- **Evidence:** `schemas.MatchRequest`; `TopMatchSchema`; `api/main.py` route list; existence check results.
- **Proposed correction:** regenerate README/API docs from the OpenAPI schema and a real captured response; mark unimplemented architecture as "planned"; delete or create the missing scripts; correct the file paths.
- **Dependencies:** R14, R18, R23.
- **Validation:** Stage A — a docs test parses the request examples, validates them against `MatchRequest`, and resolves every referenced path.
- **Acceptance:** every documented example validates and every referenced path exists.
- **Effort:** M.

**R43 — Medium — `config/retrieval_config.yaml` is never read**
- **Location:** `config/retrieval_config.yaml` vs `search_engine/*` constants (`DEFAULT_RRF_K=60`, `k1=1.5`, `b=0.75`, `SIMILARITY_THRESHOLD=0.90`, chunk limits, PoC limits).
- **Problem:** none of the YAML keys are loaded anywhere; operators changing fusion weights, rerank depth, EPSS threshold, or PoC limits see no effect. The Dockerfile copies the file, reinforcing the false impression that it is authoritative.
- **Evidence:** repository-wide search finds the YAML referenced only in README and the PoC README; no `yaml.safe_load` consumer; values duplicated as literals in modules.
- **Proposed correction:** introduce one settings loader (Pydantic Settings or YAML + env override) and thread values into the modules; delete duplicated literals; or delete the file and document code-level defaults.
- **Dependencies:** R39.
- **Validation:** Stage A/B — change `rrf_k` in config and assert ranking changes accordingly; assert startup fails on an unknown key.
- **Acceptance:** every tunable has exactly one authoritative source.
- **Effort:** M.

**R44 — Medium — Dead code, triplicated vocabularies, and stale artefacts**
- **Location:** `api/helpers.py` (legacy scorer, duplicate regex/vocab, duplicated `_TOOL_TO_TECH`), `api/pipeline.py` (triple import fallback, dead imports), `api/confidence.py` (duplicate regex/vocab), `backend/api/main.py::THREAT_MATCHING_UNAVAILABLE`; artefacts `benchmarks/benchmark_results.json`, `baseline_before.json`, `baseline_after.json`, `data/labels/sealed_test_results.json`.
- **Problem:** three copies of the CVE/IP/hash/MITRE regexes and actor/malware lists invite drift; the legacy tier function contradicts the new one; the "matching unavailable" constant is unused while the route *is* wired to Team 3 (so the message contradicts behaviour); result artefacts are stale and mutually inconsistent.
- **Evidence:** the duplicated literals; `THREAT_MATCHING_UNAVAILABLE` defined at `backend/api/main.py:612` and never referenced; `investigate_threat(...)` used at the route.
- **Proposed correction:** extract a single `indicators.py` for patterns/vocabularies used by helpers, confidence, and the feature extractor; delete dead code and stale artefacts (or regenerate into a versioned `results/` directory with a manifest); remove the misleading constant.
- **Dependencies:** R20, R42.
- **Validation:** Stage A — import-graph check shows one definition per pattern; ruff/pyflakes reports no unused names; artefact directory contains only manifests referencing an existing run id.
- **Acceptance:** no duplicated vocabulary, no unused public symbol, no stale result file.
- **Effort:** M.

**R45 — High — Team 3 integration timeouts, zero-score handling, and UI semantics**
- **Status:** U (`llm/`, `backend/`, `frontend/` are outside the archive); confirm each cited line in V0.
- **Location:** `llm/workflows/investigator.py::fetch_team2_evidence` (`timeout=30`), `normalize_team2_evidence` (`score = item.get("composite_score") or ...`), `backend/api/main.py::get_threat_matches` (`mitre_tactics` populated from `associated_malware`, `match_status != "Unsupported"` gate), `frontend/app.js:272-302`.
- **Problem:** the client timeout (30 s) is below the latencies observed in the current build (31–75 s), so the integration fails today regardless of the confidence bug; `composite_score == 0.0` is falsy and silently replaced; malware families are rendered as "MITRE tactics"; and because all non-L1 matches currently return `UNSUPPORTED` with probability 0.0, Team 3's LLM is likely to answer `match_status: "Unsupported"`, suppressing every match in the UI. **Note:** the observed latencies are a defect of the current build (R32). They must not be used to size the timeout; the timeout is sized from the V2 contract.
- **Evidence:** the `urlopen(..., timeout=30)`; the `or` chain; `"mitre_tactics": result.get("associated_malware", [])`; the `!= "Unsupported"` guard; `composite_score` 0.0 in `baseline_after.json` (A).
- **Proposed correction:** read `T_client_match` from the V2 config (`= D_match + client margin`, so the client never gives up before the server has answered or declared a deadline); handle the server's documented deadline outcome explicitly (retry policy, user-visible message); PoC enrichment is fetched separately under `D_poc`, with polling or a job handle if it can exceed the request deadline. Use explicit `is None` checks; map malware to its own field; surface Team 2's `confidence_tier`/`probability`/`calibrated` directly in the API and UI instead of only through the LLM.
- **Dependencies:** V2, R1, R34. (R32 determines whether `D_match` is achievable; it is not needed to write the contract.)
- **Validation (revised; replaces "60 s stub succeeds"):** tests are parameterised on the V2 values and use a local stub server with an injectable or scaled clock, so no test sleeps for tens of seconds:
  1. *Static:* config asserts `T_client_match > D_match`.
  2. *Within deadline:* stub latency = 0.5·`D_match` and = `D_match` − margin → client returns the result.
  3. *At/after deadline:* stub latency = `D_match` + ε → the server returns its documented deadline outcome (not a hang), and the client surfaces it **before** its own timeout (proves ordering `D_match` < `T_client_match` end to end).
  4. *Characterisation of the original failure:* against the old configuration (30 s) a stub at the observed worst case (75 s, scaled) fails. This test is written first and must fail on the unmodified code, so a green result on the fixed code is meaningful.
  5. *Score semantics:* a `0.0` score is preserved and labelled, not replaced; UI shows tier and probability from Team 2.
  6. *PoC separation:* with PoC sources unreachable, `/match` completes within `D_match` and the UI shows `poc_status`.
- **Acceptance:** the client and server deadlines satisfy the V2 invariant in config and in an end-to-end test; the integration path preserves Team 2's confidence semantics; no test depends on a fixed 60 s figure.
- **Effort:** M.

---

## 3. Validation and acceptance plan

**Stage A — Static inspection and low-cost checks (two runs: A0 now, A1 as a gate; X6).**
*A0 (now, no corpus work):* run everything below on the unmodified commit and record failures. Red is expected; this is the baseline and feeds V0. *A1 (gate):* rerun after Phases 0, 1 and 7; only A1 must be green.
*Objective:* prove the repository is internally consistent and the service can start. *Prerequisites:* none for A0; Phases 0, 1, 7 for A1. *Approach:* clean virtualenv from pinned `requirements-retrieval.txt`; `python -c "import threat_retrieval_engine.api.main"`; `pytest verify -q`; ruff/pyflakes for unused names and undefined locals; JSON-schema validation of `models/confidence_model.json` against `FEATURE_NAMES`; a docs test that validates every example request and resolves every referenced path; container build and boot with no `.env`. *Success criteria (A1):* import succeeds, zero collection errors, all unit tests pass, zero undefined-name warnings, every documented path resolves, container reaches `/health`. *Proceed when:* A1 is green.

**Stage B — Component-level tests on bounded fixtures (≤1,000 chunks; no full corpus).**
*Objective:* verify each component's contract with production-shaped inputs. *Prerequisites:* A0 complete; V0. *Approach:* build a 1,000-chunk SQLite/Qdrant fixture from existing rows (`LIMIT`), with at least three records per CVE (description, KEV, EPSS); exercise tokenizer, BM25, RRF, exact lookup, dedup, storage round-trip/re-ingestion, reranker, graph with a small real STIX fixture, confidence resolution across a feature grid, cache keying, connector error paths (mock transport), and the API contract. *Success criteria:* the R1 gates (parity: schema identical, `max|Δ| ≤ 1e−6`; support guard; ordering sanity). Runtime-versus-training distribution is reported as a drift diagnostic, not a pass/fail gate; probability values for hand-picked pairs are not asserted; no `UnboundLocalError`; `len(top_matches) ≤ top_k`; identical filter semantics across engines; every connector returns a typed status for each injected fault; cache entries never cross parameter sets. *Proceed when:* all B gates pass and each Critical fix has a test that fails when reverted.

**Stage C — Representative evaluation set (the long pole; start in parallel with Phase 0).**
*Objective:* replace the self-referential dataset with defensible ground truth. *Prerequisites:* none. *Approach:* queries (count from the R21 power table) authored independently of corpus text, stratified by year (2017–2026), source, severity, and query type (exact identifier / partial identifier / symptom-only / multi-CVE / behavioural / benign); ground truth = acceptable CVE/document set plus required enrichment fields; two independent annotators with adjudication; development/sealed split with the sealed part sized to the power requirement (X3); a leak check for ≥10-token verbatim spans; a documented sampling frame. *Success criteria:* κ meets the threshold fixed in the annotation protocol; zero leaked spans over the pre-registered length; query–document overlap distribution reported and materially lower than the current set; the set is frozen and hashed before any tuning. *Proceed when:* the sealed split is locked and the hash is recorded.

**Stage D — Integration and quality evaluation (after R1, R2, R6a, R7, R9, R12 and Stage B; X7).**
*Objective:* measure what the service actually does, end to end. *Prerequisites:* Stages B and C; V1 and V2. *Approach:* run the frozen set through the HTTP service (network disabled for PoC except in the PoC-specific run); measure Top-1/Top-5 document precision with Clopper-Pearson CI, MRR@10, NDCG@10, tier confusion and per-band precision, ECE/reliability, citation resolvability and substring fidelity, PoC precision on the labelled PoC set, and per-stage latency p50/p95/p99; run a load test at 32 concurrent requests; repeat at 1:3 and at the operational prevalence (R22). *Success criteria:* Task-1 description precision passes the X5 rule (one-sided 95 % lower bound ≥ 0.90), PoC precision passes it against 0.70, citation resolvability and substring fidelity 100 %, `STRONG` band precision passes the X5 rule against 0.90 or the gate is formally renegotiated, zero `database is locked`, the V2 deadline contract holds (deadline outcome tests of R45) and the latency budget is met or explicitly re-baselined, and no metric derived from a pool containing the query's own source text. *Proceed when:* every published number in `docs/BENCHMARKS.md` is regenerated from this run.

**Stage E — Full-scale evaluation (deferred; host specification comes from V1).**
*Objective:* validate at 362,301 records. *Prerequisites:* Stages B–D green, V1 complete and showing (by extrapolation from smaller fractions) that the full run fits the chosen host, persisted BM25/FTS index (R33), pinned model revisions. *Hardware:* the host is specified from V1 as "measured peak X GB RAM (+ Y GB VRAM if a GPU is used) with Z % headroom"; CPU RAM and GPU VRAM are separate numbers, and a GPU is only relevant to the model stages, not to CPU-resident structures such as BM25 postings or embedded-Qdrant memory. The original "≥ 32 GB RAM or a GPU" is withdrawn. *Approach:* rebuild the index from scratch and verify row/point parity; measure recall@100, MRR@10, NDCG@10, throughput, cold-start time, and peak RSS; run the sealed set at full scale; run a nightly regression. *Success criteria:* recall@100 and the other quality metrics are no worse than the Stage-D values beyond their CIs, and meet targets fixed in advance from the product requirement (the original "recall@100 ≥ 0.90" had no stated derivation); cold start and RSS meet the budgets written down in V1/R33. *Executed in remediation, not in the audit.*

---

## 4. Completion criteria

Team 2 is ready only when all of the following hold:

0. The verification ledger (V0) is complete, every item carries its evidence class, and the profile (V1) and deadline contract (V2) exist; every number cited below traces to one of them or to a pre-registered target.
1. `python -c "import threat_retrieval_engine.api.main"` succeeds from a clean install of pinned, complete requirements, and the container starts with `/health` reporting every component.
2. One lexical-feature definition exists; no score key is aliased across meanings; the Stage-B parity gate passes; on labelled held-out data the repaired model is calibrated (reliability and ECE reported with CI) and not worse than the lexical-only baseline.
3. A CVE query returns a substantive description record (not an EPSS/KEV stub) with EPSS/KEV/severity as structured fields, and `sources_found` is populated from ingested data.
4. No citation contains a synthesised date, title, or source; every citation resolves to a stored chunk (100 %) and its snippet is a verbatim substring (100 %).
5. `stix_relationships` are traceable to document entities, query-derived edges are labelled, and the real ATT&CK bundle is either loaded or explicitly reported unavailable.
6. Exactly one confidence model artefact exists, its embedded metrics match the regenerated metrics file, and the tier thresholds carry measured per-band precision with confidence intervals.
7. Task-1 description precision on the sealed independent set, measured through the running service, has a one-sided 95 % Clopper-Pearson lower bound ≥ 0.90 (point estimate alone is inconclusive).
8. PoC precision on the labelled PoC set has a one-sided 95 % lower bound ≥ 0.70, with per-source breakdown; the circular `precision_score` is renamed and no unsupported ≥70 % badge remains.
9. Latency and resource budgets follow the V2 contract: measured per stage on the V1 host and met, or formally re-baselined with the approval trail recorded; `T_client_match > D_match` holds in config and in the end-to-end test.
10. `/match` succeeds with all OSINT sources unreachable; PoC enrichment is opt-in or asynchronous, with an explicit status.
11. Every route is authenticated in non-dev mode, CORS uses an explicit allowlist, no internal error detail reaches clients, and paid outbound calls require explicit opt-in plus a quota.
12. `pytest verify` is green, the twelve missing test modules exist, every Critical/High fix has a test that fails when reverted, and every documented example and referenced path resolves.
13. `config/retrieval_config.yaml` is either loaded as the single source of tunables or deleted; no duplicated vocabulary or dead public symbol remains.
14. Stale artefacts (`sealed_test_results.json` with 100 %, inconsistent baseline files, missing `evaluate_confidence.py`/`joblib` references) are removed or regenerated from the Stage-D run, and the docs cite one run id.

---

## Appendix A — Changes in revision 2

| Area | Change |
|---|---|
| Arbitrary criteria | R1 (≥ 0.45 point assertion, 5th–95th percentile gate, universal monotonicity), R16 (non-zero reranker weight), R8 (>10k relationships), R21 (150–300 queries; 70/30), R22 (≤ 50 % signal), R23 (200+), R24 (n ≥ 100), R27 (99 % vs 100 %), R33 (< 30 s), R35 (32 concurrent), R40 (70 %/80 % coverage), Stage E (recall@100 ≥ 0.90) were replaced by a decision rule, a power calculation, a deterministic invariant, or a value to be fixed in advance from V1/V2. Conventions kept (κ ≥ 0.70, 10-token leak span, 0.90 and 0.70 precision targets from the task) are marked as conventions or requirements. |
| Latency | New V1/V2; R4, R32, R34, R35, R45, Stage D and completion #9 reference one deadline contract. |
| Hardware | "≥ 32 GB RAM or a GPU" withdrawn; V1 measures; Stage E states how the host is specified. |
| Verification | §1.1–1.3 added; R2, R6, R12 corrected or split; R4 text corrected; R16 mechanism corrected; six additions (N1–N6). |
| Contradictions | §1.4 (X1–X9). |
| Constraint scope | Read-only applies to the audit; remediation execution is separately authorized (§1). |

## Appendix B — Items still requiring the full repository before work starts

Everything classed **U** in §1.2: the Dockerfile/requirements half of R3; docs, scripts and `data/labels` claims in R6 (counts), R10 (counts), R18, R19, R21–R23, R25, R27; the `backend/`, `llm/`, `frontend/`, `deployment/` claims in R28 (proxy), R36–R39, R42–R45; the existence of `data/mitre/enterprise-attack.json` in the deployed environment (R8).
