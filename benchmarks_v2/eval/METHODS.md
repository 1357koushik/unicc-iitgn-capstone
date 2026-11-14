# Evaluation harness: methods (work package B4)

This file states exactly how every number in a B4 report is computed. Code: `benchmarks_v2/eval/`.
Data contract: `docs/benchmark_format.md`. Plan: `docs/RETRIEVAL_V2_PLAN.md` (sections 4.6, 4.7, 6).
The block in section 12 is machine-checked against the code by `benchmarks_v2/eval/check_b4.py`.

## 1. Inputs and validation (`schema.py`)

* Every file is JSON Lines. Loaders collect every problem and fail with `<file>:<line>: <field>: <problem>`.
* Unknown fields, missing fields and wrong JSON types are errors (booleans must be JSON booleans; grades must
  be the integers 0, 1, 2; a boolean is not an integer).
* Queries: `qid` is `<slice>-<n>` and its prefix equals `slice`; `answerable` is `false` exactly for T7;
  non-generated sources need `id` and `licence`; duplicate qids are errors.
* Qrels: `doc_id` is an upper-case CVE ID or `attack:<ID>`; `judge` is required for `origin: judged` and
  forbidden otherwise; every qid must exist; an unanswerable query may only carry grade 0; a duplicate
  (qid, doc_id) is an error.
* Equivalence: at least two distinct valid members. Overlapping sets are merged (union-find), because "same
  flaw" is transitive; merges are listed as a report warning.
* Run files: one variant per file; unique qids; `ranked` de-duplicated; `score` a finite number; `tier` one of
  `UNSUPPORTED, WEAK, PARTIAL, STRONG, EXACT` or null; `probability` in [0, 1] or null. A `doc_id` that is not
  of contract form loads with a warning (it can never be judged, so it shows up as unjudged).
* Dataset directory: `queries.jsonl`, `qrels.jsonl`, `equivalence.jsonl`, `manifest.json`; test split under
  `sealed/`. Test-split rows outside `sealed/` and non-test rows inside it are errors. Every file's sha256 is
  recorded; files listed in the manifest with a sha256 are verified and a mismatch is an error.
* Scoring requires the run to cover every selected query (else error, or `--allow-incomplete`, which marks
  the report), and every answerable query to have a document with grade >= `min_grade`.

## 2. Documents, units and judgements

* A **unit** is an equivalence class (`eq:<first set_id>`) or a single document not in any set.
* A unit is **judged** for a query if any member has a qrel for that query; its grade is the **maximum**
  grade over its judged members (members judged differently are counted as "grade conflicts" in the report).
* Unanswerable queries (T7) are fully judged by definition: every document has grade 0. (The contract says
  only T7 is unanswerable and its ground truth is "must abstain"; see the contract notes in the B4 report.)
* `min_grade` (default 2): a unit is *relevant* for binary metrics if grade >= `min_grade`. Grade 1
  ("related") counts only in graded nDCG unless `--min-grade 1`.

## 3. Ranking metrics (`metrics.py`), answerable queries only

The ranked list is used **in file order**; scores are never used to re-sort, so ties keep the system's
order. Each document is mapped to its unit. A later member of a unit already seen keeps its rank position but
has gain 0 and is not a new hit ("a hit on any member counts once for the set").

* Success@k (k = 1, 5): 1 if a relevant unit occurs in the first k positions.
* MRR@10: 1/r for the first position r <= 10 holding a relevant unit, else 0.
* nDCG@10 (graded): gain(g) = 2^g − 1 (grade 2 → 3, grade 1 → 1, grade 0 → 0); DCG@10 = Σ_{r=1..10}
  gain_r / log2(r + 1). The ideal DCG uses **all judged units of the query with grade >= 1** (collapsed, so an
  equivalence set appears once at its maximum grade), sorted by grade, cut at 10.
* Recall@k (k = 10, 50, 100): |relevant units in the first k positions| / |relevant units|, over the judged
  relevant set (unjudged documents are neither hits nor part of the denominator).
* SetRecall@10, only for queries with at least two relevant units: |relevant units in the top 10| /
  min(|relevant units|, 10).
* An error record (HTTP 504, timeout, ...) has an empty ranking: every metric is 0 and the query stays in the
  denominator. An abstained answerable query also scores 0 (`abstain_is_miss`).

## 4. Unjudged documents

* For each answerable query the harness counts top-10 positions whose unit is unjudged. Reports show, per
  population, unjudged positions / top-10 positions (rate, with bootstrap interval) and the number of queries
  with any unjudged document.
* The reported **value** of a metric gives an unjudged document no gain. Because that would be the same as
  calling it not relevant, a population with unjudged documents is always flagged: the report shows the
  counts, the value under the opposite scenario (`if_unjudged_relevant`: every unjudged unit in the top 10 has
  grade 2 and joins the ideal), and the judgement-completeness gate **fails** unless `--allow-unjudged` is
  given, in which case the gate is WAIVED and the report says PROVISIONAL. For Success@k and MRR the two
  numbers bound the truth; for nDCG the scenario is not a strict bound (adding relevant units also raises the
  ideal).
* `pool` exports every (qid, doc_id) in the top 10 of the given runs whose unit has no judgement (answerable
  queries only; error records have no ranking; abstained records are pooled), with the rank per variant.

## 5. Abstention

* **False accept** (unanswerable query): the system did not abstain AND returned at least one result AND the
  top result's tier is PARTIAL or higher (`PARTIAL, STRONG, EXACT`). A null tier is not an accept. If the
  variant returns no tiers at all, the false-accept gate is MISSING (cannot be judged), never a pass.
  False-accept rate = false accepts / unanswerable queries (bootstrap and Wilson intervals).
* **Abstention rate** on answerable queries = abstained / answerable (also reported for unanswerable ones).
* **Risk–coverage** (5.3). Confidence key of a query = (tier rank, probability) of its top result, compared
  lexicographically (tier rank −1 when the tier is null, probability 0 when null; no key if both are null).
  A query is accepted at threshold t if its key >= t. Abstained, errored and empty queries are never accepted
  but stay in the population N; queries whose top result is unjudged are excluded from N and counted.
  Candidates are sorted by key, highest first; **tied keys form one group** (a threshold accepts the whole
  group). At group j: coverage_j = accepted_j / N, risk_j = wrong_j / accepted_j, where wrong = top result not
  relevant (always wrong for an unanswerable query). AURC = Σ_j (coverage_j − coverage_{j−1}) · risk_j with
  coverage_0 = 0, i.e. the area under the step curve up to the maximum coverage, which is reported with it.
  Without ties this equals (1/N) Σ_i risk(i).

## 6. Calibration and tier precision (`calibration.py`)

* Pairs: every returned result in the first `calib_depth` (default 10) positions of a record without error
  (abstained records included), whose unit is judged; label y = 1 if grade >= `min_grade`. Pairs with an
  unjudged unit are excluded and counted. ECE and Brier use pairs with a probability; tier precision uses
  pairs with a tier (EXACT results carry no probability, so they enter tier precision only).
* **ECE, equal-mass bins**: sort pairs by probability (stable). With P pairs and B bins (default B = 10),
  boundary k (k = 1..B−1) is placed after the ⌈k·P/B⌉-th smallest prediction, then moved forward to the end of
  that prediction's run of tied probabilities, so ties never straddle bins; empty bins are dropped.
  ECE = Σ_b (n_b / P) · |mean p_b − mean y_b|. The report gives requested and effective bin counts.
* **Brier** = mean (p − y)².
* **Reliability diagram data**: per bin n, probability range, mean probability, observed frequency and its
  Wilson interval.
* **Observed precision per tier** = relevant pairs / pairs with that tier, with a Wilson 95% interval (pairs
  treated as independent) and a query-level bootstrap interval (pairs of one query move together). The STRONG
  gate requires both lower bounds to meet its floor (`interval: both`).
* **Wilson interval** (no continuity correction), z = Φ⁻¹(0.975): centre = (p̂ + z²/2n)/(1 + z²/n),
  half-width = z·√(p̂(1−p̂)/n + z²/4n²)/(1 + z²/n); exactly 0 (1) at x = 0 (x = n).

## 7. Latency

End-to-end `latency_ms` of every record including errors (a 504 at 15 s is real latency). p50, p95, p99 use
linear interpolation between order statistics (NumPy's default, the same definition as the B5 harness),
with bootstrap intervals; mean and max are reported.

## 8. Populations and aggregation

* Per query, then per population: each slice present, `overall` (all evaluated queries; micro average over
  the queries where the metric is defined), `temporal_holdout`, and the groups of `gates.yaml` (`T3+T4`,
  `T9_id_name`, `free_text`).
* **Macro over slices** = unweighted mean of slice means over slices where the metric is defined (T7 never
  has ranking metrics).
* **Parent pairs** (T6): each derived query is paired with `meta.parent_qid`; the mean of (derived − parent)
  over pairs whose parent was evaluated; missing parents are counted.

## 9. Statistics (`stats.py`)

* **Bootstrap**: B = 10,000 resamples (default). A resample draws n queries uniformly with replacement from
  the n queries of the population (count vector c). Every statistic is recomputed with weights c: means of
  defined values are Σc·v / Σc·d (d = 1 where defined), so undefined queries are excluded, never zero.
  Ratios (false-accept rate, tier precision, Brier, unjudged rate) are cluster (query-level) ratios.
  Non-linear statistics (ECE, AURC, latency percentiles) are recomputed on the weighted sample, which equals
  computing them on the sample with each query repeated c_i times.
* **Seeds**: the random stream of each population is seeded from (seed, sha256(key)) with seed default
  20261114 and key `pop|<name>`, `macro|<metric>`, `cmp|<population>`, `cmpmacro|<metric>`,
  `parent|<pair>`; results therefore do not depend on which other populations are evaluated. Resamples are
  generated in fixed blocks of 250.
* **Interval**: 95% percentile interval = 2.5th and 97.5th percentiles (linear interpolation) of the bootstrap
  values (undefined resamples dropped).
* **Paired bootstrap** (A − B on the same queries): per-query differences d over queries defined in both;
  the same resample of queries is applied to both systems. diff = mean d; interval as above.
  **Two-sided p-value** (dual to the percentile interval): p = min(1, 2·min(1 + #{Δ* ≤ 0}, 1 + #{Δ* ≥ 0}) /
  (B + 1)). Identical runs give Δ* = 0 throughout and p = 1.
* **Non-inferiority** (plan 4.6): H0: Δ ≤ −margin. A is non-inferior when the lower bound of the two-sided
  95% interval — the α = 0.025 percentile of Δ* — is >= −margin (margin default 0.01 = 1 point, on nDCG@10 and
  Success@1). One-sided p = (1 + #{Δ* ≤ −margin}) / (B + 1). This is the CONSORT convention (two-sided 95%
  interval, one-sided α = 0.025).
* **Stratified bootstrap for macro metrics**: queries are resampled within each slice independently (slice
  sizes fixed, as in the design); the macro value of each resample is the mean of slice means (a slice whose
  resample has no defined value is left out of that resample's mean). Paired macro differences use the same
  stratified scheme.

## 10. Gates (`gates.py`, `gates.yaml`)

Thresholds are configuration (plan 6.7), frozen by the package that freezes them. Each gate yields PASS,
FAIL, MISSING (population, comparison or metric absent: counts as a failure), NOT_APPLICABLE (population
present but metric undefined, only where the gate allows it, e.g. ECE of a slice answered only by EXACT hits)
or WAIVED (judgement completeness with `--allow-unjudged`). Overall PASS requires no FAIL and no MISSING.
Point thresholds apply to the point estimate; `lower_min` to the lower interval bound; comparison gates use
the paired difference and its interval; non-inferiority gates use the stored α-percentile lower bound and
require the report's α to equal the gate's.

## 11. Runs (`adapters.py`, `runner.py`, `variants.yaml`)

* HTTP adapters POST `{"query", **request}` (v1: `top_k: 10`) and map the response with configured dotted
  paths. v1 `/threats/match`: `citations.0.doc_id` → CVE prefix before any `_EPSS`/`_KEV` suffix; score and
  probability `composite_score`; tier `confidence_tier`; an empty result list is abstention (v1 has no
  abstention signal). v1 `/search/hybrid`: `chunk_id` resolved read-only through the v1 corpus database, score
  `rrf_score`, no tier or probability. Results are de-duplicated after mapping, keeping the first occurrence.
* Non-200 responses become `error: "http_<status>: <body prefix>"`, a client timeout becomes `timeout: ...`,
  both with an empty ranking and the measured latency; they are never dropped or retried. Connection
  refused/reset is retried (2 times by default) and then stops the run (exit 3) without recording the query.
  A response that does not have the configured shape stops the run (configuration error).
* Runs append one fsynced line per query, skip qids already present, and repair a truncated last line on
  resume. `--pause-after-error S` waits S seconds after a recorded error (the error is still recorded) so
  work v1 keeps running after its 504 does not spill into the next measurement.
* Run-file additions beyond the contract: optional per-record `extra` (`http_status`, `raw_results`,
  `duplicates_removed`) and a sidecar `<run>.meta.json` (variant configuration and per-session host, harness
  commit, service health response, load average, counts).

## 12. Settings (machine-checked)

```methods-check
{
  "settings": {"min_grade": 2, "abstain_is_miss": true, "calib_depth": 10, "ece_bins": 10,
               "false_accept_min_tier": "PARTIAL", "bootstrap": 10000, "seed": 20261114, "ci": 0.95,
               "ni_alpha": 0.025, "ni_margin": 0.01, "ni_metrics": ["ndcg@10", "success@1"]},
  "depth": 10,
  "unjudged_relevant_grade": 2,
  "bootstrap_block": 250,
  "gain": {"0": 0, "1": 1, "2": 3},
  "examples": [
    {"what": "nDCG@10 with equivalence collapse and a duplicate member",
     "ranking": ["CVE-2014-0160", "CVE-2014-0346", "CVE-2017-0144"],
     "grades": {"CVE-2014-0160": 2, "CVE-2014-0346": 2, "CVE-2017-0144": 2},
     "equivalence": [["CVE-2014-0160", "CVE-2014-0346"]],
     "metric": "ndcg@10", "expected": 0.919721},
    {"what": "graded nDCG@10",
     "ranking": ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004"],
     "grades": {"CVE-2021-0001": 1, "CVE-2021-0002": 0, "CVE-2021-0003": 2, "CVE-2021-0004": 1, "CVE-2021-0005": 2},
     "equivalence": [], "metric": "ndcg@10", "expected": 0.503253},
    {"what": "ECE, 2 equal-mass bins with ties", "p": [0.2, 0.5, 0.5, 0.5, 0.9, 0.9], "y": [0, 1, 0, 1, 1, 1],
     "bins": 2, "expected": 0.083333},
    {"what": "Wilson 95% upper bound for 0 of 10", "x": 0, "n": 10, "expected": 0.277533}
  ]
}
```

## 13. Limitations

* Percentile intervals slightly under-cover for proportions near 0 or 1 at small n; gates with a lower-bound
  floor are therefore stated on samples of at least 150 queries (plan 6.3).
* Wilson intervals for tier precision assume independent pairs; the bootstrap interval does not, which is why
  the STRONG gate needs both.
* ECE with equal-mass bins is biased upward for small samples; the bin count is reported with every value.
