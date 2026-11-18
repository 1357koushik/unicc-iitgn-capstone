# Confidence Scoring & Tier Classification Contract

**Document Version:** 1.0.0  
**Status:** FROZEN (Phase 1)  
**Target Branch:** `fix/learned-calibrated-confidence`  
**Applicability:** Threat Retrieval & Matching Subsystem (TRMS) — UNICC x IITGN Capstone

---

## 1. Problem Statement & Architecture Principles

### 1.1 Evaluator Feedback & Baseline Failures
- **Evaluator Finding:** On Task 1 (*Vulnerability Enrichment - CVE, Tier A, expected precision $\ge 90\%$*), feedback stated: *"Confidence Scoring method is not correct."*
- **Baseline Root Cause (Phase 0 Audit):**
  1. The existing scoring in `helpers.py` uses fixed static weights `CALIBRATED_SCORING_WEIGHTS = (0.40 IOC, 0.20 TTP, 0.20 Semantic, 0.20 CVE)`. These are uncalibrated heuristics not fitted to relevance data.
  2. The score is not a probability; "0.85" does not represent an 85% probability of true relevance.
  3. Observables absent from the query are penalized identically to observables missed by a document. When a query contains only a CVE (no host IOCs, no TTPs), `ioc_sim=0` and `ttp_sim=0`, yielding a base composite score of $0.380$.
  4. An ad-hoc override in `pipeline.py:432-433` (`elif cve_sim == 1.0: composite = max(composite, 0.400)`) clamped the score to $0.400$. Because the `weak_to_partial` threshold is $0.45$, all exact CVE matches without IOCs were forced into **`WEAK`**.

### 1.2 Two-Layer Architecture
The new architecture divides confidence resolution into two distinct, decoupled layers:

```
[ Incoming Query + Retrieved Document ]
                 │
                 ▼
┌────────────────────────────────────────────────────────┐
│ LAYER 1: Deterministic Identifier Match (No Model)     │
│  - Primary CVE ID match: doc_id prefix ^(CVE-\d{4}-\d+) │
│  - Hash match: MD5/SHA256 in entities_json['iocs']     │
│  - True by construction: Assigns tier EXACT            │
│  - Returns provenance: sources_found (NVD, CISA, etc.) │
└──────────────────────────┬─────────────────────────────┘
                           │ (No Layer 1 Exact Match)
                           ▼
┌────────────────────────────────────────────────────────┐
│ LAYER 2: Learned & Calibrated Probability / Fallback   │
│  - CVE / Vuln Queries: L2-Logistic Regression          │
│    Trained ONLY on ID-masked queries. Outputs P(rel).  │
│    Mapped to calibrated probability bands.             │
│  - Behavioral Queries (IOC/TTP): Option B Heuristic    │
│    Presence-renormalized M1 weights, calibrated=False. │
│    Documented as heuristic (no IP/hash corpus data).   │
└────────────────────────────────────────────────────────┘
```

---

## 2. Layer 1: Deterministic Identifier Match

Layer 1 operates strictly on exact identifier equality against document primary keys and structural entity sets.

### 2.1 Rules & Conditions
1. **`EXACT_ID`**:
   - Triggered when every queried CVE ID matches the document's primary CVE identifier.
   - **Primary Identification Rule:** Extracted directly from document ID prefix:
     $$\text{primary\_cve} = \text{regex\_match}(r"\text{\textasciicircum}(CVE-\backslash d\{4\}-\backslash d\{4,7\})", \text{doc\_id})$$
   - **Phase 0 Empirical Proof:** An audit of all 362,301 records in `data/sqlite/corpus_store.db` confirmed that **100% of records have `doc_id` matching this prefix** (0 exceptions). Therefore, fallback to `entities_json['cves'][0]` is formally dropped to eliminate ambiguity.
   - Incidental mentions of CVE IDs inside arbitrary text passages do NOT trigger Layer 1.
   - Queries with multiple distinct CVEs do not trigger Layer 1 unless the document primary ID covers all of them.

2. **`EXACT_HASH`**:
   - Triggered when a queried cryptographic hash (MD5 or SHA256) matches the document's own verified hash field in `entities_json['iocs']['sha256']` or `['md5']`.
   - **Corpus Qualification:** In Phase 0, the 362,301-record corpus was verified to contain **0 file hashes**. `EXACT_HASH` is implemented in runtime code and covered by synthetic unit test fixtures, but flagged as `"unvalidated on corpus"`.

3. **Output of Layer 1:**
   - Tier assigned: `EXACT` (by deterministic construction).
   - Probability assigned: `1.0`.
   - `calibrated`: `True` (deterministic certitude).
   - `match_type`: `EXACT_ID` or `EXACT_HASH`.
   - `tier_basis`: `DETERMINISTIC_L1`.
   - **Validation Standard:** Layer 1 precision is true by construction and reported separately. It is **never** presented as machine learning model validation. Task 1 precision claims must be demonstrated on the ID-masked Layer 2 slice.

### 2.2 Strict Separation of Metadata Fields
Layer 1 certifies that the retrieved record is the **correct document**, NOT that the vulnerability is severe or actively exploited.
The following fields are strictly separated and **never** merged into the confidence score:
1. `severity` (CVSS v3/v2 vector and score)
2. `epss_score` (daily exploitation probability percentile)
3. `cisa_kev` (boolean flag for inclusion in Known Exploited Vulnerabilities catalog)
4. `sources_found`: Dictionary of status per source (`NVD`, `CISA`, `EPSS`, `CVE_LIST_V5`), with values:
   - `FOUND`: Verified record exists in this source feed.
   - `NOT_FOUND`: Feed searched, no record exists.
   - `UNAVAILABLE`: Feed offline or unconfigured.

---

## 3. Layer 2: Learned Calibrated Confidence

All candidate pairs that do not qualify for Layer 1 pass to Layer 2.

### 3.1 Model Formulation
- **Algorithm:** L2-regularized Logistic Regression predicting:
  $$P(\text{relevant} = 1 \mid \mathbf{x}_{q, d}) = \sigma(\mathbf{w}^T \mathbf{x}_{q, d} + b) = \frac{1}{1 + e^{-(\mathbf{w}^T \mathbf{x}_{q, d} + b)}}$$
- **Inference Guarantee:** 100% local CPU inference via lightweight vectorized NumPy / scikit-learn coefficients. Sub-millisecond latency; zero external network calls.

### 3.2 ID-Masked Training & Evaluation Constraint (Anti-Leakage)
To prevent the model from trivial memorization of CVE strings, training data is strictly partitioned:
1. **ID-bearing queries:** Routed to Layer 1. Excluded entirely from Layer 2 training and evaluation.
2. **ID-masked queries:** The query text contains only vulnerability symptoms, software name, vendor, affected versions, CWE, or exploitation mechanism (e.g., *"Remote code execution in Apache Log4j2 JNDI via LDAP lookup"* with `"CVE-2021-44228"` stripped).
3. **Feature Isolation:** Layer 2 features must **never** inspect or derive information from `doc_id` or explicit identifier equality. The model learns to score semantic and structural alignment, not identity.

### 3.3 Behavioral Slice: Option B Heuristic Protocol
- **Constraint:** Phase 0 proved that the 362K corpus contains zero IPs and zero hashes, and existing behavioral relevance judgments are $< 45$ pairs.
- **Protocol:** Per user specification, **no synthetic behavioral labels will be fabricated for model training**.
- For behavioral queries (queries containing IOCs and/or TTPs without primary CVE match):
  - Handled via **M1 (Presence-Renormalized Weights)**.
  - Runtime output sets `calibrated = False`.
  - `tier_basis`: `"UNCALIBRATED_BEHAVIORAL_HEURISTIC"`.
  - Documented in code and API docs: *"heuristic, not validated: no labeled data and the corpus has no IPs/hashes"*.
  - `golden_dataset.json` is retained solely as a regression test suite, never as training data.

---

## 4. Feature Schema (Version 1.0.0)

Feature extraction is centralized in a shared `FeatureExtractor` module to guarantee **train-serve parity**.

| Feature Key | Type | Description | Handling of Absent Observables |
|---|---|---|---|
| `has_cve` | binary (0/1) | Whether query contains any CVE mention | Indicator flag |
| `has_ioc` | binary (0/1) | Whether query contains any IP/hash IOC | Indicator flag |
| `has_ttp` | binary (0/1) | Whether query contains any MITRE technique/actor | Indicator flag |
| `cve_coverage` | float [0, 1] | $\|Q_{cve} \cap D_{cve}\| / \|Q_{cve}\|$ | If `has_cve == 0`, set to `0.0` (neutralized by interaction) |
| `ioc_coverage` | float [0, 1] | $\|Q_{ioc} \cap D_{ioc}\| / \|Q_{ioc}\|$ | If `has_ioc == 0`, set to `0.0` (neutralized by interaction) |
| `ttp_coverage` | float [0, 1] | $\|Q_{ttp} \cap D_{ttp}\| / \|Q_{ttp}\|$ | If `has_ttp == 0`, set to `0.0` (neutralized by interaction) |
| `reranker_score` | float [0, 1] | Cross-encoder logit converted via sigmoid: $\sigma(s)$ | Continuous semantic alignment score |
| `bm25_norm_score` | float [0, 1] | Okapi BM25 score normalized by query max | Continuous lexical alignment score |
| `inter_cve_cov` | float [0, 1] | `has_cve * cve_coverage` | Interaction term |
| `inter_ioc_cov` | float [0, 1] | `has_ioc * ioc_coverage` | Interaction term |
| `inter_ttp_cov` | float [0, 1] | `has_ttp * ttp_coverage` | Interaction term |
| `inter_reranker` | float [0, 1] | `has_cve * reranker_score` | Context interaction |

> [!IMPORTANT]
> **No-Penalty Principle for Absent Observables:**
> When an observable type is absent from the query (`has_ioc == 0`), the model receives explicit zero indicators for both the presence flag and the interaction terms. The logistic regression bias and channel weights are fitted such that absent channels do not decrease the predicted probability $P(\text{relevant})$.

---

## 5. Dataset Generation & Label Provenance (CVE Slice)

### 5.1 Structural Sampling from 362K Corpus
1. **Positive Pairs ($y = 1$):**
   - Sample $N \ge 800$ CVEs uniformly distributed across high, medium, and low severity, and across years 2017–2026.
   - For each CVE, take the NVD/CISA document text, strip the explicit CVE token, and construct realistic ID-masked queries.
   - Pair with the primary corpus record: `(masked_query, chunk_id, label=1)`.
   - `source = "structural"`.

2. **Hard Negative Pairs ($y = 0$):**
   - For each query, mine negatives using 3 distinct strategies:
     - **Adjacent CVE Negatives:** Retrieve chunks sharing adjacent IDs (e.g. `CVE-2021-44227` or `CVE-2021-44229` for `CVE-2021-44228`).
     - **Same Product / CWE Negatives:** Retrieve chunks from the same vendor/product/CWE retrieved by BM25/BGE-M3 that refer to a different CVE.
     - **Cross-CVE EPSS/KEV Negatives:** Chunks containing EPSS/KEV metadata for different vulnerabilities.
   - Pair: `(masked_query, distractor_chunk_id, label=0)`.
   - `source = "structural"`.

3. **Data Quality Review & Error Rate:**
   - Draw a random sample of 100 generated pairs.
   - Manually audit pairs for label correctness.
   - Record and report the label error rate (target: $< 2.0\%$).

### 5.2 Group-Wise Splitting & Sealed Holdout
- **Group Key:** Primary CVE ID.
- **Sealed Test Set:** 20% of CVE groups are permanently held out in `data/labels/cve_masked_test_sealed.json`. This set is never touched during feature exploration, CV fitting, or threshold tuning.
- **Cross-Validation Split:** 5-fold `GroupKFold` on the remaining 80% of CVE groups. All pairs originating from the same CVE stay in the same fold.

---

## 6. Model Selection Protocol & Quality Gates

### 6.1 Pre-Registered Candidates
The following models are evaluated strictly out-of-fold across the 5 GroupKFold splits:
- **M0:** Baseline static weights `(0.40, 0.20, 0.20, 0.20)` (unmodified).
- **M1:** Presence-renormalized static weights (renormalize weights dynamically over present observables).
- **M2:** Global L2-regularized Logistic Regression with presence flags and interaction features.
- **M3:** Profile-specific Logistic Regression (only if $> 300$ samples exist per profile; otherwise skipped).

### 6.2 Pre-Registered Selection Rule
1. **Primary Metric:** Out-of-fold Log Loss (Cross-Entropy).
2. **Tie-Breaking:** If two models are within 1 standard error of log loss, select the simpler model.
3. **Calibration Metrics:** Report Brier Score and Expected Calibration Error (ECE, 10 equal-frequency bins).
4. **Post-Hoc Calibration:** Evaluate Platt scaling (sigmoid) and Isotonic regression fitted inside cross-validation loops. Adopt calibrator only if it reduces Brier score and ECE without degrading Log Loss.

### 6.3 Retrieval & Precision Quality Gates
To be eligible for deployment, the subsystem must satisfy all pre-registered gates:
- **NDCG@10:** $\ge 0.85$
- **MRR@10:** $\ge 0.80$
- **Macro F1:** $\ge 0.80$ across the 5 tiers
- **P95 Latency:** $\le 200$ ms
- **Task 1 Precision (CVE Slice):** Expected precision $\ge 90\%$ on the ID-masked sealed test set, reported with 95% bootstrap confidence intervals (grouped by CVE).

---

## 7. Tier Bands & Probability Calibration

### 7.1 Tier Mapping Definition
The 5 standard tier names are mapped to calibrated probability bands:

| Confidence Tier | Calibrated Probability $P(\text{rel} \mid q, d)$ | Operational Meaning |
|---|---|---|
| **`EXACT`** | Layer 1 Deterministic Match | Exact primary identifier verified. Highest conviction. |
| **`STRONG`** | $P \in [0.65, 1.00]$ | High statistical confidence. Automated enrichment/triage safe. |
| **`PARTIAL`** | $P \in [0.45, 0.65)$ | Moderate relevance. Software/symptom match; requires analyst review. |
| **`WEAK`** | $P \in [0.10, 0.45)$ | Low semantic overlap or ambiguous distractor. Display with caution. |
| **`UNSUPPORTED`**| $P < 0.10$ | Sub-threshold or benign noise. Filtered or unverified. |

### 7.2 Empirical Calibration Rule
- Phase 4 must report empirical precision for every probability band on out-of-fold predictions and the sealed test set.
- If a band's empirical precision falls outside its stated range (e.g. `STRONG` achieves $< 65\%$ precision), the orchestrator must halt, report the divergence, and submit proposed threshold adjustments for explicit user approval before making any changes.

---

## 8. Runtime Interface & Degraded Mode

### 8.1 API Resolution Schema
The scoring subsystem exposes `resolve_confidence(...)` returning a strongly-typed schema:

```python
@dataclass(frozen=True)
class ConfidenceResolution:
    match_type: str       # EXACT_ID | EXACT_HASH | LEARNED_MODEL | HEURISTIC_PRESENCE
    probability: float    # Calibrated probability in [0.0, 1.0]
    tier: str             # EXACT | STRONG | PARTIAL | WEAK | UNSUPPORTED
    tier_basis: str       # DETERMINISTIC_L1 | CALIBRATED_LOGISTIC_REGRESSION | UNCALIBRATED_BEHAVIORAL_HEURISTIC
    features: dict[str, float]
    feature_contributions: dict[str, float]
    model_version: str
    calibrated: bool
    degraded: bool
```

### 8.2 Safe Degradation Protocol
If the trained model artifact is missing, unreadable, or the cross-encoder reranker is unavailable:
1. `degraded` is set to `True`.
2. Confidence tier is capped at `STRONG` (never `EXACT`).
3. An explicit warning log is emitted.
4. The system falls back to presence-renormalized heuristic M1 with `calibrated = False`.
5. Silent fallback to old static weights is strictly prohibited.

---

## 9. Downstream System Alignment

### 9.1 Pipeline Override Removal
- **Action:** Delete the override at `threat_retrieval_engine/api/pipeline.py:432-433`:
  ```python
  # REMOVED:
  # elif cve_sim == 1.0:
  #     composite = max(composite, 0.400)
  ```
- **Replacement:** Call `resolve_confidence()` directly from the pipeline scoring stage.

### 9.2 Investigator Agent Impact Verification
- `threat_retrieval_engine/llm/workflows/investigator.py:90-135` branches on `confidence_tier`.
- In Phase 4, the investigator workflow will be run on the 4 CVE-only benchmark queries (`bench_04`, `bench_05`, `bench_06`, `bench_07`) to record and report how downstream triage decisions shift from "Escalate due to WEAK confidence" to automated enrichment.

---

## 10. Open Decisions & Pre-Implementation Approvals

The following design decisions are documented and frozen for Phase 2:

1. **Behavioral Scope:** Option B is frozen. M1 presence-renormalized weights will serve behavioral queries with `calibrated=False`. No synthetic behavioral labels will be used for model training.
2. **Layer 1 Fallback Dropped:** Confirmed that 100% of corpus records have a valid `doc_id` CVE prefix. The `entities_json['cves'][0]` fallback is officially dropped.
3. **ID-Masked Training Isolation:** Confirmed that all Layer 2 training queries must have their CVE ID stripped and features must not inspect `doc_id`.
4. **Offline Reranking for Labeling:** Candidate generation for training data mining will run with local BGE-M3 and BM25 offline, without triggering network PoC lookups.

---

*Contract Approved and Frozen. Proceed to Phase 2 Parallel Execution.*
