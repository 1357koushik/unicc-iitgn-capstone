# Benchmark & Evaluation Guide

This document describes the evaluation framework, metrics formulas, dataset composition, historical failure analyses, and reproduction steps for the Threat Retrieval & Matching Subsystem (TRMS).

---

## 📐 Evaluation Metrics

### 1. Retrieval Quality
- **$\text{Hit}@K$**:
  $$\text{Hit}@K = \begin{cases} 1 & \text{if } \exists d \in \mathcal{D}_{\text{relevant}} \text{ s.t. } \text{rank}(d) \le K \\ 0 & \text{otherwise} \end{cases}$$
- **$\text{MRR}@K$ (Mean Reciprocal Rank)**:
  $$\text{MRR}@K = \frac{1}{|\mathcal{Q}|} \sum_{q \in \mathcal{Q}} \frac{1}{\min \{ \text{rank}(d) : d \in \mathcal{D}_{\text{relevant}}^{(q)} \le K \}}$$
- **$\text{NDCG}@K$ (Normalized Discounted Cumulative Gain)**:
  $$\text{DCG}@K = \sum_{i=1}^K \frac{2^{\text{rel}_i} - 1}{\log_2(i + 1)}, \quad \text{NDCG}@K = \frac{\text{DCG}@K}{\text{IDCG}@K}$$

### 2. Classification & Calibration Quality
- **Macro F1**:
  $$\text{Macro F1} = \frac{1}{|\mathcal{C}|} \sum_{c \in \mathcal{C}} \text{F1}_c, \quad \mathcal{C} = \{\text{EXACT}, \text{STRONG}, \text{PARTIAL}, \text{WEAK}, \text{UNSUPPORTED}\}$$
- **Log Loss (Cross-Entropy)**:
  $$\text{Log Loss} = -\frac{1}{N} \sum_{i=1}^N \left[ y_i \log \hat{p}_i + (1 - y_i) \log (1 - \hat{p}_i) \right]$$
- **Brier Score**:
  $$\text{Brier} = \frac{1}{N} \sum_{i=1}^N (\hat{p}_i - y_i)^2$$
- **Expected Calibration Error (ECE)**:
  $$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$
  where predictions are partitioned into $M = 10$ equal-frequency probability bins $B_m$.

### 3. Latency SLA
- **P95 Latency**: 95th percentile total response time across all benchmark queries ($\le 200\text{ ms}$).

---

## 🎯 Quality Gates

| Quality Gate | Requirement | Production Status |
| :--- | :--- | :--- |
| **Retrieval Quality Gate** | $\text{NDCG}@10 \ge 0.85$ and $\text{MRR}@10 \ge 0.80$ | Active |
| **Latency SLA Gate** | $\text{P95} \le 200.0\text{ ms}$ | Active |
| **Classification Gate** | Macro F1 across 5 tiers $\ge 0.80$ | Active |
| **Task 1 Precision Gate** | Expected Precision $\ge 90\%$ on ID-masked CVE sealed test set | Active (Phase 4 Verification) |
| **Probability Calibration Gate** | Out-of-fold Log Loss minimization & empirical band monotonicity | Active (Phase 4 Verification) |

---

## 🔬 Confidence Scoring & Precision Calibration Benchmark

### 1. Historical Root Cause: Why CVE Matches Clamped to 0.400 (WEAK)

During baseline audits, evaluation of Task 1 (*Vulnerability Enrichment - CVE, Tier A, expected precision $\ge 90\%$*) failed with evaluator feedback:
> *"Confidence Scoring method is not correct."*

As documented in [`baseline_before.json`](file:///d:/Project%20Course/unicc-iitgn-capstone/threat_retrieval_engine/benchmarks/baseline_before.json), baseline Macro F1 was **0.2788**, with exact CVE queries such as `bench_01_eternalblue_exact` and `bench_04_log4shell_weak` misclassified into `WEAK`.

The failure was traced to three interacting factors:
1. **Corpus Reality vs. Weight Formula:** The 362,301-record corpus in `data/sqlite/corpus_store.db` comprises vulnerability advisories containing **0 IP addresses and 0 file hashes**. The legacy formula in [`calculate_composite_score`](file:///d:/Project%20Course/unicc-iitgn-capstone/threat_retrieval_engine/api/helpers.py#L91-L116):
   $$\text{Composite} = 0.40 \cdot S_{\text{IOC}} + 0.20 \cdot S_{\text{TTP}} + 0.20 \cdot S_{\text{Semantic}} + 0.20 \cdot S_{\text{CVE}}$$
   assigned $0.40$ weight to IOCs. Because vulnerability records have no IOCs, $S_{\text{IOC}} = 0$, immediately destroying $40\%$ of the attainable score. For queries without TTPs, another $20\%$ was eliminated. A perfect CVE match with strong semantic similarity was capped at:
   $$0.40(0) + 0.20(0) + 0.20(0.90) + 0.20(1.00) = 0.380$$
2. **The 0.400 Ad-Hoc Clamp:** In [`pipeline.py:432-433`](file:///d:/Project%20Course/unicc-iitgn-capstone/threat_retrieval_engine/api/pipeline.py#L432-L433), an override attempted to lift pure CVE matches:
   ```python
   elif cve_sim == 1.0:
       composite = max(composite, 0.400)
   ```
3. **Threshold Boundary Defeat:** The threshold for [`classify_confidence_tier`](file:///d:/Project%20Course/unicc-iitgn-capstone/threat_retrieval_engine/api/helpers.py#L118-L140) required `0.45` to transition from `WEAK` to `PARTIAL`, and `0.85` for `EXACT`. Because $0.400 < 0.45$, the override permanently clamped every pure CVE match into **`WEAK`**.

This structural failure is solved by the [Two-Layer Confidence Architecture](file:///d:/Project%20Course/unicc-iitgn-capstone/docs/dev/confidence_scoring.md): Layer 1 handles exact identifier equality deterministically, while Layer 2 learns a calibrated logistic regression on ID-masked features where absent observables are never penalized.

---

### 2. Out-of-Fold Model Comparison (Phase 4 Candidate Selection)

Model candidates are evaluated strictly out-of-fold across 5-fold `GroupKFold` splits (grouped by primary CVE ID) on the ID-masked training set (`data/labels/cve_masked_train_folds.json`, 2,560 pairs across 640 CVE groups).

#### Why M0 and M1 Yield Identical Log Loss (8.6347 +/- 0.0000)
On the ID-masked slice, queries contain zero IOCs (`has_ioc = 0`), zero TTPs (`has_ttp = 0`), and zero CVE IDs (`has_cve = 0`). The target documents also contain no IOCs/TTPs. In the offline mining split without dynamic cross-encoder scoring, `reranker_score = 0.0`.
- **M0 (Static Weights):** $\text{Composite} = 0.40(0) + 0.20(0) + 0.20(0) + 0.20(0) = 0.0$.
- **M1 (Presence-Renormalized):** Normalizing over present observables where none exist defaults to reranker score alone: $1.0 \times \text{reranker\_score} = 0.0$.
- Both M0 and M1 output predicted probability $\hat{p}_i = 0.0$ for all samples. Clamped to numerical floor $\epsilon = 10^{-15}$, Log Loss $= 0.25 \times (-\ln 10^{-15}) = 0.25 \times 34.5388 = \mathbf{8.6347}$. Every fold receives identical predictions, resulting in standard error $\mathbf{0.0000}$.

#### Model Comparison Table (Out-of-Fold 5-Fold GroupKFold)

| Model ID | Architecture / Description | OOF Log Loss | OOF Brier Score | OOF ECE (10 bins) | OOF AUC-ROC | Selection Decision |
|:---:|---|:---:|:---:|:---:|:---:|:---:|
| **M0** | Baseline Static Weights `(0.40, 0.20, 0.20, 0.20)` | `8.6347 +/- 0.0000` | `0.2500` | `0.25000` | `0.5000` | Baseline Reference (Legacy) |
| **M1** | Presence-Renormalized Static Weights | `8.6347 +/- 0.0000` | `0.2500` | `0.25000` | `0.5000` | Option B Heuristic Fallback |
| **M2 (Raw)** | Global L2-Logistic Regression (12 features) | **`0.1512`** | **`0.0449`** | `0.05184` | **`0.9729`** | **WINNER (Selected Artifact)** |
| **M2 (Platt)** | CalibratedClassifierCV (method='sigmoid') | `0.1912` | `0.0601` | `0.04152` | `0.9710` | Rejected (higher Log Loss) |
| **M2 (Isotonic)** | CalibratedClassifierCV (method='isotonic') | `0.1925` | `0.0610` | `0.04301` | `0.9698` | Rejected (higher Log Loss) |
| **M3** | Profile-Specific Logistic Regression | `0.1512` | `0.0449` | `0.05184` | `0.9729` | Reduces to M2 (uniform masked profile) |
| **M4** | Platt-Calibrated Reranker Alone (`bge-reranker-v2-m3`) | `0.2414` | `0.0791` | **`0.05104`** | `0.9529` | Defeated by M2 across primary metrics |

**Selection Outcome:** **M2 strictly beats M4** on out-of-fold Log Loss ($0.1512$ vs $0.2414$), Brier Score ($0.0449$ vs $0.0791$), and AUC-ROC ($0.9729$ vs $0.9529$). Per the pre-registered selection rule, M2 was exported to [`threat_retrieval_engine/models/confidence_model.json`](file:///d:/Project%20Course/unicc-iitgn-capstone/threat_retrieval_engine/models/confidence_model.json).

---

### 3. Sealed Holdout Test Precision & Retrieval Evaluation

Evaluation on the permanently held-out sealed test set (`data/labels/cve_masked_test_sealed.json`, 160 distinct CVE groups, 640 pairs: 160 Positives, 480 Negatives, positive rate = $25.0\%$).

#### 3.1 Pairwise Tier Band Distribution (Sealed Test)

| Confidence Tier | Nominal Probability Band | Total Pairs | True Positives | Hard Negatives | Empirical Precision |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **`EXACT`** | Layer 1 Deterministic Match ($P = 1.0$) | N/A | N/A | N/A | Excluded from L2 (Layer 1 rule) |
| **`STRONG`** | $P \in [0.65, 1.00]$ | 200 | 160 | 40 | **80.00%** (160 / 200) |
| **`PARTIAL`** | $P \in [0.45, 0.65)$ | 3 | 0 | 3 | **0.00%** (0 / 3) |
| **`WEAK`** | $P \in [0.10, 0.45)$ | 21 | 0 | 21 | **0.00%** (0 / 21) |
| **`UNSUPPORTED`** | $P < 0.10$ | 416 | 0 | 416 | **0.00%** (0 / 416) |

> [!WARNING]
> **Correction to Previous Draft:** The earlier statement claiming *"0 negatives misclassified"* was inaccurate. In the pairwise candidate pool, **40 hard negative distractor pairs** (adjacent CVE IDs and same-product advisories with high BM25 overlap) scored $\ge 0.65$ and were assigned to the `STRONG` band. 416 negative distractors were rejected into `UNSUPPORTED`, 21 into `WEAK`, and 3 into `PARTIAL`.

#### 3.2 Sealed Test Head-to-Head: M2 vs M4

| Metric | M2 (Selected Artifact) | M4 (Platt-Calibrated Reranker Alone) | Comparison Result |
|---|:---:|:---:|:---:|
| **Log Loss** | **`0.1747`** | `0.2530` | **M2 wins** (relative reduction 30.9%) |
| **Brier Score** | **`0.0544`** | `0.0829` | **M2 wins** (relative reduction 34.4%) |
| **Expected Calibration Error (ECE)** | **`0.03142`** | `0.05198` | **M2 wins** (relative reduction 39.6%) |
| **AUC-ROC** | **`0.9583`** | `0.9474` | **M2 wins** (+0.0109) |

**Conclusion:** M2 strictly outperforms M4 across all four evaluation metrics on the sealed holdout set.

#### 3.3 Full 362K Corpus Retrieval Evaluation (160 Test CVEs)

To evaluate real-world retrieval, all 160 sealed test CVE queries were run against the **complete 362,301-record SQLite corpus** (`data/sqlite/corpus_store.db`) under two query formulations:
1. **Original ID-Masked:** Verbatim NVD description sentence snippet with CVE identifier stripped.
2. **Harder Paraphrased:** Product / software name + vulnerability type only, with zero copied sentences from NVD description text.

| Metric | Original ID-Masked Queries | Harder Paraphrased Queries |
|---|:---:|:---:|
| **Corpus Size** | 362,301 records | 362,301 records |
| **Test Queries Evaluated** | 160 | 160 |
| **Deciding Layer** | **Layer 2 (160/160, 100%)** | **Layer 2 (160/160, 100%)** |
| **Layer 1 Triggered** | 0 (0.0%) | 0 (0.0%) |
| **Top-1 Precision** | **79.38%** (127 / 160) | **16.88%** (27 / 160) |
| **Exact Binomial (Clopper-Pearson) 95% CI** | **`[72.27%, 85.36%]`** | **`[11.43%, 23.59%]`** |
| **MRR@10** | **0.8656** | **0.2258** |
| **Rank 1 Count** | 127 | 27 |
| **Rank 2–5 Count** | 24 | 18 |
| **Rank 6–10 Count** | 5 | 7 |
| **Rank >10 or Missed Count** | 4 | 108 |

*Note:* Layer 1 triggered 0 times across both sets, confirming zero identifier leakage from the query into the deterministic fast-path. The previously reported bootstrap interval `[100%, 100%]` (derived from the isolated 4-pair candidate pool) is replaced by the exact Clopper-Pearson intervals above.

#### 3.4 Calibration Prior Shift Analysis

The labeled training and test sets have an artificial positive:negative ratio of $1:3$ ($25.0\%$ positive rate). In operational triage, the true prevalence of relevant records among retrieved candidates is much lower. We evaluate calibration under log-odds shifts:
$$\Delta_{\text{odds}} = \ln\left(\frac{p_{\text{target}}}{1 - p_{\text{target}}}\right) - \ln\left(\frac{0.25}{0.75}\right)$$

- **1:20 Prior ($p_{\text{target}} \approx 4.76\%$, $\Delta_{\text{odds}} = -1.8971$):**
  - `STRONG [0.65, 1.00]`: 0 pairs
  - `PARTIAL [0.45, 0.65)`: 0 pairs
  - `WEAK [0.10, 0.45)`: 204 pairs (160 Positives, 44 Negatives, empirical precision = **78.43%**)
  - `UNSUPPORTED [< 0.10)`: 436 pairs (436 Negatives, empirical precision = **0.00%**)
  - *Finding:* Distractor rejection remains robust (436 of 480 negatives correctly placed in `UNSUPPORTED`), but probabilities compress into `WEAK`.
- **1:100 Prior ($p_{\text{target}} \approx 0.99\%$, $\Delta_{\text{odds}} = -3.5066$):**
  - All 640 pairs collapse into `UNSUPPORTED` ($P < 0.10$).
  - *Finding:* At $1:100$ prevalence, raw scores require prior-specific re-thresholding to avoid universal rejection.

---

### 4. Integration Benchmark Quality Gates (Before vs After)

Evaluated on [`benchmark_dataset.json`](file:///d:/Project%20Course/unicc-iitgn-capstone/threat_retrieval_engine/benchmarks/benchmark_dataset.json) (10 queries):

| Quality Gate | Requirement | Baseline Before | Calibrated After | Status |
|---|:---:|:---:|:---:|:---:|
| **NDCG@10** | $\ge 0.85$ | 0.7500 | 0.7500 | **FAIL** |
| **MRR@10** | $\ge 0.80$ | 0.7500 | 0.7500 | **FAIL** |
| **Hit@3** | Reference | 0.7500 | 0.7500 | Reference |
| **Macro F1** | $\ge 0.80$ | 0.2788 | 0.2286 | **FAIL** |
| **P95 Latency** | $\le 200.0\text{ ms}$ | 74,027.76 ms | 75,444.64 ms | **FAIL** (cold process) |

#### Confusion Matrix (Rows = Expected Tier, Columns = Predicted `[EXACT, STRONG, PARTIAL, WEAK, UNSUPPORTED]`)

**Baseline Before:**
```text
                  EXACT  STRONG  PARTIAL  WEAK  UNSUPPORTED
EXACT                 0       0        0     1            0
STRONG                0       0        0     0            1
PARTIAL               0       0        0     1            0
WEAK                  0       0        0     4            0
UNSUPPORTED           0       0        0     1            2
```

**Calibrated After:**
```text
                  EXACT  STRONG  PARTIAL  WEAK  UNSUPPORTED
EXACT                 1       0        0     0            0
STRONG                0       0        0     0            1
PARTIAL               1       0        0     0            0
WEAK                  4       0        0     0            0
UNSUPPORTED           0       0        0     0            3
```

#### Benchmark Dataset Status & Independent Justifications for `bench_03..07`
- **Was `benchmark_dataset.json` modified?** **NO.** Verification via git confirms zero commits or edits to `benchmark_dataset.json` since commit `48f2edf` (Sep 30, 2026).
- **Why Macro F1 dropped from 0.2788 to 0.2286:**
  Before the fix, the model predicted `WEAK` for almost everything, accidentally matching the 4 artificially depressed legacy `WEAK` labels. When exact CVE queries were corrected to output `EXACT`, they diverged from the legacy `expected_tier: "WEAK"` labels, lowering Macro F1 against the uncorrected file.
- **Independent Domain Justification:**
  - `bench_04_log4shell_weak` (`CVE-2021-44228`): Query explicitly requests Log4Shell advisory. The retrieved document is primary record `CVE-2021-44228`. In operational security, an exact primary identifier query expects `EXACT`. The legacy label `WEAK` was set artificially to accommodate the 0.400 static scoring bug.
  - `bench_05_proxylogon_weak` (`CVE-2021-26855`): Exact query for ProxyLogon; target is `CVE-2021-26855_KEV`. Operational expected tier is `EXACT`.
  - `bench_06_zerologon_weak` (`CVE-2020-1472`): Exact query for ZeroLogon; target is `CVE-2020-1472`. Operational expected tier is `EXACT`.
  - `bench_07_winrar_weak` (`CVE-2023-38831`): Exact query for WinRAR; target is `CVE-2023-38831_KEV`. Operational expected tier is `EXACT`.
  - `bench_03_follina_partial` (`CVE-2022-30190`): Exact query for Follina MSDT; target is `CVE-2022-30190_EPSS`. Operational expected tier is `EXACT`.

#### Explanation of `bench_02_eternalblue_strong` Failure
`bench_02_eternalblue_strong` (query: *"Observed lateral movement from 198.51.100.24 using technique T1021.002"*) expects `STRONG` and receives `UNSUPPORTED` (score: `0.0068`).
- **Target document in benchmark:** Chunk ID `80d012b2da2575e69d44b66f29fc49ba` (CVE-2017-0144).
- **Root Cause:**
  1. Chunk `80d012b2da2575e69d44b66f29fc49ba` **does not exist** in `data/sqlite/corpus_store.db`.
  2. IP `198.51.100.24` exists in **0 records** across all 362K corpus entries.
  3. The query text contains no mention of "EternalBlue", "SMB", or "CVE-2017-0144".
  4. The engine retrieves unrelated record `CVE-2020-10549` with score $0.0068$, correctly placing it into `UNSUPPORTED`.
- **Classification:** **Confirmed retrieval failure** caused by the target document missing from the corpus and zero IP observables in the corpus.

---

---

## 🏃 Reproduction Commands

### 1. Standard Benchmark Run (Full Hybrid Pipeline)
```bash
python threat_retrieval_engine/benchmarks/evaluate.py
```
Or via the root shortcut:
```bash
python scripts/evaluate.py
```

### 2. Keyword (BM25) Fast Evaluation
```bash
python threat_retrieval_engine/benchmarks/evaluate.py --retrieval=bm25
```

### 3. Golden Dataset Evaluation
```bash
python threat_retrieval_engine/benchmarks/evaluate.py \
  --dataset=threat_retrieval_engine/benchmarks/golden_dataset.json \
  --output=threat_retrieval_engine/benchmarks/golden_results.json
```

### 4. Confidence Scoring & Calibration Evaluation (Phase 4)
```bash
python threat_retrieval_engine/benchmarks/evaluate_confidence.py \
  --test-set=data/labels/cve_masked_test_sealed.json \
  --model-artifact=threat_retrieval_engine/models/confidence_model.joblib \
  --output=threat_retrieval_engine/benchmarks/confidence_calibration_results.json
```
