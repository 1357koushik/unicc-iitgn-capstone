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

Model candidates are evaluated strictly out-of-fold across 5-fold `GroupKFold` splits (grouped by primary CVE ID) on the ID-masked training set.

> [!NOTE]
> The table below is a pre-registered placeholder to be populated during Phase 4 model training and cross-validation execution.

| Model ID | Architecture / Description | OOF Log Loss | OOF Brier Score | OOF ECE (10 bins) | Macro F1 | Selection Decision |
|:---:|---|:---:|:---:|:---:|:---:|:---:|
| **M0** | Baseline Static Weights `(0.40, 0.20, 0.20, 0.20)` | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | Baseline Reference |
| **M1** | Presence-Renormalized Static Weights | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | Candidate (Heuristic Fallback) |
| **M2** | Global Calibrated Logistic Regression (12 features) | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | Primary Candidate |
| **M3** | Profile-Specific Logistic Regression | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | *[Pending Ph4]* | Evaluated if $N > 300$/profile |

**Pre-Registered Selection Rule:**
1. Primary criterion: minimum out-of-fold Log Loss.
2. Tie-breaking: within 1 standard error, select the simpler model (M2 over M3).
3. Post-hoc calibration (Platt scaling / Isotonic) adopted only if it strictly reduces Brier score and ECE without degrading Log Loss.

---

### 3. Sealed Holdout Test Precision (Phase 4 Verification)

Evaluation on the permanently held-out sealed test set (`data/labels/cve_masked_test_sealed.json`, $20\%$ of distinct CVE groups).

> [!IMPORTANT]
> **Task 1 Target:** Expected precision $\ge 90\%$ on the ID-masked sealed test set, reported with 95% bootstrap confidence intervals (grouped by CVE). Layer 1 matches are certified true by construction and reported separately; they do not substitute for Layer 2 test evaluation.

| Confidence Tier | Nominal Probability Band | Sealed Test Precision (95% CI) | Support ($N$) | Gate Status ($\ge 90\%$ for Task 1) |
|:---:|:---:|:---:|:---:|:---:|
| **`EXACT`** | Layer 1 Deterministic Match | *100.0% (True by construction)* | *[Pending Ph4]* | Deterministic L1 |
| **`STRONG`** | $P \in [0.65, 1.00]$ | *[Pending Ph4]* | *[Pending Ph4]* | Target $\ge 90\%$ (Task 1) |
| **`PARTIAL`** | $P \in [0.45, 0.65)$ | *[Pending Ph4]* | *[Pending Ph4]* | Expected $\in [45\%, 65\%)$ |
| **`WEAK`** | $P \in [0.10, 0.45)$ | *[Pending Ph4]* | *[Pending Ph4]* | Expected $\in [10\%, 45\%)$ |
| **`UNSUPPORTED`** | $P < 0.10$ | *[Pending Ph4]* | *[Pending Ph4]* | Expected $< 10\%$ |

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
