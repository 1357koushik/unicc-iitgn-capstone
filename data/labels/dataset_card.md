# Dataset Card: CVE ID-Masked Query-Document Calibration Dataset

## 1. Dataset Summary
- **Dataset Name:** `cve_masked_calibration_pairs`
- **Version:** 1.0.0
- **Purpose:** Training, cross-validation, and sealed evaluation of Layer 2 confidence calibration models (Logistic Regression, Platt scaling, Isotonic regression) in the Threat Retrieval & Matching Subsystem (TRMS).
- **Provenance Statement:** `source = "structural"`. Ground truth pairs are derived deterministically from authoritative NIST NVD and CISA KEV records indexed in the 362K corpus store (`data/sqlite/corpus_store.db`).
- **Target Branch:** `fix/learned-calibrated-confidence`

---

## 2. Dataset Statistics & Splits

### 2.1 Overview Metrics
| Metric | Value |
|---|---|
| **Total Query-Document Pairs** | **3,200** |
| **Unique CVE Groups** | **800** |
| **Positives ($y = 1$)** | **800** (25.0%) |
| **Hard Negatives ($y = 0$)** | **2,400** (75.0%) |
| **Positive : Negative Ratio** | **1 : 3** |
| **Year Coverage** | 2017 – 2026 (10 years) |
| **Primary Sources** | CISA KEV (300 CVEs), NIST NVD (500 CVEs) |

### 2.2 Split Breakdown
| Split | CVE Groups | Total Pairs | Positives ($y=1$) | Negatives ($y=0$) | Percentage |
|---|---|---|---|---|---|
| **Train Folds (`cve_masked_train_folds.json`)** | 640 | 2,560 | 640 | 1,920 | 80.0% |
| **Sealed Test (`cve_masked_test_sealed.json`)** | 160 | 640 | 160 | 480 | 20.0% |

### 2.3 5-Fold Cross-Validation Distribution (GroupKFold)
All CVE groups are assigned strictly to a single fold, eliminating cross-fold leakage:
- **Fold 0:** 512 pairs (128 unique CVE groups, 128 positive / 384 negative)
- **Fold 1:** 512 pairs (128 unique CVE groups, 128 positive / 384 negative)
- **Fold 2:** 512 pairs (128 unique CVE groups, 128 positive / 384 negative)
- **Fold 3:** 512 pairs (128 unique CVE groups, 128 positive / 384 negative)
- **Fold 4:** 512 pairs (128 unique CVE groups, 128 positive / 384 negative)

---

## 3. Negative Sampling Composition
Every CVE query is paired with exactly 3 distinct hard negatives:
| Negative Strategy | Count | Description |
|---|---|---|
| **`adjacent_id`** | 800 | Chunks with contiguous/adjacent CVE numerical IDs (e.g. `CVE-2021-44227` for `CVE-2021-44228`). |
| **`same_product_cwe`** | 800 | Chunks retrieved as top distractors by Okapi BM25 sharing software vendor, product, or CWE taxonomy for a different CVE. |
| **`cross_cve_epss_kev`** | 800 | Chunks containing CISA KEV exploitation notices or EPSS percentiles for an entirely different vulnerability. |

---

## 4. Anti-Leakage Protocol & Query Representations
Each pair contains two representations of the query:
1. **`query_id_bearing`** (e.g., `CVE-2021-44228 remote code execution in Log4j2 JNDI`):
   - Exclusively reserved for Layer 1 exact identifier evaluation.
   - **Strictly excluded** from Layer 2 model fitting.
2. **`query_masked`** (e.g., `remote code execution in Log4j2 JNDI via LDAP lookup`):
   - All explicit CVE tokens (`r"\bCVE-\d{4}-\d{4,7}\b"`) are systematically stripped.
   - Layer 2 trains and evaluates exclusively on `query_masked` to prevent trivial identifier memorization.

---

## 5. Data Quality & Audit Results
- **Random Sample Audit Size:** 100 pairs randomly sampled across the dataset.
- **Audit Findings:**
  - Audited Errors: **0**
  - Empirical Error Rate: **0.0%** (Quality Gate: $< 2.0\%$)
  - Quality Gate Status: **PASSED**
- Audit details recorded in `data/labels/label_audit_100.json`.

---

## 6. Known Biases & Corpus Limitations
1. **NVD Dominance:** The underlying corpus contains 356,382 NVD records vs. 1,593 CISA KEV records. Sampling was explicitly balanced across both sources (300 CISA, 500 NVD) to counter this skew.
2. **Year Distribution:** Vulnerability volume in the corpus expands substantially in recent years (2024-2026). Sampling enforces an exact uniform quota of 80 CVEs per year from 2017 to 2026.
3. **Absence of Host Observables (IP/Hash):** The corpus contains zero IP addresses and zero file hashes. Per Option B protocol, behavioral queries are served by uncalibrated heuristic M1; no synthetic behavioral labels were fabricated.
