# Threat Retrieval & Matching Benchmarks

This directory contains the automated benchmark suite, evaluation datasets, and metric computation for the Threat Retrieval & Matching Subsystem.

## 📊 Overview

The benchmark framework measures:
1. **Retrieval Quality**:
   - `Hit@3`: Binary recall of relevant threat intelligence records within top-3.
   - `MRR@10`: Mean Reciprocal Rank across the top-10 candidates.
   - `NDCG@10`: Normalized Discounted Cumulative Gain against ground-truth rankings.
2. **Classification Quality**:
   - `Macro F1`: Unweighted mean F1 score across all 5 confidence tiers (`EXACT`, `STRONG`, `PARTIAL`, `WEAK`, `UNSUPPORTED`).
   - Confusion Matrix & per-tier Precision / Recall / F1.
3. **Latency SLA Verification**:
   - P95 end-to-end response time target: `<= 200 ms`.

---

## 📁 Files

- `evaluate.py`: The evaluation execution script.
- `metrics.py`: Calculation functions for Hit@K, MRR@K, NDCG@K, Macro F1, Precision/Recall, and Confusion Matrix.
- `benchmark_dataset.json`: 10 calibrated CTI test scenarios covering exact IOCs, partial matches, weak signals, and benign unsupported queries.
- `golden_dataset.json`: Reference dataset with multi-label ground truth.
- `benchmark_results.json`: Latest structured evaluation output containing summary metrics, per-query traces, and quality gate statuses.

---

## 🚀 Running the Benchmarks

### 1. Default Benchmark Run
Run against the calibrated benchmark dataset:
```bash
python threat_retrieval_engine/benchmarks/evaluate.py
```
Or via the root runner:
```bash
python scripts/evaluate.py
```

### 2. Fast Keyword (BM25) Evaluation
To evaluate using Okapi BM25 without neural GPU requirements:
```bash
python threat_retrieval_engine/benchmarks/evaluate.py --retrieval=bm25
```

### 3. Custom Dataset / Output Path
```bash
python threat_retrieval_engine/benchmarks/evaluate.py \
  --dataset=threat_retrieval_engine/benchmarks/golden_dataset.json \
  --output=threat_retrieval_engine/benchmarks/golden_results.json
```

---

## 🎯 Quality Gates

| Gate | Target SLA | Metric |
| :--- | :--- | :--- |
| **Retrieval Gate** | `PASS` | `NDCG@10 >= 0.85` and `MRR@10 >= 0.80` |
| **Latency SLA Gate**| `PASS` | `P95 <= 200.0 ms` |
| **Classification Gate**| Informational | `Macro F1` across all 5 confidence tiers |
