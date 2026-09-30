# Benchmark & Evaluation Guide

This document describes the evaluation framework, metrics formulas, dataset composition, and reproduction steps for the Threat Retrieval & Matching Subsystem.

---

## 📐 Evaluation Metrics

### 1. Retrieval Quality
- **$\text{Hit}@K$**:
  $$\text{Hit}@K = \begin{cases} 1 & \text{if } \exists d \in \mathcal{D}_{\text{relevant}} \text{ s.t. } \text{rank}(d) \le K \\ 0 & \text{otherwise} \end{cases}$$
- **$\text{MRR}@K$ (Mean Reciprocal Rank)**:
  $$\text{MRR}@K = \frac{1}{|\mathcal{Q}|} \sum_{q \in \mathcal{Q}} \frac{1}{\min \{ \text{rank}(d) : d \in \mathcal{D}_{\text{relevant}}^{(q)} \le K \}}$$
- **$\text{NDCG}@K$ (Normalized Discounted Cumulative Gain)**:
  $$\text{DCG}@K = \sum_{i=1}^K \frac{2^{\text{rel}_i} - 1}{\log_2(i + 1)}, \quad \text{NDCG}@K = \frac{\text{DCG}@K}{\text{IDCG}@K}$$

### 2. Classification Quality
- **Macro F1**:
  $$\text{Macro F1} = \frac{1}{|\mathcal{C}|} \sum_{c \in \mathcal{C}} \text{F1}_c, \quad \mathcal{C} = \{\text{EXACT}, \text{STRONG}, \text{PARTIAL}, \text{WEAK}, \text{UNSUPPORTED}\}$$

### 3. Latency SLA
- **P95 Latency**: 95th percentile total response time across all benchmark queries ($\le 200\text{ ms}$).

---

## 🎯 Quality Gates

| Quality Gate | Requirement | Production Status |
| :--- | :--- | :--- |
| **Retrieval Quality Gate** | $\text{NDCG}@10 \ge 0.85$ and $\text{MRR}@10 \ge 0.80$ | Active |
| **Latency SLA Gate** | $\text{P95} \le 200.0\text{ ms}$ | Active |
| **Classification Gate** | Macro F1 across 5 tiers | Informational |

---

## 🏃 Reproduction Commands

### 1. Standard Benchmark Run
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
