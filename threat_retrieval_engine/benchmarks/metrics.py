"""
threat_retrieval_engine/benchmarks/metrics.py
=============================================
Core evaluation metrics for Information Retrieval and Classification:
  - Hit@K: Binary hit rate within top K retrieved documents
  - MRR@K: Mean Reciprocal Rank at cutoff K
  - NDCG@K: Normalized Discounted Cumulative Gain at cutoff K
  - Macro F1: Unweighted mean of F1 scores across all confidence classes
  - Confusion Matrix: Actual vs. Predicted category breakdown
  - Precision / Recall: Unranked set-based relevance metrics
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Sequence


def hit_at_k(actual: Sequence[str], predicted: Sequence[str], k: int) -> int:
    """Returns 1 if any actual document ID is in the top K predicted items, else 0."""
    if not actual or not predicted:
        return 0
    top_k = set(predicted[:k])
    for item in actual:
        if item in top_k:
            return 1
    return 0


def mrr_at_k(actual: Sequence[str], predicted: Sequence[str], k: int) -> float:
    """Calculates Reciprocal Rank at cutoff K for a single query."""
    if not actual or not predicted:
        return 0.0
    actual_set = set(actual)
    for i, item in enumerate(predicted[:k]):
        if item in actual_set:
            return 1.0 / (i + 1.0)
    return 0.0


def ndcg_at_k(actual: Sequence[str], predicted: Sequence[str], k: int) -> float:
    """
    Calculates Normalized Discounted Cumulative Gain at cutoff K.
    Uses binary relevance (1 if document is in actual set, 0 otherwise).
    """
    if not actual or not predicted:
        return 0.0

    actual_set = set(actual)
    seen: set[str] = set()
    dcg = 0.0
    for i, item in enumerate(predicted[:k]):
        if item in actual_set and item not in seen:
            dcg += 1.0 / math.log2(i + 2.0)
            seen.add(item)

    idcg = 0.0
    num_ideal = min(len(actual_set), k)
    for i in range(num_ideal):
        idcg += 1.0 / math.log2(i + 2.0)

    if idcg == 0.0:
        return 0.0
    return dcg / idcg


def precision_recall(
    actual: Sequence[str], predicted: Sequence[str]
) -> tuple[float, float]:
    """Calculates set-based Precision and Recall."""
    if not actual and not predicted:
        return 1.0, 1.0
    if not actual or not predicted:
        return 0.0, 0.0

    actual_set = set(actual)
    predicted_set = set(predicted)
    true_positives = len(actual_set & predicted_set)

    precision = true_positives / len(predicted_set) if predicted_set else 0.0
    recall = true_positives / len(actual_set) if actual_set else 0.0
    return precision, recall


def macro_f1(
    actual_labels: Sequence[str],
    predicted_labels: Sequence[str],
    classes: Sequence[str],
) -> float:
    """Calculates unweighted Macro F1 score across all specified classes."""
    if not actual_labels or not predicted_labels or len(actual_labels) != len(predicted_labels):
        return 0.0

    f1_scores: list[float] = []
    for cls in classes:
        tp = sum(1 for a, p in zip(actual_labels, predicted_labels) if a == cls and p == cls)
        fp = sum(1 for a, p in zip(actual_labels, predicted_labels) if a != cls and p == cls)
        fn = sum(1 for a, p in zip(actual_labels, predicted_labels) if a == cls and p != cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        if precision + recall > 0:
            f1_scores.append(2 * precision * recall / (precision + recall))
        else:
            f1_scores.append(0.0)

    if not f1_scores:
        return 0.0
    return sum(f1_scores) / len(f1_scores)


def confusion_matrix(
    actual_labels: Sequence[str],
    predicted_labels: Sequence[str],
    classes: Sequence[str],
) -> dict[str, dict[str, int]]:
    """Generates an NxN confusion matrix dictionary: matrix[actual][predicted] = count."""
    matrix: dict[str, dict[str, int]] = {
        actual_cls: {pred_cls: 0 for pred_cls in classes}
        for actual_cls in classes
    }
    for a, p in zip(actual_labels, predicted_labels):
        if a in matrix and p in matrix[a]:
            matrix[a][p] += 1
        elif a in matrix:
            # Predicted class outside specified class list
            matrix[a][p] = 1
    return matrix
