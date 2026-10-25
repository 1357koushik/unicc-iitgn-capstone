"""
evaluate_sealed_test.py
=======================
Phase 4 Unsealing and Evaluation on Sealed Test Set (cve_masked_test_sealed.json).

1. Evaluates M0, M1, M2 on the 640 sealed test pairs (160 CVE groups).
2. Computes Task 1 Precision on the ID-masked test slice with 95% bootstrap CI (grouped by CVE).
3. Reports empirical precision per probability band.
4. Outputs comparison metrics (Log Loss, Brier, ECE, Precision, Recall, F1).
"""

from __future__ import annotations

import json
import logging
import math
import os
import sys
import numpy as np

# Ensure threat_retrieval_engine is on path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from threat_retrieval_engine.api.confidence import (
    ConfidenceModel,
    QueryProfile,
    classify_confidence_tier,
    load_confidence_model,
)
from threat_retrieval_engine.api.feature_extractor import (
    FEATURE_NAMES,
    extract_features,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_sealed_test")

SEALED_TEST_PATH = os.path.join("data", "labels", "cve_masked_test_sealed.json")
MODEL_PATH = os.path.join("threat_retrieval_engine", "models", "confidence_model.json")


def log_loss(y_true: np.ndarray, y_prob: np.ndarray, eps: float = 1e-15) -> float:
    p = np.clip(y_prob, eps, 1.0 - eps)
    return float(-np.mean(y_true * np.log(p) + (1.0 - y_true) * np.log(1.0 - p)))


def brier_score(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    return float(np.mean((y_prob - y_true) ** 2))


def expected_calibration_error(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(y_true)
    for i in range(n_bins):
        b_low, b_high = bins[i], bins[i + 1]
        mask = (y_prob >= b_low) & (y_prob <= b_high) if i == n_bins - 1 else (y_prob >= b_low) & (y_prob < b_high)
        if np.sum(mask) == 0:
            continue
        bin_acc = float(np.mean(y_true[mask]))
        bin_conf = float(np.mean(y_prob[mask]))
        ece += (np.sum(mask) / n) * abs(bin_acc - bin_conf)
    return float(ece)


def predict_m0(features_list: list[dict[str, float]]) -> np.ndarray:
    """M0: Legacy static weights (0.40 IOC, 0.20 TTP, 0.20 Semantic, 0.20 CVE)."""
    probs = []
    for f in features_list:
        comp = (
            0.40 * f.get("ioc_coverage", 0.0)
            + 0.20 * f.get("ttp_coverage", 0.0)
            + 0.20 * f.get("reranker_score", f.get("bm25_norm_score", 0.0))
            + 0.20 * f.get("cve_coverage", 0.0)
        )
        probs.append(min(1.0, max(0.0, comp)))
    return np.array(probs, dtype=float)


def predict_m1(features_list: list[dict[str, float]]) -> np.ndarray:
    """M1: Presence-renormalized static weights."""
    probs = []
    for f in features_list:
        has_ioc = f.get("has_ioc", 0.0)
        has_ttp = f.get("has_ttp", 0.0)
        has_cve = f.get("has_cve", 0.0)
        active_w = (0.40 * has_ioc) + (0.20 * has_ttp) + (0.20 * has_cve) + 0.20
        w_ioc = (0.40 * has_ioc) / active_w
        w_ttp = (0.20 * has_ttp) / active_w
        w_cve = (0.20 * has_cve) / active_w
        w_sem = 0.20 / active_w
        comp = (
            w_ioc * f.get("ioc_coverage", 0.0)
            + w_ttp * f.get("ttp_coverage", 0.0)
            + w_cve * f.get("cve_coverage", 0.0)
            + w_sem * f.get("reranker_score", f.get("bm25_norm_score", 0.0))
        )
        probs.append(min(1.0, max(0.0, comp)))
    return np.array(probs, dtype=float)


def compute_bootstrap_precision_ci(
    cve_groups: list[str],
    y_true: np.ndarray,
    y_pred_binary: np.ndarray,
    n_bootstrap: int = 1000,
    ci_level: float = 0.95,
    seed: int = 42,
) -> tuple[float, float, float]:
    """Group-wise bootstrap CI for precision grouped by target CVE."""
    rng = np.random.RandomState(seed)
    unique_groups = np.unique(cve_groups)
    n_groups = len(unique_groups)

    group_to_indices = {g: np.where(np.array(cve_groups) == g)[0] for g in unique_groups}

    boot_precisions = []
    for _ in range(n_bootstrap):
        sampled_groups = rng.choice(unique_groups, size=n_groups, replace=True)
        sample_indices = np.concatenate([group_to_indices[g] for g in sampled_groups])

        sample_y = y_true[sample_indices]
        sample_pred = y_pred_binary[sample_indices]

        tp = np.sum((sample_pred == 1) & (sample_y == 1))
        fp = np.sum((sample_pred == 1) & (sample_y == 0))

        if tp + fp > 0:
            boot_precisions.append(tp / (tp + fp))
        else:
            boot_precisions.append(0.0)

    alpha = (1.0 - ci_level) / 2.0
    low = float(np.percentile(boot_precisions, 100 * alpha))
    high = float(np.percentile(boot_precisions, 100 * (1.0 - alpha)))
    mean_val = float(np.mean(boot_precisions))
    return mean_val, low, high


def main():
    logger.info("=== Phase 4: Evaluating Models on Sealed Test Set ===")
    if not os.path.exists(SEALED_TEST_PATH):
        logger.error("Sealed test set not found at %s", SEALED_TEST_PATH)
        sys.exit(1)

    with open(SEALED_TEST_PATH, "r", encoding="utf-8") as f:
        test_pairs = json.load(f)

    logger.info("Loaded %d sealed test pairs across %d CVE groups.", len(test_pairs), len(set(p["target_cve"] for p in test_pairs)))

    # Load trained M2 model
    model = load_confidence_model(MODEL_PATH)
    logger.info("Loaded M2 confidence model version: %s", model.model_version)

    # Feature extraction for test pairs
    features_list = []
    y_true_list = []
    cve_groups = []

    from threat_retrieval_engine.search_engine.tokenizer import tokenize

    for pair in test_pairs:
        query_masked = pair["query_masked"]
        # Empty query profile since CVE is masked and no IOCs/TTPs in masked query
        profile = QueryProfile(cves=(), ips=(), hashes=(), mitre_techniques=(), threat_actors=(), malware=())
        q_tokens = set(tokenize(query_masked))
        d_tokens = set(tokenize(pair.get("text", "")))
        bm25_overlap = len(q_tokens & d_tokens) / len(q_tokens) if q_tokens else 0.0

        cand = {
            "chunk_id": pair["chunk_id"],
            "text": pair["text"],
            "metadata": {"text": pair["text"]},
            "bm25_norm_score": round(bm25_overlap, 4),
        }
        feat = extract_features(profile, cand)
        features_list.append(feat)
        y_true_list.append(int(pair["label"]))
        cve_groups.append(pair["target_cve"])

    y_true = np.array(y_true_list, dtype=int)

    # 1. Evaluate Models
    p_m0 = predict_m0(features_list)
    p_m1 = predict_m1(features_list)
    p_m2 = np.array([model.predict_proba(f) for f in features_list], dtype=float)

    models_eval = {
        "M0: Baseline Static": p_m0,
        "M1: Presence-Renormalized": p_m1,
        "M2: Learned Calibrated LogReg": p_m2,
        "M3: Profile-Specific (Same as M2)": p_m2,
    }

    print("\n" + "=" * 80)
    print("SEALED TEST SET EVALUATION RESULTS (160 CVE Groups, 640 Pairs)")
    print("=" * 80)
    print(f"{'Model Architecture':<36} | {'Log Loss':<10} | {'Brier Score':<12} | {'ECE (10 bins)':<14}")
    print("-" * 80)

    for name, p_arr in models_eval.items():
        ll = log_loss(y_true, p_arr)
        bs = brier_score(y_true, p_arr)
        ece = expected_calibration_error(y_true, p_arr)
        print(f"{name:<36} | {ll:<10.4f} | {bs:<12.4f} | {ece:<14.5f}")

    print("=" * 80)

    # 2. Precision & Quality Gate Evaluation on M2
    # Probability bands
    bands = [
        ("EXACT (Layer 1 Only)", lambda p: False),  # Not present in ID-masked test set
        ("STRONG [0.65, 1.00]", lambda p: p >= 0.65),
        ("PARTIAL [0.45, 0.65)", lambda p: (p >= 0.45) and (p < 0.65)),
        ("WEAK [0.10, 0.45)", lambda p: (p >= 0.10) and (p < 0.45)),
        ("UNSUPPORTED [0.00, 0.10)", lambda p: p < 0.10),
    ]

    print("\n" + "=" * 80)
    print("EMPIRICAL PRECISION PER PROBABILITY BAND (M2 on Sealed Test Set)")
    print("=" * 80)
    print(f"{'Probability Band':<28} | {'Total Pairs':<12} | {'Positives':<10} | {'Empirical Precision':<20}")
    print("-" * 80)

    for band_name, cond in bands:
        mask = np.array([cond(p) for p in p_m2])
        count = int(np.sum(mask))
        if count > 0:
            pos = int(np.sum(y_true[mask]))
            prec = (pos / count) * 100.0
            print(f"{band_name:<28} | {count:<12} | {pos:<10} | {prec:>6.2f}%")
        else:
            print(f"{band_name:<28} | {count:<12} | {0:<10} | {'N/A (Layer 1 only)':>20}")

    print("=" * 80)

    # 3. Task 1 Precision on ID-Masked CVE Slice (Target: >= 90%)
    # For a retrieval ranking scenario: top-1 predicted chunk per CVE query
    # A candidate is selected if its score is top ranked for that CVE group
    unique_cves = sorted(list(set(cve_groups)))
    top1_correct = 0
    top1_total = len(unique_cves)

    top_m2_pred = []
    top_y = []

    for cve in unique_cves:
        indices = [i for i, g in enumerate(cve_groups) if g == cve]
        # Sort by M2 predicted probability descending
        best_idx = max(indices, key=lambda idx: p_m2[idx])
        top_y.append(y_true[best_idx])
        top_m2_pred.append(1)  # Retreived top candidate
        if y_true[best_idx] == 1:
            top1_correct += 1

    top1_precision = (top1_correct / top1_total) * 100.0

    # Bootstrap CI for Task 1 Precision
    mean_ci, low_ci, high_ci = compute_bootstrap_precision_ci(
        cve_groups=unique_cves,
        y_true=np.array(top_y),
        y_pred_binary=np.array(top_m2_pred),
        n_bootstrap=1000,
        ci_level=0.95,
        seed=42,
    )

    print("\n" + "=" * 80)
    print("TASK 1 PRECISION ON ID-MASKED CVE TEST SLICE (Top-1 Retrieval)")
    print("=" * 80)
    print(f"Total ID-Masked CVE Queries Evaluated : {top1_total}")
    print(f"Top-1 Correct Retrievals              : {top1_correct}")
    print(f"Task 1 Empirical Precision            : {top1_precision:.2f}%")
    print(f"95% Grouped Bootstrap CI              : [{low_ci*100:.2f}%, {high_ci*100:.2f}%]")
    gate_status = "PASS" if top1_precision >= 90.0 else "FAIL"
    print(f"Task 1 Quality Gate (Expected >= 90%) : {gate_status}")
    print("=" * 80)

    # Save evaluation results to JSON
    report = {
        "sealed_test_pairs": len(test_pairs),
        "sealed_cve_groups": len(unique_cves),
        "model_comparison": {
            "M0_log_loss": round(log_loss(y_true, p_m0), 4),
            "M0_brier": round(brier_score(y_true, p_m0), 4),
            "M0_ece": round(expected_calibration_error(y_true, p_m0), 5),
            "M1_log_loss": round(log_loss(y_true, p_m1), 4),
            "M1_brier": round(brier_score(y_true, p_m1), 4),
            "M1_ece": round(expected_calibration_error(y_true, p_m1), 5),
            "M2_log_loss": round(log_loss(y_true, p_m2), 4),
            "M2_brier": round(brier_score(y_true, p_m2), 4),
            "M2_ece": round(expected_calibration_error(y_true, p_m2), 5),
        },
        "task1_precision": {
            "top1_correct": top1_correct,
            "top1_total": top1_total,
            "precision_pct": round(top1_precision, 2),
            "bootstrap_ci_95": [round(low_ci * 100, 2), round(high_ci * 100, 2)],
            "gate_passed": gate_status == "PASS",
        },
    }

    out_json = os.path.join("data", "labels", "sealed_test_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info("Saved sealed test results to %s", out_json)


if __name__ == "__main__":
    main()
