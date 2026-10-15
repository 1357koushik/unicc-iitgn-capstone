"""
scripts/evaluate_m4.py
======================
Evaluates M4 (bge-reranker-v2-m3 alone, Platt calibrated) vs M2 (L2-Logistic Regression on features).
Computes:
- 5-Fold GroupKFold Out-of-Fold: Log Loss, Brier Score, ECE (10 bins), AUC-ROC
- Sealed Test Set: Log Loss, Brier Score, ECE (10 bins), AUC-ROC
Saves results to data/labels/m4_comparison.json
"""

import json
import logging
import os
import sys
import time
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, brier_score_loss, log_loss

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from threat_retrieval_engine.api.confidence import load_confidence_model, QueryProfile
from threat_retrieval_engine.api.feature_extractor import extract_features, FEATURE_NAMES
from threat_retrieval_engine.search_engine.reranker import CrossEncoderReranker
from threat_retrieval_engine.search_engine.tokenizer import tokenize

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_m4")


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
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


def main():
    logger.info("Loading datasets...")
    with open("data/labels/cve_masked_train_folds.json", "r", encoding="utf-8") as f:
        all_train_pairs = json.load(f)
    with open("data/labels/cve_masked_test_sealed.json", "r", encoding="utf-8") as f:
        test_pairs = json.load(f)

    # Sample 160 distinct CVE groups from train (640 pairs) to match test set size
    # and ensure balanced representation across all 5 folds
    unique_train_cves = sorted(list(set(p["target_cve"] for p in all_train_pairs)))
    # Deterministic selection of 160 CVE groups
    rng = np.random.RandomState(42)
    selected_cves = set(rng.choice(unique_train_cves, size=160, replace=False))
    train_pairs = [p for p in all_train_pairs if p["target_cve"] in selected_cves]

    logger.info("Train pairs: %d across %d groups. Test pairs: %d across %d groups.",
                len(train_pairs), len(selected_cves), len(test_pairs), len(set(p["target_cve"] for p in test_pairs)))

    logger.info("Initializing CrossEncoderReranker (BAAI/bge-reranker-v2-m3)...")
    reranker = CrossEncoderReranker()
    scorer = reranker._load()

    cache_file = "data/labels/reranker_scores_cache.json"
    cache = {}
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cache = json.load(f)
            logger.info("Loaded %d precomputed scores from cache.", len(cache))
        except Exception:
            cache = {}

    def get_reranker_scores(pairs, desc=""):
        pairs_to_compute = []
        indices_to_compute = []
        scores = [0.0] * len(pairs)
        for idx, p in enumerate(pairs):
            pid = p["pair_id"]
            if pid in cache:
                scores[idx] = cache[pid]
            else:
                q = p["query_masked"]
                t = p.get("text", "")
                pairs_to_compute.append([q, t])
                indices_to_compute.append((idx, pid))

        if pairs_to_compute:
            logger.info("Scoring %d %s pairs with bge-reranker-v2-m3 (batch_size=64, max_length=128)...", len(pairs_to_compute), desc)
            t0 = time.perf_counter()
            batch_size = 64
            computed = []
            for i in range(0, len(pairs_to_compute), batch_size):
                b = pairs_to_compute[i:i + batch_size]
                b_scores = scorer.compute_score(b, batch_size=batch_size, max_length=128)
                computed.extend([float(s) for s in b_scores])
                logger.info("Progress (%s): %d / %d pairs", desc, len(computed), len(pairs_to_compute))

            elapsed = time.perf_counter() - t0
            logger.info("Finished scoring %s in %.2fs (%.2f pairs/s).", desc, elapsed, len(pairs_to_compute) / max(0.1, elapsed))

            for (orig_idx, pid), sc in zip(indices_to_compute, computed):
                scores[orig_idx] = sc
                cache[pid] = sc

            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache, f)

        return np.array(scores, dtype=np.float64)

    y_train = np.array([int(p["label"]) for p in train_pairs], dtype=np.int32)
    folds_train = np.array([int(p["fold"]) for p in train_pairs], dtype=np.int32)
    s_train_reranker = get_reranker_scores(train_pairs, "train")

    y_test = np.array([int(p["label"]) for p in test_pairs], dtype=np.int32)
    s_test_reranker = get_reranker_scores(test_pairs, "test")

    # -------------------------------------------------------------
    # M2 Feature Extraction & Model Evaluation
    # -------------------------------------------------------------
    m2_model = load_confidence_model("threat_retrieval_engine/models/confidence_model.json")
    profile = QueryProfile(cves=(), ips=(), hashes=(), mitre_techniques=(), threat_actors=(), malware=())

    def get_m2_probs(pairs):
        probs = []
        for p in pairs:
            q_tokens = set(tokenize(p["query_masked"]))
            d_tokens = set(tokenize(p.get("text", "")))
            bm25_overlap = len(q_tokens & d_tokens) / len(q_tokens) if q_tokens else 0.0
            cand = {"chunk_id": p["chunk_id"], "text": p["text"], "metadata": {"text": p["text"]}, "bm25_norm_score": round(bm25_overlap, 4)}
            feat = extract_features(profile, cand)
            probs.append(m2_model.predict_proba(feat))
        return np.array(probs, dtype=np.float64)

    p_test_m2 = get_m2_probs(test_pairs)
    p_train_m2 = get_m2_probs(train_pairs)

    m2_oof_log_loss = float(log_loss(y_train, p_train_m2))
    m2_oof_brier = float(brier_score_loss(y_train, p_train_m2))
    m2_oof_ece = compute_ece(y_train, p_train_m2, n_bins=10)
    m2_oof_auc = float(roc_auc_score(y_train, p_train_m2))

    # -------------------------------------------------------------
    # M4: Out-of-fold Platt calibration on reranker score alone
    # -------------------------------------------------------------
    logger.info("Computing M4 Out-of-Fold Platt Calibration...")
    oof_p_m4 = np.zeros(len(y_train), dtype=np.float64)
    unique_folds = sorted(list(set(folds_train)))

    for f_idx in unique_folds:
        tr_mask = folds_train != f_idx
        val_mask = folds_train == f_idx

        X_tr = s_train_reranker[tr_mask].reshape(-1, 1)
        y_tr = y_train[tr_mask]
        X_val = s_train_reranker[val_mask].reshape(-1, 1)

        # Platt scaling is univariate logistic regression on raw score
        platt = LogisticRegression(C=1.0, solver="lbfgs")
        platt.fit(X_tr, y_tr)
        oof_p_m4[val_mask] = platt.predict_proba(X_val)[:, 1]

    # Overall Platt fit on all train data for testing
    final_platt = LogisticRegression(C=1.0, solver="lbfgs")
    final_platt.fit(s_train_reranker.reshape(-1, 1), y_train)
    p_test_m4 = final_platt.predict_proba(s_test_reranker.reshape(-1, 1))[:, 1]

    # Metrics for M4 OOF
    m4_oof_log_loss = float(log_loss(y_train, oof_p_m4))
    m4_oof_brier = float(brier_score_loss(y_train, oof_p_m4))
    m4_oof_ece = compute_ece(y_train, oof_p_m4, n_bins=10)
    m4_oof_auc = float(roc_auc_score(y_train, oof_p_m4))

    # Metrics for Sealed Test
    m2_test_log_loss = float(log_loss(y_test, p_test_m2))
    m2_test_brier = float(brier_score_loss(y_test, p_test_m2))
    m2_test_ece = compute_ece(y_test, p_test_m2, n_bins=10)
    m2_test_auc = float(roc_auc_score(y_test, p_test_m2))

    m4_test_log_loss = float(log_loss(y_test, p_test_m4))
    m4_test_brier = float(brier_score_loss(y_test, p_test_m4))
    m4_test_ece = compute_ece(y_test, p_test_m4, n_bins=10)
    m4_test_auc = float(roc_auc_score(y_test, p_test_m4))

    comparison = {
        "OOF": {
            "M2": {
                "log_loss": round(m2_oof_log_loss, 4),
                "brier": round(m2_oof_brier, 4),
                "ece": round(m2_oof_ece, 5),
                "auc": round(m2_oof_auc, 4),
            },
            "M4": {
                "log_loss": round(m4_oof_log_loss, 4),
                "brier": round(m4_oof_brier, 4),
                "ece": round(m4_oof_ece, 5),
                "auc": round(m4_oof_auc, 4),
            },
        },
        "Sealed_Test": {
            "M2": {
                "log_loss": round(m2_test_log_loss, 4),
                "brier": round(m2_test_brier, 4),
                "ece": round(m2_test_ece, 5),
                "auc": round(m2_test_auc, 4),
            },
            "M4": {
                "log_loss": round(m4_test_log_loss, 4),
                "brier": round(m4_test_brier, 4),
                "ece": round(m4_test_ece, 5),
                "auc": round(m4_test_auc, 4),
            },
        },
        "m2_beats_m4_oof": m2_oof_log_loss < m4_oof_log_loss,
        "m2_beats_m4_test": m2_test_log_loss < m4_test_log_loss,
    }

    out_file = "data/labels/m4_comparison.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)

    print("\n" + "=" * 80)
    print("M2 vs M4 COMPARISON TABLE (OOF and Sealed Holdout)")
    print("=" * 80)
    print(f"{'Split / Metric':<22} | {'M2 (LogReg 12-feat)':<22} | {'M4 (Reranker Platt)':<22} | {'Winner'}")
    print("-" * 80)
    print(f"{'OOF Log Loss':<22} | {m2_oof_log_loss:<22.4f} | {m4_oof_log_loss:<22.4f} | {'M2' if m2_oof_log_loss < m4_oof_log_loss else 'M4'}")
    print(f"{'OOF Brier Score':<22} | {m2_oof_brier:<22.4f} | {m4_oof_brier:<22.4f} | {'M2' if m2_oof_brier < m4_oof_brier else 'M4'}")
    print(f"{'OOF ECE':<22} | {m2_oof_ece:<22.5f} | {m4_oof_ece:<22.5f} | {'M2' if m2_oof_ece < m4_oof_ece else 'M4'}")
    print(f"{'OOF AUC-ROC':<22} | {m2_oof_auc:<22.4f} | {m4_oof_auc:<22.4f} | {'M2' if m2_oof_auc > m4_oof_auc else 'M4'}")
    print("-" * 80)
    print(f"{'Test Log Loss':<22} | {m2_test_log_loss:<22.4f} | {m4_test_log_loss:<22.4f} | {'M2' if m2_test_log_loss < m4_test_log_loss else 'M4'}")
    print(f"{'Test Brier Score':<22} | {m2_test_brier:<22.4f} | {m4_test_brier:<22.4f} | {'M2' if m2_test_brier < m4_test_brier else 'M4'}")
    print(f"{'Test ECE':<22} | {m2_test_ece:<22.5f} | {m4_test_ece:<22.5f} | {'M2' if m2_test_ece < m4_test_ece else 'M4'}")
    print(f"{'Test AUC-ROC':<22} | {m2_test_auc:<22.4f} | {m4_test_auc:<22.4f} | {'M2' if m2_test_auc > m4_test_auc else 'M4'}")
    print("=" * 80)


if __name__ == "__main__":
    main()
