"""C7: fit the calibrated confidence model and freeze tier thresholds from v2_full feature logs.

    python scripts/v2/fit_calibration.py --features features-dev.jsonl features-train.jsonl \
        --dataset data/benchmark/v2.0 [--judged data/judging/round1/agreed.jsonl] \
        --out threat_retrieval_engine/v2/calibration.json --report results/v2/calibration.md

Rows: every non-EXACT result in the top 10 of every dev and train question that the reranker scored. Label:
relevant (1) when graded 2 in the benchmark answer key or in the judged pairs (``--judged``: {pair_id, grade}
with pair_id "<qid>|<doc_id>"); everything else 0. Without judged pairs an unjudged result counts as not
relevant, so precision is under-estimated: the tiers are conservative until judging round 1 is merged.

Model: logistic regression (Newton steps, L2 1e-3) over the signals in ``Calibration.vector`` (plan 4.7:
rerank logit, margin to the next result, dense cosine, lexical and dense rank, retriever agreement, nickname
hit, ATT&CK name hit, query length). Out-of-fold probabilities (5 folds by question, seeded) choose the tier
thresholds: the smallest probability p whose results at or above p reach the tier's precision (STRONG 0.95,
PARTIAL 0.70, WEAK 0.30) with at least 30 results; the final model is fitted on all rows. Reported: ECE (10 bins)
and per-tier precision, out of fold.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from threat_retrieval_engine.v2.retriever import Hit  # noqa: E402
from threat_retrieval_engine.v2.service import Calibration  # noqa: E402

TIERS = (("STRONG", 0.95), ("PARTIAL", 0.70), ("WEAK", 0.30))
MIN_SUPPORT = 30


def load_rows(feature_files, queries, rel):
    by_text = defaultdict(list)
    for q in queries:
        by_text[q["text"]].append(q)
    X, y, groups, meta = [], [], [], []
    feats = None
    for f in feature_files:
        for line in open(f, encoding="utf-8"):
            r = json.loads(line)
            qs = by_text.get(r["query"])
            if not qs:
                continue
            q = qs[0]
            hits = []
            for i, h in enumerate(r["hits"], 1):
                hh = Hit(h["doc_id"], rank=h.get("rank", i), route=h["route"], rerank_logit=h["rerank_logit"],
                         fused_rank=h["fused_rank"], lexical_rank=h["lexical_rank"], dense_rank=h["dense_rank"],
                         dense_cosine=h["dense_cosine"])
                hits.append(hh)
            for h in hits[:10]:
                if h.route == "exact_id" or h.rerank_logit is None:
                    continue
                v = Calibration.vector(h, hits, r["query"])
                feats = feats or list(v)
                X.append([v[k] for k in feats])
                y.append(1 if h.doc_id in rel.get(q["qid"], ()) else 0)
                groups.append(q["qid"])
                meta.append((q["qid"], q["slice"], q["split"], h.doc_id))
    return np.array(X, float), np.array(y, float), groups, meta, feats


def fit_lr(X, y, l2=1e-3, iters=50):
    mu, sd = X.mean(0), X.std(0) + 1e-9
    Z = np.hstack([np.ones((len(X), 1)), (X - mu) / sd])
    w = np.zeros(Z.shape[1])
    for _ in range(iters):
        p = 1 / (1 + np.exp(-np.clip(Z @ w, -40, 40)))
        g = Z.T @ (p - y) + l2 * np.r_[0, w[1:]]
        H = (Z * (p * (1 - p))[:, None]).T @ Z + l2 * np.eye(len(w))
        step = np.linalg.solve(H, g)
        w -= step
        if np.abs(step).max() < 1e-8:
            break
    # back to raw-feature weights
    wr = w[1:] / sd
    b = w[0] - (w[1:] * mu / sd).sum()
    return wr, b


def predict(X, wr, b):
    return 1 / (1 + np.exp(-np.clip(X @ wr + b, -40, 40)))


def ece(p, y, bins=10):
    e = 0.0
    for i in range(bins):
        m = (p >= i / bins) & (p < (i + 1) / bins if i < bins - 1 else p <= 1)
        if m.any():
            e += m.mean() * abs(p[m].mean() - y[m].mean())
    return e


def thresholds(p, y):
    order = np.argsort(-p)
    ps, ys = p[order], y[order]
    cum = np.cumsum(ys) / np.arange(1, len(ys) + 1)
    out = []
    for name, target in TIERS:
        ok = [i for i in range(MIN_SUPPORT - 1, len(ps)) if cum[i] >= target]
        thr = float(ps[max(ok)]) if ok else None
        out.append([name, thr])
    # tiers must be decreasing; a tier with no reachable threshold is disabled (threshold above 1)
    last = 1.0 + 1e-9
    fixed = []
    for name, thr in out:
        t = 1.01 if thr is None else min(thr, last)
        fixed.append([name, round(t, 4)])
        last = t
    return fixed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", nargs="+", required=True)
    ap.add_argument("--dataset", type=Path, default=ROOT / "data/benchmark/v2.0")
    ap.add_argument("--judged", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--seed", type=int, default=20261118)
    a = ap.parse_args()
    queries = [json.loads(l) for l in open(a.dataset / "queries.jsonl", encoding="utf-8")]
    queries = [q for q in queries if q["split"] in ("dev", "train")]
    rel = defaultdict(set)
    for l in open(a.dataset / "qrels.jsonl", encoding="utf-8"):
        r = json.loads(l)
        if r["grade"] >= 2:
            rel[r["qid"]].add(r["doc_id"])
    label_source = "benchmark answer key only (unjudged = not relevant)"
    if a.judged and a.judged.is_file():
        n = 0
        for l in open(a.judged, encoding="utf-8"):
            r = json.loads(l)
            qid, doc = r["pair_id"].split("|", 1)
            if int(r["grade"]) >= 2:
                rel[qid].add(doc)
                n += 1
        label_source = f"answer key + {n} judged relevant pairs ({a.judged.name})"
    X, y, groups, meta, feats = load_rows(a.features, queries, rel)
    uq = sorted(set(groups))
    random.Random(a.seed).shuffle(uq)
    fold = {q: i % 5 for i, q in enumerate(uq)}
    f = np.array([fold[g] for g in groups])
    oof = np.zeros(len(y))
    for k in range(5):
        wr, b = fit_lr(X[f != k], y[f != k])
        oof[f == k] = predict(X[f == k], wr, b)
    dev = np.array([m[2] == "dev" for m in meta])
    tiers = thresholds(oof[dev], y[dev])
    wr, b = fit_lr(X, y)
    spec = {"version": "c7-provisional" if not a.judged else "c7", "features": feats, "weights": wr.tolist(),
            "bias": float(b), "tiers": tiers, "label_source": label_source, "rows": int(len(y)),
            "positives": int(y.sum()), "questions": len(uq),
            "oof_ece_dev": round(ece(oof[dev], y[dev]), 4)}
    stats = []
    pd, yd = oof[dev], y[dev]
    hi = 1.01
    for name, thr in tiers:
        m = (pd >= thr) & (pd < hi)
        cum = pd >= thr
        stats.append({"tier": name, "threshold": thr, "results_in_tier": int(m.sum()),
                      "precision_in_tier": round(float(yd[m].mean()), 4) if m.any() else None,
                      "precision_at_or_above": round(float(yd[cum].mean()), 4) if cum.any() else None})
        hi = thr
    spec["oof_tier_stats_dev"] = stats
    a.out.write_text(json.dumps(spec, indent=1), encoding="utf-8")
    print(json.dumps(spec, indent=1))
    if a.report:
        a.report.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# C7 calibration (provisional)" if not a.judged else "# C7 calibration", "",
                 f"Labels: {label_source}. Rows: {len(y)} top-10 results ({int(y.sum())} relevant) of {len(uq)} "
                 f"dev+train questions. Out-of-fold (5 folds by question) on dev: ECE {spec['oof_ece_dev']}.", "",
                 "| Tier | Threshold | Results (dev, OOF) | Precision in tier | Precision at or above |",
                 "|---|---|---|---|---|"]
        for s in stats:
            lines.append(f"| {s['tier']} | {s['threshold']} | {s['results_in_tier']} | {s['precision_in_tier']} | "
                         f"{s['precision_at_or_above']} |")
        a.report.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
