"""Tune RRF depth, k and weights from harness run files (lexical and dense candidate lists, 100 per list).

    python -m threat_retrieval_engine.dense.tune_fusion --lexical-dev runs/v2_lexical-dev.jsonl \\
        --dense-dev runs/v2_dense-dev.jsonl --lexical-train ... --dense-train ... --out results/dense/tuning/fusion.json

The fused ranking of every query is recomputed in memory from the two lists stored in the run files (the
ranking each component returned, best first), for every grid point; metrics are the harness's own per-query
definitions (``benchmarks_v2.eval.metrics``: equivalence units, grade >= 2 relevant), averaged per slice and
macro over the answerable slices, without bootstrap (the selected setting is then run and reported by the
harness with intervals).

Selection: the dev objective is macro Recall@50 + macro nDCG@10 (the first stage feeds the reranker at depth
50, and its top 10 is what a user sees without reranking). Dev is the selection split because it holds every
slice; train holds only T3 and T4, so a setting fitted on train would be fitted to two slices. Train is
reported for every setting as an out-of-sample check, and the setting train alone would pick is reported too.
The sealed test split is never read.
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path

from .fusion import RRFConfig, rrf

DEPTHS = (10, 20, 30, 50, 75, 100)
KS = (1, 5, 10, 20, 40, 60, 100)
WEIGHTS = (0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0)  # dense weight; lexical weight 1
METRICS = ("recall@50", "recall@100", "ndcg@10", "recall@10", "mrr@10", "success@1")


def load_lists(path: Path) -> dict[str, list[str]]:
    from benchmarks_v2.eval.schema import load_run
    run = load_run(Path(path))
    out = {}
    for qid, rec in run.records.items():
        if rec.error:
            raise ValueError(f"{path}: {qid} has an error record ({rec.error}); fusion tuning needs complete lists")
        out[qid] = [r.doc_id for r in rec.ranked]
    return out


class Scorer:
    def __init__(self, split: str, dataset: Path):
        from benchmarks_v2.eval.schema import load_dataset
        if split not in ("train", "dev"):
            raise ValueError("tuning uses train and dev only")
        self.ds = load_dataset(dataset, split)
        self.queries = [q for q in self.ds.select(split) if q.answerable]
        from benchmarks_v2.eval.metrics import query_judgements
        self.qj = {q.qid: query_judgements(q, self.ds.qrels.get(q.qid, {}), self.ds.equivalence) for q in self.queries}

    def evaluate(self, rankings: dict[str, list[str]]) -> dict:
        from benchmarks_v2.eval.metrics import ranking_metrics
        by: dict[str, list[dict]] = {}
        for q in self.queries:
            units = [self.ds.equivalence.unit(d) for d in rankings[q.qid]]
            m, _, _, _ = ranking_metrics(units, self.qj[q.qid], 2)
            by.setdefault(q.slice, []).append(m)
        out = {}
        for sl, rows in sorted(by.items()):
            out[sl] = {}
            for k in METRICS:
                vals = [r[k] for r in rows if r[k] is not None]
                out[sl][k] = sum(vals) / len(vals) if vals else None
        sl_ok = [s for s in out if out[s]["recall@50"] is not None]
        out["macro"] = {k: sum(out[s][k] for s in sl_ok) / len(sl_ok) for k in METRICS}
        return out


def fuse_all(lex: dict, den: dict, qids, cfg: RRFConfig, limit: int = 100) -> dict[str, list[str]]:
    return {q: [d for d, _ in rrf([lex[q], den[q]], cfg, limit=limit)] for q in qids}


def objective(summary: dict) -> float:
    return summary["macro"]["recall@50"] + summary["macro"]["ndcg@10"]


def grid(lex: dict[str, dict], den: dict[str, dict], scorers: dict[str, Scorer]) -> list[dict]:
    rows = []
    for depth, k, w in itertools.product(DEPTHS, KS, WEIGHTS):
        cfg = RRFConfig(weights=(1.0, w), k=float(k), depth=depth)
        row = {"depth": depth, "k": k, "w_dense": w}
        for split, sc in scorers.items():
            qids = [q.qid for q in sc.queries]
            s = sc.evaluate(fuse_all(lex[split], den[split], qids, cfg))
            row[split] = s
            row[f"{split}_objective"] = objective(s)
        rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", type=Path, default=Path(__file__).resolve().parents[2] / "data/benchmark/v2.0")
    for s in ("dev", "train"):
        ap.add_argument(f"--lexical-{s}", type=Path, required=s == "dev")
        ap.add_argument(f"--dense-{s}", type=Path, required=s == "dev")
    ap.add_argument("--label", default="")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    scorers, lex, den = {}, {}, {}
    for s in ("dev", "train"):
        lp, dp = getattr(a, f"lexical_{s}"), getattr(a, f"dense_{s}")
        if lp is None or dp is None:
            continue
        scorers[s] = Scorer(s, a.dataset)
        lex[s], den[s] = load_lists(lp), load_lists(dp)
        missing = [q.qid for q in scorers[s].queries if q.qid not in lex[s] or q.qid not in den[s]]
        if missing:
            raise SystemExit(f"{s}: {len(missing)} queries missing from the run files, e.g. {missing[:3]}")
    rows = grid(lex, den, scorers)
    best = max(rows, key=lambda r: (r["dev_objective"], -r["depth"], r["k"]))
    out = {"label": a.label, "objective": "macro recall@50 + macro ndcg@10 on dev (answerable slices)",
           "grid": {"depth": DEPTHS, "k": KS, "w_dense": WEIGHTS, "w_lexical": 1.0},
           "inputs": {s: {"lexical": str(getattr(a, f"lexical_{s}")), "dense": str(getattr(a, f"dense_{s}"))}
                      for s in scorers},
           "selected": {k: best[k] for k in ("depth", "k", "w_dense")},
           "selected_scores": {s: best[s] for s in scorers},
           "top10_dev": [{k: r[k] for k in ("depth", "k", "w_dense", "dev_objective")} | (
               {"train_objective": r["train_objective"]} if "train" in scorers else {}) for r in
               sorted(rows, key=lambda r: -r["dev_objective"])[:10]],
           "default_rrf": next({s: r[s] for s in scorers} for r in rows
                               if r["depth"] == 100 and r["k"] == 60 and r["w_dense"] == 1.0)}
    if "train" in scorers:
        tb = max(rows, key=lambda r: (r["train_objective"], -r["depth"], r["k"]))
        out["train_selected"] = {k: tb[k] for k in ("depth", "k", "w_dense")}
        out["train_selected_dev"] = tb["dev"]
    out["all"] = [{k: r[k] for k in ("depth", "k", "w_dense", "dev_objective")} | (
        {"train_objective": r["train_objective"]} if "train" in scorers else {}) for r in rows]
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps({"selected": out["selected"], "dev_macro": best["dev"]["macro"],
                      "train_macro": best.get("train", {}).get("macro")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
