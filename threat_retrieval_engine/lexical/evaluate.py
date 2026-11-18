"""Fast in-process evaluation of lexical settings on the open benchmark splits (train, dev) for tuning.

Uses the B4 harness's own metric definitions (``benchmarks_v2.eval.metrics``: equivalence units, grade >= 2
relevant, Recall@k, nDCG@10, MRR@10) without bootstrap, so a setting can be scored in seconds. Reported
numbers for the package come from the harness itself (``python -m benchmarks_v2.eval run/score``).
The sealed test split is never loaded here: ``load_dataset`` refuses it without TRE_OPEN_SEALED.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Iterable

METRICS = ("recall@50", "recall@100", "ndcg@10", "mrr@10", "recall@10", "success@1")


def default_dataset() -> Path:
    env = os.environ.get("TRE_BENCHMARK_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "data" / "benchmark" / "v2.0"


def load(split: str, root: Path | None = None):
    from benchmarks_v2.eval.schema import load_dataset
    if split not in ("train", "dev"):
        raise ValueError("tuning uses the train and dev splits only")
    ds = load_dataset(root or default_dataset(), split)
    return ds, [q for q in ds.select(split) if q.answerable]


def per_query(ds, queries, ranked_fn: Callable[[str], list[str]], threads: int = 8) -> dict[str, dict]:
    """qid -> {"slice", metric: value} using the harness's ranking_metrics."""
    from benchmarks_v2.eval.metrics import query_judgements, ranking_metrics
    with ThreadPoolExecutor(max_workers=threads) as ex:
        rankings = list(ex.map(lambda q: ranked_fn(q.text), queries))
    out = {}
    for q, docs in zip(queries, rankings):
        qj = query_judgements(q, ds.qrels.get(q.qid, {}), ds.equivalence)
        units = [ds.equivalence.unit(d) for d in docs]
        m, _, _, _ = ranking_metrics(units, qj, 2)
        out[q.qid] = {"slice": q.slice, **{k: m[k] for k in METRICS}}
    return out


def summarize(pq: dict[str, dict], metrics: Iterable[str] = METRICS) -> dict[str, dict[str, float]]:
    """slice -> metric -> mean (undefined values skipped), plus 'macro' over slices."""
    by: dict[str, list[dict]] = {}
    for r in pq.values():
        by.setdefault(r["slice"], []).append(r)
    out: dict[str, dict[str, float]] = {}
    for sl, rs in sorted(by.items()):
        out[sl] = {}
        for m in metrics:
            vals = [r[m] for r in rs if r[m] is not None]
            out[sl][m] = sum(vals) / len(vals) if vals else float("nan")
        out[sl]["n"] = len(rs)
    out["macro"] = {m: sum(out[s][m] for s in by) / len(by) for m in metrics}
    return out
