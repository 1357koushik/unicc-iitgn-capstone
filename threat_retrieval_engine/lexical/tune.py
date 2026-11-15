"""Tuning of the lexical retriever on the benchmark's train split (fit) and dev split (select).

    python -m threat_retrieval_engine.lexical.tune weights --index <build> [--out results/lexical/tuning]
    python -m threat_retrieval_engine.lexical.tune grid    --index <build> --configs '<json list>'
    python -m threat_retrieval_engine.lexical.tune k1b     --index <build> --store <C1 build>

``weights``: coordinate ascent over the column weights on train (objective: macro Recall@50 over the train
slices, nDCG@10 breaking ties within 0.002), then the best few train settings, crossed with the ``ids``
weight (train has no identifier queries), are compared on dev macro Recall@50 and the best is selected.
``grid``: train and dev metrics of explicit settings (tokenizer builds, stop words, term caps).
``k1b``: FTS5's bm25() fixes k1 = 1.2 and b = 0.75; this measures whether other values would help, by
re-scoring each query's top 200 FTS5 candidates with BM25F under a grid of k1 and b (term frequencies from
re-tokenizing the candidate documents of the store). Re-scoring a candidate pool is an approximation (a
document outside the pool cannot enter); it is reported as such.

The sealed test split is never read (``evaluate.load`` accepts train and dev only).
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

from . import evaluate as E
from .config import RankingConfig
from .index import LexicalIndex
from .schema import COLUMNS

GRID = (0.0, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
IDS_GRID = (1.0, 5.0, 10.0, 20.0, 50.0)


def run(ix: LexicalIndex, data, r: RankingConfig, threads: int = 8) -> tuple[dict, dict]:
    ds, qs = data
    lat: list[float] = []

    def fn(text: str) -> list[str]:
        res = ix.search(text, k=100, ranking=r)
        lat.append(res.timings_ms["total"])
        return [d for d, _ in res.hits]

    pq = E.per_query(ds, qs, fn, threads=threads)
    lat.sort()
    pct = {f"p{int(p * 100)}": lat[min(len(lat) - 1, int(p * len(lat)))] for p in (0.5, 0.95, 0.99)} if lat else {}
    return E.summarize(pq), {"latency_ms": pct, "per_query": pq}


def objective(sm: dict) -> tuple[float, float]:
    return sm["macro"]["recall@50"], sm["macro"]["ndcg@10"]


def better(a: tuple[float, float], b: tuple[float, float]) -> bool:
    """a better than b: higher Recall@50, or equal within 0.002 and higher nDCG@10."""
    if a[0] > b[0] + 0.002:
        return True
    return abs(a[0] - b[0]) <= 0.002 and a[1] > b[1]


def fmt(sm: dict) -> str:
    return " ".join(f"{s}:{m['recall@50']:.3f}/{m['ndcg@10']:.3f}" for s, m in sm.items())


def cmd_weights(a) -> dict:
    ix = LexicalIndex.open(a.index)
    train, dev = E.load("train"), E.load("dev")
    from .config import RANKING
    # query-side settings from the code (config.RANKING), not from whatever the index was built with
    base = RANKING.with_(**json.loads(a.base)).with_(weights={c: 1.0 for c in COLUMNS})
    cur = base
    cache: dict[tuple, tuple] = {}

    def score(r: RankingConfig):
        key = r.weights
        if key not in cache:
            sm, _ = run(ix, train, r)
            cache[key] = (objective(sm), sm)
        return cache[key]

    best_obj, _ = score(cur)
    print(f"[tune] start {dict(zip(COLUMNS, cur.weights))} train R@50/nDCG {best_obj}", flush=True)
    for rnd in range(a.rounds):
        changed = False
        for col in COLUMNS:
            if col == "ids":  # no identifier queries in train; chosen on dev below
                continue
            for w in GRID:
                cand = cur.with_(weights={col: w})
                if cand.weights == cur.weights or not any(x > 0 for x in cand.weights[1:]):
                    continue
                obj, _ = score(cand)
                if better(obj, best_obj):
                    best_obj, cur, changed = obj, cand, True
                    print(f"[tune] round {rnd} {col}={w}: train {obj[0]:.4f}/{obj[1]:.4f}", flush=True)
        if not changed:
            break
    ranked = sorted(cache.items(), key=lambda kv: (-kv[1][0][0], -kv[1][0][1]))
    top = [base.with_(weights=dict(zip(COLUMNS, k))) for k, _ in ranked[: a.top]]
    selection = []
    best_dev = None
    for r in top:
        for iw in IDS_GRID:
            cand = r.with_(weights={"ids": iw})
            sm, _ = run(ix, dev, cand)
            obj = objective(sm)
            row = {"weights": cand.weight_map(), "train": cache[r.weights][0], "dev": obj, "dev_slices": sm}
            selection.append(row)
            print(f"[tune] dev {cand.weight_map()} -> {obj[0]:.4f}/{obj[1]:.4f}", flush=True)
            if best_dev is None or better(obj, best_dev[0]):
                best_dev = (obj, cand)
    out = {"index": str(ix.build_dir), "train_evaluations": len(cache),
           "train_path": [{"weights": dict(zip(COLUMNS, k)), "train": v[0]} for k, v in ranked[:20]],
           "dev_selection": selection, "selected": best_dev[1].weight_map(), "selected_dev": best_dev[0]}
    return out


def cmd_grid(a) -> dict:
    ix = LexicalIndex.open(a.index)
    splits = a.splits.split(",")
    data = {s: E.load(s) for s in splits}
    rows = []
    for c in json.loads(a.configs):
        r = ix.ranking.with_(**c)
        row = {"config": c, "ranking": r.as_dict(), "tokenizer": ix.meta.get("tokenizer")}
        for s in splits:
            sm, extra = run(ix, data[s], r, threads=a.threads)
            row[s] = sm
            row[f"{s}_latency_ms"] = extra["latency_ms"]
            print(f"[grid] {ix.meta.get('tokenizer')} {c} {s} lat {extra['latency_ms']} | {fmt(sm)}", flush=True)
        rows.append(row)
    return {"index": str(ix.build_dir), "rows": rows}


# --------------------------------------------------------------------------- k1/b re-scoring
def cmd_k1b(a) -> dict:
    from collections import Counter

    from ..store import Store
    from ..text.tokenizer import tokenize
    from .sources import CveStoreSource

    ix = LexicalIndex.open(a.index)
    st = Store.open(a.store)
    src = CveStoreSource(st)
    r = ix.ranking
    db = ix._conn()
    n_docs = ix.n_docs
    total_tokens = int(ix.meta["tokens"])
    avgdl = total_tokens / n_docs
    w = dict(zip(COLUMNS, r.weights))
    tf_cache: dict[str, tuple[dict, int]] = {}

    def doc_tf(cid: str) -> tuple[dict, int]:
        if cid not in tf_cache:
            row = st.get(cid, columns=("cve_id", "title", "aliases", "vendor_product", "description", "weakness",
                                       "kev_text"))
            cols = {c: row.get(c) or "" for c in COLUMNS if c not in ("ids", "exploit_titles")}
            cols["ids"] = cid
            cols["exploit_titles"] = "; ".join(sorted({x["alias"] for x in st.aliases(cid, kinds=("title",))}))
            wtf: Counter = Counter()
            length = 0
            for c in COLUMNS:
                toks = tokenize(cols[c], ix.tokenizer)
                length += len(toks)
                for t in toks:
                    wtf[t] += w[c]
            tf_cache[cid] = (dict(wtf), length)
        return tf_cache[cid]

    grid = [(k1, b) for k1 in (0.9, 1.2, 1.5, 2.0) for b in (0.5, 0.75, 0.9)]
    out = {"pool_depth": a.pool, "grid": {}}
    for split in ("train", "dev"):
        ds, qs = E.load(split)
        pools = []
        t0 = time.time()
        for q in qs:
            res = ix.search(q.text, k=a.pool)
            pools.append((q, res.query, [d for d, _ in res.hits]))
        print(f"[k1b] {split}: pools in {time.time() - t0:.0f} s", flush=True)
        for k1, b in grid:
            per = {}
            for q, query, docs in pools:
                idf = {}
                for t in query.terms:
                    v = math.log((n_docs - query.df[t] + 0.5) / (query.df[t] + 0.5))
                    idf[t] = v if v > 0 else 1e-6
                scored = []
                for i, d in enumerate(docs):
                    tf, dl = doc_tf(d)
                    s = 0.0
                    for t in query.terms:
                        f = tf.get(t, 0.0)
                        if f:
                            s += idf[t] * f * (k1 + 1) / (f + k1 * (1 - b + b * dl / avgdl))
                    scored.append((-s, i, d))
                scored.sort()
                per[q.qid] = [d for _, _, d in scored[:100]]
            pq = E.per_query(ds, qs, lambda text, m={q.text: per[q.qid] for q in qs}: m[text], threads=1)
            sm = E.summarize(pq)
            out["grid"].setdefault(f"{k1}/{b}", {})[split] = sm
            print(f"[k1b] {split} k1={k1} b={b}: macro R@50 {sm['macro']['recall@50']:.4f} "
                  f"nDCG {sm['macro']['ndcg@10']:.4f}", flush=True)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("weights")
    p.add_argument("--index", required=True)
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--top", type=int, default=4)
    p.add_argument("--base", default="{}", help="JSON overrides of the query settings")
    p = sub.add_parser("grid")
    p.add_argument("--index", required=True)
    p.add_argument("--configs", default="[{}]")
    p.add_argument("--splits", default="train,dev")
    p.add_argument("--threads", type=int, default=8)
    p = sub.add_parser("k1b")
    p.add_argument("--index", required=True)
    p.add_argument("--store", required=True)
    p.add_argument("--pool", type=int, default=200)
    for p in sub.choices.values():
        p.add_argument("--out", help="write the result JSON here")
    a = ap.parse_args(argv)
    res = {"weights": cmd_weights, "grid": cmd_grid, "k1b": cmd_k1b}[a.cmd](a)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        slim = json.loads(json.dumps(res, default=str))
        Path(a.out).write_text(json.dumps(slim, indent=1), encoding="utf-8", newline="\n")
        print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
