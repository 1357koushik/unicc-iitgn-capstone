"""Open the whole v2 retrieval system from build directories (environment or arguments).

    TRE_STORE_DIR     C1 store build or root with LATEST
    TRE_LEXICAL_DIR   C2 lexical build (built with --attack)
    TRE_DENSE_DIR     C3 dense root with LATEST (or a build)
    TRE_ATTACK_DIR    C9 ATT&CK build or root with LATEST
    TRE_RERANKER_MODEL / TRE_RERANK_THREADS   C5 reranker (Hugging Face cache, offline)

Fusion settings are the ones tuned on dev in C3 (``FUSION``). ``make_v2`` is the factory of the benchmark
variant ``v2_full``; with ``TRE_V2_FEATURES_OUT`` set it appends each question's top-``features_depth`` signals to
that JSONL file (input of the calibrated confidence, C7).
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from ..dense.fusion import RRFConfig

FUSION = {"weights": (1.0, 0.35), "k": 2.0, "depth": 100}   # C3b: tuned on dev over the full bge-large index (results/dense/tuning/fusion-full.json)


def _attack_store(path=None):
    from ..attack.reader import AttackStore
    p = path or os.environ.get("TRE_ATTACK_DIR")
    if not p:
        from ..config import get_config
        p = get_config().attack_build_dir
    return AttackStore.open(p)


def rerank_weight_default() -> float:
    """`TRE_RERANK_WEIGHT`: blend weight of the reranker's order (0 = off, the default; inf = reranker alone)."""
    return float(os.environ.get("TRE_RERANK_WEIGHT", "0"))


def open_system(store=None, lexical=None, dense=None, attack=None, rerank: bool | None = None, rerank_depth: int = 10,
                fusion: dict | None = None, torch_threads: int | None = None, rerank_threads: int | None = None,
                rerank_weight: float | None = None):
    from ..dense.index import DenseIndex, default_root
    from ..dense.retriever import DenseRetriever
    from ..lexical import LexicalIndex
    from ..store import Store
    from .nicknames import NicknameRoute
    from .rerank import Int8Reranker
    from .retriever import V2Retriever
    from .texts import DocTexts
    st = Store.open(store)
    atk = _attack_store(attack)
    lex = LexicalIndex.open(lexical, verify=True)
    dpath = Path(dense) if dense else default_root()
    den = DenseRetriever(DenseIndex.open(dpath), torch_threads=torch_threads)
    f = dict(FUSION, **(fusion or {}))
    cfg = RRFConfig(weights=tuple(float(w) for w in f["weights"]), k=float(f["k"]), depth=int(f["depth"]))
    w = rerank_weight_default() if rerank_weight is None else float(rerank_weight)
    if rerank is False:
        w = 0.0
    rr = Int8Reranker.load(threads=rerank_threads) if w > 0 else None
    return V2Retriever(st, lex, den, cfg, reranker=rr, nicknames=NicknameRoute.from_store(st), attack_store=atk,
                       texts=DocTexts(st, atk), rerank_depth=rerank_depth, rerank_weight=w)


class V2System:
    """Benchmark adapter: ``search(text) -> [(doc_id, score)]`` with score = descending rank order."""

    def __init__(self, k: int = 100, rerank: bool | None = None, rerank_depth: int = 10, features_depth: int = 20,
                 rerank_weight: float | None = None,
                 lexical: str | None = None, dense: str | None = None, store: str | None = None,
                 attack: str | None = None, torch_threads: int | None = None, rerank_threads: int | None = None):
        if rerank and rerank_weight is None:
            rerank_weight = float("inf")      # variant v2_full: the reranker's order, as measured
        self.r = open_system(store, lexical, dense, attack, rerank=rerank, rerank_depth=rerank_depth,
                             torch_threads=torch_threads, rerank_threads=rerank_threads, rerank_weight=rerank_weight)
        self.k = int(k)
        self.features_depth = int(features_depth)
        out = os.environ.get("TRE_V2_FEATURES_OUT")
        self._fo = open(out, "a", encoding="utf-8") if out else None
        self._lock = threading.Lock()

    def search(self, text: str) -> list[tuple[str, float]]:
        res = self.r.retrieve(text, k=self.k)
        if self._fo is not None:
            rec = {"query": text, "skipped": res.skipped, "timings_ms": res.timings_ms,
                   "nicknames": res.nicknames, "cve_ids_in_query": res.cve_ids_in_query,
                   "hits": [{"doc_id": h.doc_id, "rank": h.rank, **h.features()} for h in res.hits[:self.features_depth]]}
            with self._lock:
                self._fo.write(json.dumps(rec) + "\n")
                self._fo.flush()
        n = len(res.hits)
        return [(h.doc_id, float(n - i)) for i, h in enumerate(res.hits)]

    def info(self) -> dict:
        return {"component": "v2_full", **self.r.info()}


def make_v2(**kw) -> V2System:
    return V2System(**kw)
