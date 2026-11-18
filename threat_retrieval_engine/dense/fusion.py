"""Weighted Reciprocal Rank Fusion (Cormack et al. 2009) of ranked candidate lists; reusable by the pipeline (C6).

    from threat_retrieval_engine.dense.fusion import RRFConfig, rrf
    fused = rrf([lexical_ids, dense_ids], RRFConfig(weights=(1.0, 1.2), k=60, depth=100))

score(d) = sum over lists i of  w_i / (k + rank_i(d))  for the lists where d is ranked within the first
``depth`` positions (rank 1-based). Ties are broken by the best (smallest) rank the document has in any list,
then by the list order (a document from an earlier list first), then by doc_id, so the result is a
deterministic function of the input lists. The fused score is a ranking device only, never a confidence
(plan 3.1 row 3).

``FusedRetriever`` runs the C2 lexical index and the C3 dense retriever for one query (``candidates`` per list,
plan 4.5: 100) and fuses them; ``timings_ms`` reports each stage.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Iterable, Sequence


@dataclass(frozen=True)
class RRFConfig:
    weights: tuple[float, ...] = (1.0, 1.0)
    k: float = 60.0
    depth: int = 100

    def __post_init__(self):
        if not self.weights or any((not isinstance(w, (int, float))) or w < 0 or w != w for w in self.weights):
            raise ValueError("weights must be non-negative numbers")
        if not any(w > 0 for w in self.weights):
            raise ValueError("at least one weight must be positive")
        if not (isinstance(self.k, (int, float)) and self.k >= 0 and self.k == self.k):
            raise ValueError("k must be a non-negative number")
        if not isinstance(self.depth, int) or self.depth < 1:
            raise ValueError("depth must be a positive integer")

    def as_dict(self) -> dict:
        d = asdict(self)
        d["weights"] = list(self.weights)
        return d


def rrf(lists: Sequence[Sequence[str]], cfg: RRFConfig = RRFConfig(), limit: int | None = None
        ) -> list[tuple[str, float]]:
    if len(lists) != len(cfg.weights):
        raise ValueError(f"{len(lists)} lists for {len(cfg.weights)} weights")
    score: dict[str, float] = {}
    best: dict[str, tuple[int, int]] = {}
    for li, (docs, w) in enumerate(zip(lists, cfg.weights)):
        seen = set()
        for r, d in enumerate(docs[: cfg.depth], 1):
            if d in seen:  # a list names a document once; later repeats are ignored
                continue
            seen.add(d)
            score[d] = score.get(d, 0.0) + w / (cfg.k + r)
            b = best.get(d)
            if b is None or (r, li) < b:
                best[d] = (r, li)
    out = sorted(score.items(), key=lambda x: (-x[1], best[x[0]][0], best[x[0]][1], x[0]))
    return out[:limit] if limit else out


@dataclass
class FusedResult:
    hits: list[tuple[str, float]]
    lists: dict[str, list[tuple[str, float]]]
    timings_ms: dict[str, float] = field(default_factory=dict)


class FusedRetriever:
    """Lexical (C2) + dense (C3) candidates fused by RRF, in this order (weights follow it)."""

    def __init__(self, lexical, dense, cfg: RRFConfig, candidates: int = 100):
        if candidates < cfg.depth:
            raise ValueError("candidates per list must be at least the fusion depth")
        self.lexical = lexical
        self.dense = dense
        self.cfg = cfg
        self.candidates = int(candidates)

    def search(self, text: str, k: int = 100, kinds: Iterable[str] | None = ("cve",)) -> FusedResult:
        t0 = time.perf_counter()
        lex = self.lexical.search(text, k=self.candidates, kinds=kinds)
        t1 = time.perf_counter()
        den = self.dense.search(text, k=self.candidates, kinds=kinds)
        t2 = time.perf_counter()
        fused = rrf([[d for d, _ in lex.hits], [d for d, _ in den.hits]], self.cfg, limit=k)
        t3 = time.perf_counter()
        return FusedResult(fused, {"lexical": lex.hits, "dense": den.hits},
                           {"lexical": (t1 - t0) * 1000, "dense_encode": den.timings_ms["encode"],
                            "dense_search": den.timings_ms["search"], "fuse": (t3 - t2) * 1000,
                            "total": (t3 - t0) * 1000})
