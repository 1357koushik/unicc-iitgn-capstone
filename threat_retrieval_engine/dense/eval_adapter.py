"""Factories for the B4 harness's ``inprocess`` adapter (variants ``v2_dense*``, ``v2_fused*`` in variants.yaml).

``index`` is a dense build directory, or a root holding ``LATEST``; a relative path is resolved under
``$TRE_DENSE_DIR`` (default ``data/dense``), e.g. ``compare/bge-m3`` for a comparison build.
"""
from __future__ import annotations

from pathlib import Path

from .fusion import FusedRetriever, RRFConfig
from .index import DenseIndex, default_root
from .retriever import DenseRetriever


def _kinds(kinds: str):
    return None if kinds == "all" else tuple(x.strip() for x in kinds.split(","))


def _index_path(index: str | None) -> Path:
    if index is None:
        return default_root()
    p = Path(index)
    return p if p.is_absolute() or p.exists() else default_root() / p


class DenseSystem:
    def __init__(self, index: str | None = None, k: int = 100, kinds: str = "cve", query_format: str = "documented",
                 query_max_tokens: int | None = None, torch_threads: int | None = None, blas_threads: int | None = None):
        self.r = DenseRetriever(DenseIndex.open(_index_path(index)), query_format=query_format,
                                query_max_tokens=query_max_tokens, torch_threads=torch_threads,
                                blas_threads=blas_threads)
        self.k = int(k)
        self.kinds = _kinds(kinds)

    def search(self, text: str) -> list[tuple[str, float]]:
        return self.r.search(text, k=self.k, kinds=self.kinds).hits

    def info(self) -> dict:
        return {"component": "dense", "kinds": self.kinds or "all", **self.r.info()}


class FusedSystem:
    def __init__(self, lexical: str | None = None, index: str | None = None, k: int = 100, kinds: str = "cve",
                 weights: list[float] | None = None, rrf_k: float = 60.0, depth: int = 100, candidates: int = 100,
                 query_format: str = "documented", query_max_tokens: int | None = None,
                 torch_threads: int | None = None, blas_threads: int | None = None):
        from ..lexical import LexicalIndex
        self.lex = LexicalIndex.open(lexical, verify=True)
        self.dense = DenseRetriever(DenseIndex.open(_index_path(index)), query_format=query_format,
                                    query_max_tokens=query_max_tokens, torch_threads=torch_threads,
                                    blas_threads=blas_threads)
        self.cfg = RRFConfig(weights=tuple(float(w) for w in (weights or (1.0, 1.0))), k=float(rrf_k), depth=int(depth))
        self.f = FusedRetriever(self.lex, self.dense, self.cfg, candidates=int(candidates))
        self.k = int(k)
        self.kinds = _kinds(kinds)

    def search(self, text: str) -> list[tuple[str, float]]:
        return self.f.search(text, k=self.k, kinds=self.kinds).hits

    def info(self) -> dict:
        return {"component": "fused", "kinds": self.kinds or "all", "rrf": self.cfg.as_dict(),
                "candidates": self.f.candidates, "lexical": self.lex.info(), "dense": self.dense.info()}


def make_dense(**kw) -> DenseSystem:
    return DenseSystem(**kw)


def make_fused(**kw) -> FusedSystem:
    return FusedSystem(**kw)
