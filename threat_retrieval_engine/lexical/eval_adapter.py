"""Factory for the B4 harness's ``inprocess`` adapter (variant ``v2_lexical`` in variants.yaml)."""
from __future__ import annotations

from .config import RankingConfig
from .index import LexicalIndex


class LexicalSystem:
    def __init__(self, index: str | None = None, k: int = 100, ranking: dict | None = None):
        self.ix = LexicalIndex.open(index, ranking=RankingConfig.from_dict(ranking) if ranking else None, verify=True)
        self.k = int(k)

    def search(self, text: str) -> list[tuple[str, float]]:
        return self.ix.search(text, k=self.k).hits

    def info(self) -> dict:
        return {"component": "lexical", **self.ix.info()}


def make(index: str | None = None, k: int = 100, ranking: dict | None = None) -> LexicalSystem:
    return LexicalSystem(index=index, k=k, ranking=ranking)
