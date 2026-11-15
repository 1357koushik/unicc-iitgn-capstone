"""Factory for the B4 harness's ``inprocess`` adapter (variants ``v2_lexical`` and ``v2_lexical_attack``)."""
from __future__ import annotations

from .index import LexicalIndex


class LexicalSystem:
    def __init__(self, index: str | None = None, k: int = 100, kinds: str = "cve"):
        self.ix = LexicalIndex.open(index, verify=True)
        self.k = int(k)
        self.kinds = None if kinds == "all" else tuple(x.strip() for x in kinds.split(","))

    def search(self, text: str) -> list[tuple[str, float]]:
        return self.ix.search(text, k=self.k, kinds=self.kinds).hits

    def info(self) -> dict:
        return {"component": "lexical", "kinds": self.kinds or "all", **self.ix.info()}


def make(index: str | None = None, k: int = 100, kinds: str = "cve") -> LexicalSystem:
    return LexicalSystem(index=index, k=k, kinds=kinds)
