"""Reciprocal Rank Fusion: formula, depth, weights, deterministic tie-break, input validation."""
from __future__ import annotations

import random

import pytest

from threat_retrieval_engine.dense.fusion import FusedRetriever, RRFConfig, rrf


def test_formula_and_depth():
    a = ["d1", "d2", "d3"]
    b = ["d3", "d4"]
    out = dict(rrf([a, b], RRFConfig(weights=(1.0, 2.0), k=10, depth=100)))
    assert out["d1"] == pytest.approx(1 / 11)
    assert out["d3"] == pytest.approx(1 / 13 + 2 / 11)
    assert out["d4"] == pytest.approx(2 / 12)
    shallow = dict(rrf([a, b], RRFConfig(weights=(1.0, 1.0), k=10, depth=1)))
    assert set(shallow) == {"d1", "d3"}


def test_weight_zero_and_order():
    a = ["x", "y"]
    b = ["y", "z"]
    assert [d for d, _ in rrf([a, b], RRFConfig(weights=(1.0, 0.0), k=60))] == ["x", "y", "z"]
    # equal scores: the document with the better best rank first, then the earlier list, then doc_id
    out = rrf([["p", "q"], ["q", "p"]], RRFConfig(weights=(1.0, 1.0), k=60))
    assert [d for d, _ in out] == ["p", "q"]
    out = rrf([["b"], ["a"]], RRFConfig(weights=(1.0, 1.0), k=60))
    assert [d for d, _ in out] == ["b", "a"]
    out = rrf([["b", "a"], []], RRFConfig(weights=(1.0, 1.0), k=0))
    assert [d for d, _ in out] == ["b", "a"]


def test_duplicates_and_limit():
    out = rrf([["a", "a", "b"], ["b"]], RRFConfig(weights=(1.0, 1.0), k=1))
    assert dict(out)["a"] == pytest.approx(1 / 2) and dict(out)["b"] == pytest.approx(1 / 4 + 1 / 2)
    assert len(rrf([list("abcdef"), list("ghij")], RRFConfig(), limit=3)) == 3


def test_deterministic_under_shuffled_construction():
    rnd = random.Random(4)
    docs = [f"d{i}" for i in range(300)]
    l1 = rnd.sample(docs, 100)
    l2 = rnd.sample(docs, 100)
    ref = rrf([l1, l2], RRFConfig(weights=(1.0, 1.3), k=40, depth=60))
    for _ in range(5):
        assert rrf([list(l1), list(l2)], RRFConfig(weights=(1.0, 1.3), k=40, depth=60)) == ref
    scores = [s for _, s in ref]
    assert scores == sorted(scores, reverse=True)


def test_config_validation():
    for bad in [dict(weights=()), dict(weights=(-1.0, 1.0)), dict(weights=(0.0, 0.0)), dict(k=-1),
                dict(depth=0), dict(depth=1.5), dict(weights=(float("nan"), 1.0))]:
        with pytest.raises(ValueError):
            RRFConfig(**bad)
    with pytest.raises(ValueError):
        rrf([["a"]], RRFConfig(weights=(1.0, 1.0)))


class _Fake:
    def __init__(self, hits):
        self.hits = hits

    def search(self, text, k=100, kinds=None):
        class R:
            pass
        r = R()
        r.hits = self.hits[:k]
        r.timings_ms = {"encode": 1.0, "search": 2.0}
        return r


def test_fused_retriever():
    lex = _Fake([("a", 9.0), ("b", 8.0), ("c", 1.0)])
    den = _Fake([("c", 0.9), ("a", 0.8)])
    f = FusedRetriever(lex, den, RRFConfig(weights=(1.0, 1.0), k=60, depth=100), candidates=100)
    res = f.search("q", k=2)
    assert [d for d, _ in res.hits] == ["a", "c"]
    assert set(res.timings_ms) == {"lexical", "dense_encode", "dense_search", "fuse", "total"}
    with pytest.raises(ValueError):
        FusedRetriever(lex, den, RRFConfig(depth=100), candidates=50)
