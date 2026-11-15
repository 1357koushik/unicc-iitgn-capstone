"""C2: user text can never reach FTS5 as query syntax (plan 5.1 input hardening)."""
from __future__ import annotations

import json
import random
import time

import pytest

from threat_retrieval_engine.lexical import LexicalIndex
from threat_retrieval_engine.lexical import build as LB
from threat_retrieval_engine.lexical.fuzz import fuzz_queries, run_fuzz
from threat_retrieval_engine.lexical.index import _quote

from test_lexical_index import ListSource, synthetic_docs


@pytest.fixture(scope="module")
def ix(tmp_path_factory):
    root = tmp_path_factory.mktemp("c2safe")
    bdir = root / "b"
    bdir.mkdir()
    LB.build_index([ListSource(synthetic_docs(200))], bdir / "lexical.sqlite", workers=1, progress=lambda m: None)
    (bdir / "manifest.json").write_text(json.dumps({"tokenizer": LB.TOKENIZER.as_dict(), "ranking": LB.RANKING.with_(max_df_ratio=1.0).as_dict()}))
    with LexicalIndex.open(bdir) as i:
        yield i


HOSTILE = [
    '"', '""', '"""', "'", "a\"b", 'overflow"', '"overflow', 'NEAR(overflow remote, 2)', "NEAR", "overflow NEAR remote",
    "title: overflow", "{title description}: overflow", "- overflow", "+overflow", "overflow*", "*", "^overflow",
    "^", "(", ")", "(((overflow", "overflow)))", "overflow AND", "AND OR NOT", "NOT overflow", "overflow NOT remote",
    "overflow OR", "OR", "a:b:c", "lex: overflow", "rank:bm25", "rowid:1", "* OR *", "\x00overflow\x00", "\\",
    "overflow; DROP TABLE lex; --", "') OR 1=1 --", "‮‭ overflow", "﻿overflow", "\u0000",
    "漏洞 переполнение हिन्दी", "😀😀 overflow 😀", "\t\n\r overflow \v\f", " " * 5000, "a" * 100_000,
    "overflow " * 20_000, "-".join(["x"] * 5000), ".".join(["1"] * 5000), "/" * 10_000, "_" * 10_000,
]


@pytest.mark.parametrize("text", HOSTILE, ids=[f"h{i}" for i in range(len(HOSTILE))])
def test_hostile_inputs_are_safe(ix, text):
    t0 = time.perf_counter()
    res = ix.search(text, k=10)
    assert time.perf_counter() - t0 < 5.0
    if res.query.match is not None:
        parts = res.query.match.split(" OR ")
        assert all(p.startswith('"') and p.endswith('"') and '"' not in p[1:-1] for p in parts)


def test_empty_and_none(ix):
    for text in ("", None, "   ", "!!!", "the of and"):
        res = ix.search(text)
        assert res.hits == [] and res.query.match is None


def test_operators_are_plain_terms(ix):
    q = ix.build_query("overflow NEAR remote AND NOT execution", ix.ranking.with_(stop_words="none"))
    assert q.terms and all(t == t.lower() for t in q.terms)  # case-folded: AND/OR/NOT/NEAR are never operators


def test_long_input_is_cut(ix):
    res = ix.search("overflow " + "remote " * 50_000)
    assert res.query.truncated
    assert len(res.query.terms) <= ix.ranking.max_terms


def test_quote_refuses_invalid_term():
    for bad in ('a"b', "a b", "(", "-a", ""):
        with pytest.raises(ValueError):
            _quote(bad)


def test_fuzz_corpus_no_error(ix):
    qs = fuzz_queries(2000, seed=5)
    assert len(qs) == 2000
    rep = run_fuzz(ix, qs, per_query_limit_s=2.0)
    assert rep["errors"] == [] and rep["slow"] == [], rep
