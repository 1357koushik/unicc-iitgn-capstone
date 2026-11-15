"""C2 lexical index: build, determinism, identity of tokenization, ranking, MaxScore exactness, document
kinds, and the end-to-end build from a C1 fixture store."""
from __future__ import annotations

import json
import random
import sqlite3

import pytest

from threat_retrieval_engine.lexical import COLUMNS, LexicalIndex, RankingConfig
from threat_retrieval_engine.lexical import build as LB
from threat_retrieval_engine.lexical.schema import KIND_RANGES, cve_id_from_rowid, cve_rowid
from threat_retrieval_engine.lexical.sources import RowSource
from threat_retrieval_engine.store import build as SB

from store_fixtures import make_feeds, make_sources

WORDS = ("remote code execution buffer overflow cross site scripting sql injection denial service privilege "
         "escalation authentication bypass memory corruption path traversal deserialization arbitrary file "
         "upload crafted request attacker allows vulnerability plugin server kernel driver firmware router "
         "apache nginx openssl windows linux android chrome firefox wordpress").split()


class ListSource:
    kind = "cve"

    def __init__(self, docs):
        self.docs = sorted(docs)

    def describe(self):
        return {"kind": "cve", "fixture": len(self.docs)}

    def count(self):
        return len(self.docs)

    def iter_documents(self):
        for did, cols in self.docs:
            yield did, dict(cols)


def synthetic_docs(n=400, seed=3):
    rnd = random.Random(seed)
    docs = []
    for i in range(n):
        cid = f"CVE-2020-{1000 + i}"
        desc = " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(8, 40)))
        cols = {"ids": cid, "title": " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(0, 6))),
                "description": desc, "vendor_product": rnd.choice(["Apache HTTP Server", "OpenSSL", "Linux Kernel"]),
                "weakness": rnd.choice(["CWE-79 Cross-site Scripting", "CWE-89 SQL Injection", ""]),
                "aliases": "", "kev_text": "", "exploit_titles": ""}
        docs.append((cid, cols))
    docs.append(("CVE-2021-44228", {"ids": "CVE-2021-44228", "title": "Apache Log4j2 JNDI lookup",
                                    "aliases": "Log4Shell", "description": "Apache Log4j2 2.0-beta9 through 2.15.0 "
                                    "JNDI features allow remote code execution", "vendor_product": "Apache log4j"}))
    docs.append(("CVE-2021-45046", {"ids": "CVE-2021-45046", "description": "The fix to address CVE-2021-44228 in "
                                    "Apache Log4j 2.15.0 was incomplete; CVE-2021-44228 CVE-2021-44228"}))
    return docs


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("c2")
    bdir = root / "build"
    bdir.mkdir()
    info = LB.build_index([ListSource(synthetic_docs())], bdir / "lexical.sqlite", workers=1, progress=lambda m: None)
    (bdir / "manifest.json").write_text(json.dumps({
        "build_id": "fixture", "tokenizer": {**LB.TOKENIZER.as_dict()}, "ranking": LB.RANKING.with_(max_df_ratio=1.0).as_dict()}))
    return {"root": root, "dir": bdir, "info": info}


@pytest.fixture()
def ix(built):
    with LexicalIndex.open(built["dir"], verify=True) as i:
        yield i


def test_counts_and_identity_check(built, ix):
    assert ix.count() == ix.n_docs == 402
    assert built["info"]["identity_check"]["mismatches"] == 0
    assert tuple(json.loads(ix.meta["impact_weights"])) == tuple(LB.RANKING.weights)
    assert info_nnz(built) == len(ix.data) and ix.memory_bytes() > 0


def info_nnz(built):
    return built["info"]["impact"]["nnz"]


def test_rebuild_is_byte_identical(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a, b = tmp_path / "a" / "lexical.sqlite", tmp_path / "b" / "lexical.sqlite"
    ia = LB.build_index([ListSource(synthetic_docs())], a, workers=1, progress=lambda m: None)
    ib = LB.build_index([ListSource(synthetic_docs())], b, workers=2, progress=lambda m: None)
    assert LB.sha256_file(a) == LB.sha256_file(b)
    assert ia["impact"]["sha256"] == ib["impact"]["sha256"]


def test_identity_check_rejects_a_foreign_tokenizer(tmp_path, monkeypatch):
    """If FTS5 split tokens differently from the domain tokenizer the build must fail."""
    monkeypatch.setattr(LB, "fts5_tokenize_option", lambda: "ascii")  # '-' '.' '/' '_' become separators
    with pytest.raises(LB.BuildError, match="tokenization differs"):
        LB.build_index([ListSource(synthetic_docs(20))], tmp_path / "x.sqlite", workers=1, progress=lambda m: None)


def test_rowid_scheme_round_trip():
    for cid in ("CVE-1999-0001", "CVE-2021-44228", "CVE-2024-1234567", "CVE-2014-0160"):
        assert cve_id_from_rowid(cve_rowid(cid)) == cid
        assert KIND_RANGES["cve"][0] <= cve_rowid(cid) <= KIND_RANGES["cve"][1]


def test_identifier_ranks_own_document_first(ix):
    hits = ix.search("CVE-2021-44228", k=5).hits
    assert hits[0][0] == "CVE-2021-44228"


def test_alias_and_version_match(ix):
    assert ix.search("log4shell", k=3).hits[0][0] == "CVE-2021-44228"
    assert {d for d, _ in ix.search("log4j 2.15.0", k=2).hits} == {"CVE-2021-44228", "CVE-2021-45046"}


def test_document_level_unique_and_ordered(ix):
    res = ix.search("remote code execution apache overflow", k=100)
    ids = [d for d, _ in res.hits]
    assert len(ids) == len(set(ids))
    scores = [s for _, s in res.hits]
    assert scores == sorted(scores, reverse=True)


def test_deterministic_order(ix):
    a = ix.search("sql injection plugin", k=50).hits
    b = ix.search("sql injection plugin", k=50).hits
    assert a == b


def test_impact_matrix_equals_fts5_bm25(ix):
    """Same documents in the same order, scores equal within 1e-5 relative, for random queries, every k and both
    kind filters, against the plain FTS5 query with the build's weights."""
    rnd = random.Random(11)
    for _ in range(300):
        q = " ".join(rnd.choice(WORDS + ["log4j", "2.15.0", "CVE-2021-44228", "jndi"]) for _ in range(rnd.randint(1, 14)))
        for k in (1, 5, 50, 1000):
            a = ix.search(q, k=k).hits
            b = ix.search_fts5(q, k=k).hits
            assert [d for d, _ in a] == [d for d, _ in b], q
            assert all(abs(x - y) <= 1e-5 * max(abs(y), 1e-12) for (_, x), (_, y) in zip(a, b)), q


def test_ranking_weights_must_match_the_matrix(built):
    with pytest.raises(RuntimeError, match="impact"):
        LexicalIndex.open(built["dir"], ranking=RankingConfig(weights=tuple([1.0] * len(COLUMNS))))


def test_zero_weight_refused_at_build(tmp_path):
    with pytest.raises(LB.BuildError, match="positive"):
        LB.build_index([ListSource(synthetic_docs(5))], tmp_path / "z.sqlite", workers=1, progress=lambda m: None,
                       ranking=RankingConfig(weights=tuple([1.0] * (len(COLUMNS) - 1) + [0.0])))


def test_bm25_weights_change_ranking(ix):
    only_title = RankingConfig(weights=tuple(1.0 if c == "title" else 0.0 for c in COLUMNS))
    res = ix.search_fts5("jndi", k=3, ranking=only_title)
    assert res.hits[0][0] == "CVE-2021-44228"


def test_stop_words_and_unknown_terms_dropped(ix):
    q = ix.build_query("what is the zzzunknownzzz overflow")
    assert q.terms == ["overflow"]
    assert "what" in q.dropped["stop_word"] and "zzzunknownzzz" in q.dropped["not_in_index"]
    q2 = ix.build_query("the overflow", ix.ranking.with_(stop_words="none"))
    assert q2.terms == ["the", "overflow"]  # "the" occurs in one fixture document
    assert ix.build_query("the of and").match is None


def test_max_terms_keeps_rarest(ix):
    r = ix.ranking.with_(max_terms=2)
    q = ix.build_query("log4shell jndi remote code execution vulnerability", r)
    assert len(q.terms) == 2 and "log4shell" in q.terms
    assert q.dropped["over_max_terms"]


def test_ranking_config_validation():
    with pytest.raises(ValueError):
        RankingConfig(weights=(1.0,))
    with pytest.raises(ValueError):
        RankingConfig(weights=tuple([0.0] * len(COLUMNS)))
    with pytest.raises(ValueError):
        RankingConfig(weights=tuple([float("nan")] + [1.0] * (len(COLUMNS) - 1)))
    with pytest.raises(ValueError):
        RankingConfig(stop_words="french")
    r = RankingConfig()
    assert RankingConfig.from_dict(r.as_dict()) == r


def test_search_argument_validation(ix):
    for k in (0, -1, 1.5, True):
        with pytest.raises(ValueError):
            ix.search("x", k=k)
    with pytest.raises(ValueError):
        ix.search("overflow", kinds=("nope",))


def test_refuses_mismatched_tokenizer(built, tmp_path):
    import shutil
    d = tmp_path / "b"
    shutil.copytree(built["dir"], d)
    m = json.loads((d / "manifest.json").read_text())
    m["tokenizer"]["stemmer"] = "none"
    (d / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(RuntimeError, match="tokenizer"):
        LexicalIndex.open(d)


def test_attack_kind_through_row_source(tmp_path):
    rows = [{"doc_id": "attack:G0032", "title": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Guardians of Peace"],
             "description": "North Korean state-sponsored threat group", "dense_text": "ignored"},
            {"doc_id": "attack:S0334", "title": "DarkComet", "aliases": ["DarkKomet"], "description": "remote access tool"}]
    src = RowSource("attack", lambda: rows, {"title": "title", "aliases": "aliases", "description": "description"})
    bdir = tmp_path / "bd"
    bdir.mkdir()
    LB.build_index([ListSource(synthetic_docs(30)), src], bdir / "lexical.sqlite", workers=1, progress=lambda m: None)
    (bdir / "manifest.json").write_text(json.dumps({"tokenizer": LB.TOKENIZER.as_dict(), "ranking": LB.RANKING.with_(max_df_ratio=1.0).as_dict()}))
    with LexicalIndex.open(bdir, verify=True) as ix:
        assert ix.count("attack") == 2
        assert ix.search("hidden cobra", kinds=("attack",)).hits[0][0] == "attack:G0032"
        assert ix.search("G0032", kinds=None).hits[0][0] == "attack:G0032"
        assert ix.search("hidden cobra").hits == []  # default: CVE documents only
        assert all(d.startswith("CVE-") for d, _ in ix.search("remote access tool code").hits)
        assert any(d == "attack:S0334" for d, _ in ix.search("remote access tool", kinds=None).hits)
        for q in ("remote access tool", "hidden cobra code", "G0032 overflow"):
            for kinds in (None, ("attack",), ("cve",)):
                assert [d for d, _ in ix.search(q, kinds=kinds).hits] == \
                    [d for d, _ in ix.search_fts5(q, kinds=kinds).hits]


def test_attack_sqlite_reader(tmp_path):
    import sqlite3 as sq
    from threat_retrieval_engine.lexical.sources import AttackSqliteReader
    d = tmp_path / "attack" / "b1"
    d.mkdir(parents=True)
    (tmp_path / "attack" / "LATEST").write_text("b1")
    db = sq.connect(d / "attack.sqlite")
    db.execute("CREATE TABLE meta (key TEXT, value TEXT)")
    db.execute("INSERT INTO meta VALUES ('build_id', 'b1')")
    db.execute("CREATE TABLE objects (doc_id TEXT, title TEXT, aliases TEXT, description TEXT, state TEXT, "
               "searchable INTEGER)")
    db.executemany("INSERT INTO objects VALUES (?,?,?,?,?,?)", [
        ("attack:G0032", "Lazarus Group", '["HIDDEN COBRA"]', "North Korean group", "active", 1),
        ("attack:G9999", "Old", None, "revoked", "revoked", 0)])
    db.commit()
    db.close()
    rows = list(AttackSqliteReader(tmp_path / "attack").iter_searchable())
    assert rows == [{"doc_id": "attack:G0032", "title": "Lazarus Group", "aliases": ["HIDDEN COBRA"],
                     "description": "North Korean group"}]


def test_end_to_end_from_c1_fixture_store(tmp_path):
    feeds, sources = make_feeds(tmp_path), make_sources(tmp_path)
    store_dir = SB.build(feeds, sources, tmp_path / "store", workers=1, build_id="test-build", log=lambda m: None)
    out = LB.build(store_dir, tmp_path / "lexical", workers=1, progress=lambda m: None)
    m = json.loads((out / "manifest.json").read_text())
    con = sqlite3.connect(store_dir / "store.sqlite")
    searchable = con.execute("SELECT COUNT(*) FROM cve WHERE searchable = 1").fetchone()[0]
    con.close()
    assert m["counts"]["documents"]["cve"] == searchable
    assert m["inputs"][0]["store_build_id"] == "test-build"
    assert m["index_sha256"] == LB.sha256_file(out / "lexical.sqlite")
    with LexicalIndex.open(tmp_path / "lexical", verify=True) as ix:  # via LATEST
        assert ix.count("cve") == searchable
        assert ix.build_id == out.name
    out2 = LB.build(store_dir, tmp_path / "lexical2", workers=1, progress=lambda m: None)
    m2 = json.loads((out2 / "manifest.json").read_text())
    assert m2["index_sha256"] == m["index_sha256"] and m2["documents_sha256"] == m["documents_sha256"]
