"""C1 document store: end-to-end build on a miniature feed set (reconciliation, joins, similar groups, aliases,
leakage guard, idempotent rebuild, read API)."""
import json
import sqlite3

import pytest

from threat_retrieval_engine.store import Store
from threat_retrieval_engine.store import aliases as A
from threat_retrieval_engine.store import build as B
from threat_retrieval_engine.store.text import alias_norm

from store_fixtures import make_feeds, make_sources


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("c1")
    feeds, sources = make_feeds(root), make_sources(root)
    out = B.build(feeds, sources, root / "store", workers=1, build_id="test-build", log=lambda m: None)
    return {"root": root, "feeds": feeds, "sources": sources, "dir": out}


@pytest.fixture()
def db(built):
    con = sqlite3.connect(built["dir"] / "store.sqlite")
    yield con
    con.close()


def manifest(built):
    return json.loads((built["dir"] / "manifest.json").read_text(encoding="utf-8"))


def test_one_row_per_cve_in_universe(db):
    ids = [r[0] for r in db.execute("SELECT cve_id FROM cve")]
    assert len(ids) == len(set(ids))
    assert set(ids) == {"CVE-2018-6116", "CVE-2018-0001", "CVE-2018-0002", "CVE-2018-0003", "CVE-2021-44228",
                        "CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004", "CVE-2021-0006",
                        "CVE-2021-0007"}


def test_states_and_searchable(db):
    st = dict(db.execute("SELECT cve_id, state || '/' || searchable FROM cve"))
    assert st["CVE-2018-0001"] == "rejected/0" and st["CVE-2021-0003"] == "rejected/0"
    assert st["CVE-2018-0002"] == "reserved/0"
    assert st["CVE-2021-0006"] == "published/0"   # EPSS-only: no description to search
    assert st["CVE-2021-44228"] == "published/1" and st["CVE-2021-0004"] == "published/1"


def test_reconciliation_zero_unexplained_and_reasons(built, db):
    rec = manifest(built)["reconciliation"]
    assert all(v["unexplained"] == 0 for v in rec.values()), rec
    assert rec["nvd"] == {"read": 9, "stored_or_merged": 8, "rejected": 1, "unexplained": 0}
    reasons = {(s, r) for s, _, r in db.execute("SELECT source, record_id, reason FROM rejected_records")}
    assert ("nvd", "duplicate_identical_record") in reasons
    assert ("cve_list", "unparseable_json") in reasons and ("cve_list", "not_a_cve_record_file") in reasons
    assert ("kev", "malformed_cve_id") in reasons and ("epss", "malformed_cve_id") in reasons
    assert ("exploitdb", "cve_not_in_universe") in reasons
    assert any(s == "exploitdb" and r.startswith("no_alias_accepted:") for s, r in reasons)  # generic-only title


def test_kev_without_nvd_and_epss_joins(db):
    kev, epss, src = db.execute("SELECT kev, epss, sources FROM cve WHERE cve_id = 'CVE-2021-0004'").fetchone()
    assert json.loads(kev)["vulnerability_name"] == "Acme Widget Server SQL Injection Vulnerability"
    assert json.loads(epss)["score"] == 0.12 and "nvd" not in src.split(",")
    n_epss = db.execute("SELECT COUNT(*) FROM cve WHERE epss IS NOT NULL").fetchone()[0]
    assert n_epss == 4
    sev = [e["severity"] for e in json.loads(db.execute(
        "SELECT cvss FROM cve WHERE cve_id = 'CVE-2021-44228'").fetchone()[0])]
    assert sorted(sev) == ["CRITICAL", "CRITICAL", "HIGH"]  # V2 HIGH kept as published, V3.1, V4.0


def test_vendor_product_platform_rule_end_to_end(db):
    vp = dict(db.execute("SELECT cve_id, vendor_product FROM cve"))
    assert vp["CVE-2018-6116"] == "Google Chrome"
    assert vp["CVE-2021-0001"] == "Example Gallery"
    assert vp["CVE-2021-0007"] == "Acme Corp Widget Server"
    assert all("_" not in v for v in vp.values() if v)


def test_similar_group_keeps_both_twins(db):
    g = dict(db.execute("SELECT cve_id, similar_group FROM cve"))
    assert g["CVE-2021-0001"] == g["CVE-2021-0002"] == "CVE-2021-0001"
    assert g["CVE-2021-44228"] is None


def test_dense_text_clean(db):
    for cid, d in db.execute("SELECT cve_id, dense_text FROM cve WHERE searchable = 1"):
        assert d and "CVE-" not in d and "Malware:" not in d and "Content:" not in d, (cid, d)
    assert db.execute("SELECT COUNT(*) FROM cve WHERE searchable = 0 AND dense_text IS NOT NULL").fetchone()[0] == 0


def test_aliases_from_allowed_sources_only(db):
    rows = db.execute("SELECT cve_id, alias, kind, source FROM aliases").fetchall()
    assert ("CVE-2021-44228", "Log4Shell", "nickname", "exploitdb") in rows
    assert {r[3] for r in rows} <= set(A.ALLOWED_SOURCES)
    assert not {r[3] for r in rows} & A.QUERY_SIDE_SOURCES
    assert not any("LeakedQueryName" in r[1] for r in rows)  # present only in the query-side fixture source
    assert db.execute("SELECT aliases FROM cve WHERE cve_id = 'CVE-2021-44228'").fetchone()[0] == "Log4Shell"


def test_weak_evidence_needs_corroboration(db):
    rows = db.execute("SELECT cve_id, alias, source FROM aliases WHERE kind = 'nickname'").fetchall()
    assert ("CVE-2021-44228", "Log4Shell", "poc_in_github") in {(c, a.title() if a.islower() else a, s)
                                                                 for c, a, s in rows}
    assert not any(alias_norm(a) == "widgetsmash" for _, a, _ in rows)  # two PoC owners: one family only
    assert not any(alias_norm(a) == "lonelyname" for _, a, _ in rows)   # one owner only
    reasons = dict(((s, r), n) for s, r, n in db.execute(
        "SELECT source, record_id, reason FROM rejected_records WHERE source = 'poc_in_github'"))
    assert reasons.get(("poc_in_github", "erin/CVE-2018-6116-Lonelyname")) == "no_corroborated_alias"
    assert reasons.get(("poc_in_github", "dave/widgetsmash")) == "no_alias_accepted:corpus_rules"


def test_query_side_source_directory_is_never_opened(built):
    with pytest.raises(ValueError):
        B.latest_source_dir(built["sources"], "ghsa_reviewed")


def test_reconciliation_failure_on_unexplained_record(built, monkeypatch, tmp_path):
    """A record that is read but neither stored nor rejected must fail the build."""
    monkeypatch.setattr(B, "pick_nvd", lambda recs: (max(recs, key=lambda r: r["index"]) if recs else None, []))
    with pytest.raises(B.ReconciliationError, match="nvd"):
        B.build(built["feeds"], built["sources"], tmp_path / "store", workers=1, build_id="bad", log=lambda m: None)
    assert not (tmp_path / "store" / "bad").exists()  # nothing published


def test_idempotent_rebuild_same_content_hashes(built, tmp_path):
    out2 = B.build(built["feeds"], built["sources"], tmp_path / "store2", workers=1, build_id="test-build",
                   log=lambda m: None, previous=built["dir"])
    a = dict(sqlite3.connect(built["dir"] / "store.sqlite").execute("SELECT cve_id, content_hash FROM cve"))
    b = dict(sqlite3.connect(out2 / "store.sqlite").execute("SELECT cve_id, content_hash FROM cve"))
    assert a == b
    ch = json.loads((out2 / "manifest.json").read_text(encoding="utf-8"))["changes_vs_previous"]
    assert ch["added"] == ch["changed"] == ch["removed"] == 0


def test_read_api(built):
    with Store.open(built["dir"].parent) as s:
        assert s.build_id == "test-build"
        r = s.get("cve-2021-44228")
        assert r["kev"]["listed"] is True and isinstance(r["cvss"], list)
        assert s.get("CVE-1999-9999") is None and s.get("not an id") is None
        ids = [x["cve_id"] for x in s.iter_searchable(columns=("cve_id", "dense_text"))]
        assert ids == sorted(ids) and len(ids) == s.count(searchable=True)
        assert ("CVE-2021-44228", "Log4Shell", "nickname", "exploitdb") in s.find_alias("log4shell")
        assert set(s.get_many(["CVE-2021-0001", "CVE-2021-0002"])) == {"CVE-2021-0001", "CVE-2021-0002"}
