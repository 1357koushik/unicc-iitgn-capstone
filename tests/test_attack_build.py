"""C9 ATT&CK store: end-to-end build on a miniature STIX bundle and KEV mapping file against the miniature C1
store (reconciliation, identity, revocation, edges, CVE links, licence handling, read API)."""
import json
import sqlite3

import pytest

from threat_retrieval_engine.attack import AttackStore
from threat_retrieval_engine.attack import build as AB
from threat_retrieval_engine.attack.text import ATTACK_ID_IN_TEXT, clean_description
from threat_retrieval_engine.store import build as SB

from attack_fixtures import bundle, low_df_policy, make_attack_sources
from store_fixtures import make_feeds, make_sources


@pytest.fixture(scope="module")
def c1_store(tmp_path_factory):
    root = tmp_path_factory.mktemp("c1_for_c9")
    return SB.build(make_feeds(root), make_sources(root), root / "store", workers=1, build_id="c1-test",
                    log=lambda m: None)


@pytest.fixture(scope="module")
def built(tmp_path_factory, c1_store):
    root = tmp_path_factory.mktemp("c9")
    src = make_attack_sources(root)
    out = AB.build(src, c1_store, root / "attack", build_id="c9-test", log=lambda m: None, policy=low_df_policy())
    return {"root": root, "sources": src, "dir": out, "store": c1_store}


@pytest.fixture()
def db(built):
    con = sqlite3.connect(built["dir"] / "attack.sqlite")
    yield con
    con.close()


@pytest.fixture()
def a(built):
    s = AttackStore.open(built["dir"])
    yield s
    s.close()


def manifest(built):
    return json.loads((built["dir"] / "manifest.json").read_text(encoding="utf-8"))


def reasons(db, source):
    return dict(db.execute("SELECT record_id, reason FROM rejected WHERE source = ?", (source,)))


# ---------------------------------------------------------------------------- reconciliation and identity
def test_reconciliation_zero_unexplained(built, db):
    rec = manifest(built)["reconciliation"]
    assert all(v["unexplained"] == 0 for v in rec.values()), rec
    b = bundle()["objects"]
    assert rec["stix_objects"]["read"] == sum(1 for o in b if o["type"] != "relationship")
    assert rec["stix_relationships"]["read"] == sum(1 for o in b if o["type"] == "relationship")
    n_rej = dict(db.execute("SELECT source, COUNT(*) FROM rejected GROUP BY source"))
    assert n_rej["stix_object"] == rec["stix_objects"]["rejected"]
    assert n_rej["stix_relationship"] == rec["stix_relationships"]["rejected"]
    assert db.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == rec["stix_objects"]["stored"]
    assert db.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == rec["stix_relationships"]["stored"]


def test_object_rejection_reasons(db):
    r = reasons(db, "stix_object")
    assert r["course-of-action--legacy"] == "id_kind_mismatch"       # legacy mitigation reusing T1059
    assert r["malware--noid"] == "no_attack_id"
    assert r["x-mitre-tactic--exec"] == "type_not_ingested:x-mitre-tactic"
    assert r["x-mitre-detection-strategy--d1"] == "type_not_ingested:x-mitre-detection-strategy"
    assert r[bundle()["objects"][0]["id"]] == "type_not_ingested:marking-definition"


def test_doc_ids_kinds_and_states(a):
    t = a.get("attack:T1059")
    assert t["stix_type"] == "attack-pattern" and t["doc_kind"] == "technique"   # not the legacy mitigation
    assert a.get("S0154")["doc_kind"] == "software" and a.get("S0154")["software_type"] == "tool"
    assert a.get("S0046")["software_type"] == "malware"
    assert a.get("C0024")["doc_kind"] == "campaign" and a.get("C0024")["first_seen"].startswith("2019")
    assert a.get("M1042")["doc_kind"] == "mitigation"
    states = {d: a.brief(d)["state"] for d in ("G9001", "G9002", "T1086", "T9999", "S9005", "G0016")}
    assert states == {"G9001": "revoked", "G9002": "deprecated", "T1086": "revoked", "T9999": "deprecated",
                      "S9005": "revoked", "G0016": "active"}
    searchable = {r["doc_id"] for r in a.iter_searchable(columns=("doc_id",))}
    assert not searchable & {"attack:G9001", "attack:G9002", "attack:T1086", "attack:T9999", "attack:S9005"}
    assert "attack:G0016" in searchable and "attack:C0024" in searchable


def test_revoked_maps_to_replacement(a, db):
    assert a.get("T1086")["revoked_by"] == "attack:T1059.001"
    assert a.get("G9001")["revoked_by"] == "attack:G0016"
    assert a.get("S9005")["revoked_by"] == "attack:S0154"           # malware revoked by a tool
    r = a.resolve_id("T1086")
    assert r["doc_id"] == "attack:T1059.001" and r["resolved_from"] == "attack:T1086"
    assert a.resolve_id("T9999") is None                            # deprecated: no replacement
    assert a.resolve_id("t1059/001")["doc_id"] == "attack:T1059.001"
    assert db.execute("SELECT COUNT(*) FROM edges WHERE rel_type = 'revoked-by'").fetchone()[0] == 3


# ---------------------------------------------------------------------------- text fields
def test_text_fields_cleaned(a):
    g = a.get("G0016")
    assert g["title"] == "APT29" and g["aliases_list"] == ["Cozy Bear", "NOBELIUM"]   # "apt 29" folds into the name
    assert g["aliases"] == "Cozy Bear; NOBELIUM"
    d = g["description"]
    assert "(Citation" not in d and "](" not in d and "**" not in d and "nested" not in d and ") It" not in d
    assert d.startswith("APT29 is a threat group attributed to Russia's SVR.") and "VMware servers." in d
    assert "CVE-2021-44228" in d                                    # the stored description keeps IDs
    dense = g["dense_text"]
    assert dense.startswith("APT29. Cozy Bear, NOBELIUM. APT29 is")
    assert "CVE-" not in dense and not ATTACK_ID_IN_TEXT.search(dense)
    assert a.get("G0007")["description"] == "APT28 is a group."      # <code> removed
    sub = a.get("T1059.001")
    assert sub["title"] == "Command and Scripting Interpreter: PowerShell"
    assert sub["parent_doc_id"] == "attack:T1059" and sub["tactics"] == "Execution"
    assert sub["dense_text"].startswith("Command and Scripting Interpreter: PowerShell. Execution. ")
    assert "T1059" not in sub["dense_text"] and sub["description"].endswith("(T1059.001).")
    assert sub["tactics_list"] == [{"shortname": "execution", "name": "Execution", "attack_id": "TA0002"}]
    for row in a.iter_searchable(columns=("doc_id", "title", "dense_text", "content_hash")):
        assert row["title"] and row["dense_text"] and len(row["content_hash"]) == 64, row
    assert a.get("T1086")["dense_text"] is None                     # not searchable: no dense text


def test_clean_description_rules():
    s = ("[Cobalt Strike](https://attack.mitre.org/software/S0154) uses `cmd.exe`.(Citation: A (B) C)"
         "(Citation: D)\n\n* item one\n* item **two**\n[wiki](https://en.wikipedia.org/wiki/X_(y))")
    assert clean_description(s) == "Cobalt Strike uses cmd.exe. item one item two wiki"


# ---------------------------------------------------------------------------- graph
def test_edges_traceable_and_redirected(a, db):
    for e in a.iter_edges():
        assert e["rel_stix_id"].startswith("relationship--")
        assert a.brief(e["src_doc_id"])["attack_id"] == e["src_attack_id"]
        assert a.brief(e["dst_doc_id"])["attack_id"] == e["dst_attack_id"]
        if e["rel_type"] != "revoked-by":
            assert a.brief(e["src_doc_id"])["state"] == "active" and a.brief(e["dst_doc_id"])["state"] == "active"
    u5 = [e for e in a.edges("G0007") if e["rel_stix_id"] == "relationship--u5"][0]
    assert u5["dst_doc_id"] == "attack:T1059.001" and u5["orig_dst_doc_id"] == "attack:T1086"
    assert u5["redirected"] == "dst" and u5["description"] == "APT28 used PowerShell via CVE-2018-0001."
    r = reasons(db, "stix_relationship")
    assert r["relationship--u6"] == "duplicate_after_redirect"
    assert r["relationship--u7"] == "endpoint_deprecated" and r["relationship--u10"] == "endpoint_deprecated"
    assert r["relationship--m2"] == "endpoint_not_stored"
    assert r["relationship--d1"] == "endpoint_type_not_ingested:x-mitre-detection-strategy"
    assert r["relationship--x1"] == "dangling_reference"
    assert r["relationship--x2"] == "relationship_revoked" and r["relationship--x3"] == "relationship_deprecated"
    assert a.has_edge("C0024", "attributed-to", "G0016") and a.has_edge("T1059.001", "subtechnique-of", "T1059")
    assert {e["src_attack_id"] for e in a.edges("T1059.001", "in", "mitigates")} == {"M1042"}


# ---------------------------------------------------------------------------- CVE links
def test_cve_links_with_evidence(a, db):
    links = {(l["doc_id"], l["cve_id"], l["evidence_kind"], l["role"]) for l in
             a.cve_links("G0016") + a.cve_links("T1059.001") + a.cve_links("T1190")}
    assert ("attack:G0016", "CVE-2021-44228", "object_description", "self") in links
    assert ("attack:G0016", "CVE-2021-0004", "object_external_reference", "self") in links
    assert ("attack:G0016", "CVE-2018-6116", "relationship_description", "relationship_source") in links
    assert ("attack:T1059.001", "CVE-2018-6116", "relationship_description", "relationship_target") in links
    assert ("attack:G0016", "CVE-2021-0001", "relationship_external_reference", "relationship_source") in links
    assert ("attack:T1190", "CVE-2021-44228", "kev_mapping", "mapped_technique") in links
    kev_rev = [l for l in a.cve_links("T1059.001") if l["evidence_kind"] == "kev_mapping"]
    assert kev_rev and kev_rev[0]["detail"]["redirected_from"] == "attack:T1086"
    assert kev_rev[0]["detail"]["mapping_type"] == "primary_impact"
    snippet = [l for l in a.cve_links("G0016") if l["evidence_kind"] == "object_description"][0]["detail"]["snippet"]
    assert "CVE-2021-44228" in snippet
    r = reasons(db, "cve_link")
    assert any(k.endswith("|CVE-2030-9999") and v == "cve_not_in_store" for k, v in r.items())
    assert any(k.endswith("|CVE-2018-0001") and v == "cve_not_searchable_in_store" for k, v in r.items())
    assert any(k.endswith("|CVE-2021-0002") and v == "relationship_not_stored" for k, v in r.items())
    k = reasons(db, "kev_mapping")
    assert k["CVE-2021-0004|T9999|primary_impact"] == "technique_deprecated"
    assert k["CVE-2030-0001|T1190|exploitation_technique"] == "cve_not_in_store"
    assert k["CVE-2021-0004|T1234|secondary_impact"] == "technique_not_in_build"
    assert k["CVE-2021-44228|T1190|exploitation_technique#2"] == "duplicate_mapping"
    assert k["CVE-2018-0001|T1190|exploitation_technique"] == "cve_not_searchable_in_store"
    # every stored link names a searchable document and a CVE searchable in the C1 store
    from threat_retrieval_engine.store import Store
    with Store.open(a.manifest["inputs"]["c1_store"]["dir"]) as s:
        for doc_id, cve in db.execute("SELECT doc_id, cve_id FROM cve_links"):
            assert a.brief(doc_id)["searchable"] == 1
            assert s.get(cve, columns=("searchable",))["searchable"] == 1
    assert [d["doc_id"] for d in a.docs_for_cve("cve-2021-44228")].count("attack:G0016") == 1


# ---------------------------------------------------------------------------- manifest, licence, inputs
def test_manifest_records_inputs_and_counts(built, a):
    m = manifest(built)
    assert m["build_id"] == "c9-test" == a.build_id and a.attack_version == "20.1"
    assert len(m["inputs"]["attack_enterprise"]["sha256"]) == 64 and m["inputs"]["kev_attack_mappings"]["ingested"]
    assert m["inputs"]["c1_store"]["build_id"] == "c1-test" == a.c1_store_build_id
    assert "git_commit" in m["code"] and m["copyright_notice"].startswith("Copyright The MITRE Corporation")
    assert m["report"]["objects_by_kind_state"]["technique/revoked"] == 1
    assert m["report"]["edges_by_type"]["uses"] == 6 and m["timings"]["total_s"] >= 0
    assert (built["dir"].parent / "LATEST").read_text().strip() == "c9-test"


def test_kev_not_ingested_when_licence_not_accepted(tmp_path, c1_store):
    src = make_attack_sources(tmp_path, kev_licence="Proprietary, no redistribution")
    out = AB.build(src, c1_store, tmp_path / "attack", build_id="c9-nolic", log=lambda m: None,
                   policy=low_df_policy())
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert m["inputs"]["kev_attack_mappings"]["ingested"] is False
    assert "not in the accepted list" in m["inputs"]["kev_attack_mappings"]["licence_decision"]
    assert m["reconciliation"]["kev_mappings"]["read"] == 0
    con = sqlite3.connect(out / "attack.sqlite")
    assert con.execute("SELECT COUNT(*) FROM cve_links WHERE evidence_kind = 'kev_mapping'").fetchone()[0] == 0
    con.close()


def test_hash_mismatch_fails_and_leaves_no_build(tmp_path, c1_store):
    src = make_attack_sources(tmp_path)
    p = src / "attack_enterprise" / "2026-11-14" / "raw" / "enterprise-attack.json"
    p.write_bytes(p.read_bytes() + b" ")
    with pytest.raises(AB.SourceError):
        AB.build(src, c1_store, tmp_path / "attack", build_id="bad", log=lambda m: None)
    assert not (tmp_path / "attack" / "bad").exists()


def test_rebuild_is_deterministic(tmp_path, built, c1_store):
    out = AB.build(built["sources"], c1_store, tmp_path / "attack", build_id="again", log=lambda m: None,
                   policy=low_df_policy())
    q = "SELECT * FROM {} ORDER BY 1, 2"
    one, two = sqlite3.connect(built["dir"] / "attack.sqlite"), sqlite3.connect(out / "attack.sqlite")
    for t in ("objects", "edges", "cve_links", "gazetteer", "gazetteer_keys", "rejected"):
        assert one.execute(q.format(t)).fetchall() == two.execute(q.format(t)).fetchall(), t
    one.close()
    two.close()
