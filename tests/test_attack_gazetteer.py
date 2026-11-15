"""C9 entity-name gazetteer: exact lookup, ambiguity, qualified and revoked names, token alignment, the
short/common-word policy (stored as data and applied by the matcher) and ID mentions."""
import pytest

from threat_retrieval_engine.attack import AttackStore
from threat_retrieval_engine.attack import build as AB
from threat_retrieval_engine.attack.gazetteer import POLICY, Gazetteer, assign_policy, corpus_df
from threat_retrieval_engine.store import build as SB

from attack_fixtures import low_df_policy, make_attack_sources
from store_fixtures import make_feeds, make_sources


@pytest.fixture(scope="module")
def a(tmp_path_factory):
    root = tmp_path_factory.mktemp("c9g")
    store = SB.build(make_feeds(root), make_sources(root), root / "store", workers=1, build_id="c1-g",
                     log=lambda m: None)
    out = AB.build(make_attack_sources(root), store, root / "attack", build_id="c9-g", log=lambda m: None,
                   policy=low_df_policy())
    s = AttackStore.open(out)
    yield s
    s.close()


@pytest.fixture()
def g(a) -> Gazetteer:
    return a.gazetteer()


def ids(mentions):
    return [(m.text, m.doc_ids, m.matched_by) for m in mentions]


# ---------------------------------------------------------------------------- exact lookup
def test_find_name_exact_and_ambiguous(a):
    r = a.find_name("cozy bear")
    assert {(x["doc_id"], x["doc_kind"]) for x in r} == {("attack:G0016", "group"), ("attack:S0046", "software")}
    assert all(x["ambiguous"] for x in r)
    assert [x["doc_id"] for x in a.find_name("Cozy Bear", kinds=("group",))] == ["attack:G0016"]
    apt = a.find_name("APT-29")
    assert apt == [{"doc_id": "attack:G0016", "attack_id": "G0016", "doc_kind": "group", "name": "APT29",
                    "title": "APT29", "surface": "APT29", "origin": "name", "policy": "anywhere", "ambiguous": False}]
    assert a.find_name("Cozy") == []                           # exact only, never partial


def test_qualified_names_disambiguate_subtechniques(a):
    assert {x["doc_id"] for x in a.find_name("Domain Account")} == {"attack:T1087.002", "attack:T1136.002"}
    assert [x["doc_id"] for x in a.find_name("Account Discovery: Domain Account")] == ["attack:T1087.002"]
    assert a.find_name("Account Discovery: Domain Account")[0]["origin"] == "qualified_name"


def test_revoked_names_point_to_replacement_unless_taken(a):
    dark = a.find_name("Dark Halo")
    assert [(x["doc_id"], x["origin"]) for x in dark] == [("attack:G0016", "revoked_name")]
    assert [x["doc_id"] for x in a.find_name("OldBeacon")] == ["attack:S0154"]
    # the revoked T1086 is also called PowerShell; the active T1059.001 owns the name
    assert [(x["doc_id"], x["origin"]) for x in a.find_name("PowerShell")] == [("attack:T1059.001", "name")]
    assert a.find_name("Old Crew") == [] and a.find_name("Old Technique") == []   # deprecated: no entry
    assert a.find_name("Disable or Remove Feature or Program") == []              # mitigations: by ID only


# ---------------------------------------------------------------------------- policy as data
def test_policy_stored_with_the_build(a, g):
    pol = a.gazetteer_policy
    assert pol["short_max_chars"] == 3 and pol["corpus_term_min_df"] == 2 and "software" in pol["kind_markers"]
    assert g.key_info["net"]["policy"] == "restricted" and g.key_info["net"]["reason"].startswith("short")
    assert g.key_info["at"]["policy"] == "restricted"
    # "attacker" is written in two fixture CVE descriptions: a corpus term, so restricted
    assert g.key_info["attacker"] == {"key": "attacker", "n_docs": 1, "kinds": "software", "policy": "restricted",
                                      "reason": "corpus_term", "df_cve": 2}
    assert g.key_info["cobaltstrike"]["policy"] == "anywhere" and g.key_info["cobaltstrike"]["df_cve"] == 0


def test_assign_policy_and_corpus_df_units():
    entries = [{"key": "page", "doc_id": "attack:S1", "doc_kind": "software", "surface": "Page", "origin": "name",
                "fine_tokens": 1},
               {"key": "badnews", "doc_id": "attack:S2", "doc_kind": "software", "surface": "BADNEWS",
                "origin": "name", "fine_tokens": 1},
               {"key": "cobaltstrike", "doc_id": "attack:S3", "doc_kind": "software", "surface": "Cobalt Strike",
                "origin": "name", "fine_tokens": 2}]
    df = corpus_df(["a crafted HTML Page", "page two", "bad news for Cobalt Strike", "CobaltStrike", ""], entries)
    assert df == {"page": 2, "cobaltstrike": 2}                 # "bad news" is not BADNEWS
    rows = {r["key"]: r for r in assign_policy(entries, df, {**POLICY, "corpus_term_min_df": 2})}
    assert rows["page"]["policy"] == "restricted" and rows["page"]["reason"] == "corpus_term"
    assert rows["badnews"]["policy"] == "anywhere"


# ---------------------------------------------------------------------------- matching
def test_anywhere_names_match_case_insensitively_and_token_aligned(g):
    m = g.match("Analysts saw apt 29 deploy cobaltstrike beacons and BADNEWS")
    assert ids(m) == [("apt 29", ("attack:G0016",), "anywhere"),
                      ("cobaltstrike", ("attack:S0154",), "anywhere"),
                      ("BADNEWS", ("attack:S9004",), "anywhere")]
    assert g.match("this is bad news") == []
    assert g.match("APT290 and XAPT29") == []                    # whole tokens only


def test_short_names_need_a_marker(g):
    assert ids(g.match("Net")) == [("Net", ("attack:S0039",), "whole_query")]
    assert ids(g.match('  "Net"  ')) == [("Net", ("attack:S0039",), "whole_query")]
    assert g.match("net income rose at the end of the quarter") == []
    assert ids(g.match("they ran the net command")) == [("net", ("attack:S0039",), "kind_marker")]
    assert ids(g.match("the cmd and net utilities")) == [("net", ("attack:S0039",), "kind_marker")]
    assert ids(g.match('scheduled with "at" on the host')) == [("at", ("attack:S0110",), "quoted")]
    assert ids(g.match("started net.exe")) == [("net.exe", ("attack:S0039",), "anywhere")]
    assert g.match("Net", query=False) == []                     # document text: no whole-query marker


def test_corpus_term_names_need_a_marker(g):
    assert g.match("the attacker sent a file") == []
    assert ids(g.match("Attacker")) == [("Attacker", ("attack:S9003",), "whole_query")]
    assert ids(g.match("Attacker malware on the host")) == [("Attacker", ("attack:S9003",), "kind_marker")]


def test_ambiguous_mentions_return_every_candidate(g):
    (m,) = g.match("Cozy Bear phishing wave")
    assert m.ambiguous and m.doc_ids == ("attack:G0016", "attack:S0046") and m.kinds == ("group", "software")
    (m,) = g.match("Cozy Bear phishing wave", kinds=("group",))
    assert m.doc_ids == ("attack:G0016",) and not m.ambiguous


def test_longest_match_and_ids(g):
    m = g.match("T1086 then Command and Scripting Interpreter: PowerShell and g0016 and T1059/001 and T1000")
    assert [(x.text, x.doc_ids, x.matched_by, x.candidates[0].origin) for x in m] == [
        ("T1086", ("attack:T1059.001",), "id", "revoked_id"),
        ("Command and Scripting Interpreter: PowerShell", ("attack:T1059.001",), "anywhere", "qualified_name"),
        ("g0016", ("attack:G0016",), "id", "id"),
        ("T1059/001", ("attack:T1059.001",), "id", "id")]
    assert g.match("T9999") == []                                # deprecated technique: no active document


def test_mitigation_ids_resolve(g):
    (m,) = g.match("apply M1042")
    assert m.doc_ids == ("attack:M1042",) and m.kinds == ("mitigation",)
