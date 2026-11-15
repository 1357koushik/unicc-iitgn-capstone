"""C1 document store: alias extraction, generic-alias filtering, corpus-wide selection, leakage firewall."""
import pytest

from threat_retrieval_engine.store import aliases as A
from threat_retrieval_engine.store.text import alias_norm


def nick(cands):
    return {(c.alias, c.position) for c in cands if c.kind == "nickname"}


def test_exploitdb_title_nickname_bulletin_and_title():
    cs = A.candidates_from_record("exploitdb", "42031", ["CVE-2017-0144"],
                                  "Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)")
    assert ("EternalBlue", "quoted") in nick(cs)
    assert {c.alias for c in cs if c.kind == "advisory_id"} == {"MS17-010"}
    assert not any(c.kind == "nickname" and c.norm == "ms17010" for c in cs)
    assert {c.alias for c in cs if c.kind == "title"} == {
        "Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)"}


def test_span_cleaning_keeps_leading_name_and_drops_parameters_and_packaging():
    cs = A.candidates_from_record("exploitdb", "40839", ["CVE-2016-5195"],
                                  "Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition (Metasploit)")
    assert ("Dirty COW", "quoted") in nick(cs)
    cs = A.candidates_from_record("exploitdb", "1", ["CVE-2006-2667"], "WordPress Core 2.0.2 - 'cache' Remote Shell Injection")
    assert nick(cs) == {("WordPress", "camel")}  # 'cache' is a parameter; a head with a version is a product
    cs = A.candidates_from_record("exploitdb", "2", ["CVE-2007-1286"], "PHP 4.4.6 - 'unserialize()' Overflow (PoC)")
    assert nick(cs) == {("PoC", "paren")}  # function names never; packaging is removed later as generic
    t = [c.alias for c in cs if c.kind == "title"]
    assert t == ["PHP 4.4.6 - 'unserialize()' Overflow"]


def test_metasploit_name_camelcase_and_via_paren():
    cs = A.candidates_from_record("metasploit_modules", "exploit/multi/http/log4shell_header_injection",
                                  ["CVE-2021-44228"], "VMware vCenter Server Unauthenticated JNDI Injection RCE (via Log4Shell)")
    assert ("Log4Shell", "paren") in nick(cs)
    cs = A.candidates_from_record("metasploit_modules", "m", ["CVE-2017-0143"],
                                  "MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution")
    assert {a for a, _ in nick(cs)} >= {"EternalRomance", "EternalSynergy", "EternalChampion"}


def test_known_as_phrases():
    assert A.known_as_spans("... related to d1_both.c and t1_lib.c, aka the Heartbleed bug.") == [("Heartbleed", "known_as")]
    assert A.known_as_spans('... processes trailing strings, aka "ShellShock."') == [("ShellShock", "known_as")]
    assert A.known_as_spans('... aka "Netlogon Elevation of Privilege Vulnerability."') == []
    assert A.known_as_spans("Invision Power Board (aka IPB) 3.4.6") == []
    assert A.known_as_spans("aka Bug ID CSCti11629.") == []


def test_description_candidates():
    cs = A.description_candidates("CVE-2014-0160", ["The TLS implementation in OpenSSL ... aka the Heartbleed bug."])
    assert [(c.alias, c.source, c.kind) for c in cs] == [("Heartbleed", "cve_description", "nickname")]


@pytest.mark.parametrize("alias,own,desc,why", [
    ("Remote Code Execution", ["Example"], "", "generic_phrase"),
    ("Metasploit", [], "", "generic_phrase"),
    ("Microsoft", ["Microsoft", "Windows"], "", "own_vendor_or_product"),
    ("Windows SMB", ["Microsoft", "Windows"], "", "generic_words"),
    ("DirectWrite", ["Microsoft", "Windows"], "Windows DirectWrite allows information disclosure.", "named_in_description"),
    ("Heartbleed", ["OpenSSL"], "OpenSSL mishandles Heartbeat packets.", "keep"),
])
def test_local_decision_filters_generic_and_vendor_only_names(alias, own, desc, why):
    c = A.Candidate("CVE-2014-0160", alias, alias_norm(alias), "nickname", "exploitdb", "1", "quoted", 1)
    own_tokens = A.own_name_tokens(own)
    own_keys = frozenset(alias_norm(x) for x in own)
    assert A.local_decision(c, own_tokens, own_keys, [desc] if desc else [], frozenset()) == why


def test_generic_title_is_dropped_but_informative_title_kept():
    own = ["Google", "Chrome"]
    t1 = A.Candidate("CVE-2018-6116", "Google Chrome - Remote Code Execution", "x", "title", "exploitdb", "1", "title", 1)
    t2 = A.Candidate("CVE-2018-6116", "Google Chrome - WebAssembly Null Dereference", "y", "title", "exploitdb", "2", "title", 1)
    ot, ok = A.own_name_tokens(own), frozenset(alias_norm(x) for x in own)
    assert A.local_decision(t1, ot, ok, [], frozenset()) == "generic_title"
    assert A.local_decision(t2, ot, ok, [], frozenset()) == "keep"


def _c(cid, alias, rid, n=1, pos="quoted", src="exploitdb"):
    return (A.Candidate(cid, alias, alias_norm(alias), "nickname", src, rid, pos, n), "keep")


VOC = A.Vocabulary(dictionary=frozenset({"review", "found", "again", "dirty", "pipe", "records", "policy"}),
                   names=frozenset({"debian", "freebsd", "ubuntulinux", "sharepoint"}),
                   name_tokens=frozenset({"ubuntu", "desktop", "debian", "linux"}))


def groups(sel):
    return {g.norm: g.cve_ids for g in sel.groups}


def test_title_head_is_a_candidate():
    cs = A.candidates_from_record("nuclei_templates", "CVE-2023-4966", ["CVE-2023-4966"],
                                  "Citrix Bleed - Leaking Session Tokens")
    assert ("Citrix Bleed", "head") in nick(cs)
    sel = A.select([(c, "keep") for c in cs if c.kind == "nickname"], VOC)
    assert groups(sel) == {"citrixbleed": ("CVE-2023-4966",)}   # one structured unit is enough to propose


@pytest.mark.parametrize("alias,pos,src,why", [
    ("review", "reference", "cve_references", "dictionary_word"),
    ("Found again", "reference", "cve_references", "dictionary_word"),
    ("w3hj", "reference", "cve_references", "identifier_fragment"),
    ("apsb20", "reference", "cve_references", "identifier_fragment"),
    ("APSB22", "paren", "exploitdb", "identifier_fragment"),
    ("debian", "reference_host", "cve_references", "vendor_product_vocabulary"),
    ("ubuntu desktop", "poc_repo", "poc_in_github", "vendor_product_vocabulary"),
    ("SharePoint", "camel", "exploitdb", "vendor_product_vocabulary"),
])
def test_prefilters_reject_words_fragments_and_vocabulary(alias, pos, src, why):
    rows = [_c("CVE-2021-0001", alias, f"r{i}", pos=pos, src=src) for i in range(3)]
    rows = [(A.Candidate(c.cve_id, c.alias, c.norm, c.kind, c.source, f"https://h{i}.example/{alias}" if
                         src == "cve_references" else c.record_id, c.position, 1), d) for i, (c, d) in enumerate(rows)]
    sel = A.select(rows, VOC)
    assert sel.groups == [] and sel.rejected_names[alias_norm(alias)] == why


def test_quoted_exploit_title_name_is_exempt_from_dictionary_filter():
    sel = A.select([_c("CVE-2022-0847", "Dirty Pipe", "50808")], VOC)  # 'dirty' and 'pipe' are words
    assert groups(sel) == {"dirtypipe": ("CVE-2022-0847",)}
    sel = A.select([_c("CVE-2022-0847", "Dirty Pipe", "50808", pos="head")], VOC)
    assert groups(sel) == {}


def test_weak_evidence_needs_two_units_and_dedicated_site_needs_one():
    one = [_c("CVE-2021-4034", "PwnKit", "alice/pwnkit", pos="poc_repo", src="poc_in_github")]
    assert groups(A.select(one, VOC)) == {}
    two = one + [_c("CVE-2021-4034", "pwnkit", "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt",
                    pos="reference", src="cve_references")]
    assert groups(A.select(two, VOC)) == {"pwnkit": ("CVE-2021-4034",)}
    krack = [_c(f"CVE-2017-{13077 + i}", "krack", "https://www.krackattacks.com/", pos="reference_site",
                src="cve_references") for i in range(10)]
    info = {"krackattacks.com": [10, 2017, 2017], "redhat.com": [90000, 1999, 2026]}
    g = groups(A.select(krack, VOC, info))
    assert g["krack"] == tuple(f"CVE-2017-{13077 + i}" for i in range(10))
    not_dedicated = [_c("CVE-2017-0001", "Redhatnews", "https://redhat.com/", pos="reference_site", src="cve_references")]
    assert groups(A.select(not_dedicated, VOC, info)) == {}  # a widely cited domain is not a dedicated site


def test_spread_years_and_relative_support():
    cands = [_c(f"CVE-2010-{i:04d}", "Widgetron", f"r{i}") for i in range(20)]
    cands += [_c(f"CVE-{y}-0001", "Oldname", f"a{y}") for y in ("2005", "2012", "2019")]
    cands += [_c("CVE-2014-6271", "Shellshock", f"m{i}") for i in range(4)]
    cands += [_c(c, "Shellshock", "e1", n=3) for c in ("CVE-2014-6271", "CVE-2014-3659", "CVE-2014-3671")]
    sel = A.select(cands, VOC)
    assert groups(sel)["shellshock"] == ("CVE-2014-6271",)   # 3659/3671 only share a multi-CVE exploit record
    assert sel.rejected_names[alias_norm("Widgetron")] == "spread_too_wide"
    assert sel.rejected_names[alias_norm("Oldname")] == "spread_over_years"


def test_cna_advisory_page_is_not_independent_of_the_cna_title():
    cs = A.weak_candidates("CVE-2026-0001", ["https://www.vulncheck.com/advisories/shop-idor-in-useraddresscontroller"],
                           [], frozenset({"useraddresscontroller"}), assigner="VulnCheck")
    assert cs and {A.evidence_unit(c) for c in cs} == {"cna"}
    title = A.Candidate("CVE-2026-0001", "UserAddressController", "useraddresscontroller", "nickname", "cve_list",
                        "CVE-2026-0001#title", "camel", 1)
    rows = [(title, "keep")] + [(c, "keep") for c in cs if c.norm == "useraddresscontroller"]
    assert A.select(rows, VOC).groups == []   # CNA title camel + CNA page = one unit


def test_verdicts_serve_only_matching_accepts(tmp_path):
    sel = A.select([_c("CVE-2014-0160", "Heartbleed", "32745"), _c("CVE-2014-6271", "Shellshock", "34766")], VOC)
    hb, ss = sorted(sel.groups, key=lambda g: g.norm)
    import json
    vf = tmp_path / "v.jsonl"
    common = {"judge": "sonnet", "adjudicator": "opus", "date": "2026-11-15"}
    vf.write_text("\n".join(json.dumps(x) for x in (
        {"alias_norm": hb.norm, "cve_ids": list(hb.cve_ids), "verdict": "accept", "evidence_sha256": hb.evidence_sha256,
         **common},
        {"alias_norm": ss.norm, "cve_ids": list(ss.cve_ids), "verdict": "accept", "evidence_sha256": "0" * 64,
         **common})) + "\n", encoding="utf-8")
    st = A.apply_verdicts(sel.groups, A.load_verdicts(vf))
    assert st[(hb.norm, hb.cve_ids)] == "accepted" and st[(ss.norm, ss.cve_ids)] == "stale"
    assert A.apply_verdicts(sel.groups, {})[(hb.norm, hb.cve_ids)] == "pending"
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"alias_norm": "x", "cve_ids": ["CVE-2014-0160"], "verdict": "maybe", **common}) + "\n",
                   encoding="utf-8")
    with pytest.raises(ValueError):
        A.load_verdicts(bad)
    leak = tmp_path / "leak.jsonl"
    leak.write_text(json.dumps({"alias_norm": hb.norm, "cve_ids": list(hb.cve_ids), "verdict": "accept",
                                "evidence_sha256": hb.evidence_sha256, "qid": "T2-0004", **common}) + "\n",
                    encoding="utf-8")
    with pytest.raises(ValueError):
        A.load_verdicts(leak)   # benchmark fields are refused


@pytest.mark.parametrize("source", sorted(A.QUERY_SIDE_SOURCES))
def test_query_side_sources_are_refused(source):
    with pytest.raises(ValueError):
        A.candidates_from_record(source, "1", ["CVE-2021-44228"], "Log4Shell")


def test_allowed_sources_exclude_every_query_side_source():
    assert not set(A.ALLOWED_SOURCES) & A.QUERY_SIDE_SOURCES
    assert {"ghsa_reviewed", "et_open_rules", "sigma_rules", "acsc_advisories", "ncsc_uk_advisories"} <= A.QUERY_SIDE_SOURCES


def test_url_phrases_skip_handles_and_strip_site_suffix():
    unit, ph = A.url_phrases("https://github.com/vanhoefm/fragattacks/blob/master/SUMMARY.md")
    assert unit == "github.com" and "vanhoefm" not in [x.lower() for x in ph] and "fragattacks" in ph
    unit, ph = A.url_phrases("https://drownattack.com")
    assert unit == "drownattack.com" and "drown" in ph
    unit, _ = A.url_phrases("https://bugzilla.redhat.com/show_bug.cgi?id=1")
    assert unit == "redhat.com"
    assert A.registrable_domain("ccsinjection.lepidum.co.jp") == "lepidum.co.jp"


def test_code_host_urls_use_repository_name_only():
    _, ph = A.url_phrases("https://github.com/acme/widgetron/blob/main/src/MainController.php")
    assert ph == ["widgetron"]


def test_weak_candidates_count_registrable_domains():
    refs = ["https://drownattack.com", "https://access.redhat.com/security/vulnerabilities/drown"]
    assert "drown" in {c.norm for c in A.weak_candidates("CVE-2016-0800", refs, [], frozenset())}
    same = ["https://access.redhat.com/a/drown", "https://bugzilla.redhat.com/drown"]
    assert A.weak_candidates("CVE-2016-0800", same, [], frozenset()) == []
    assert {c.position for c in A.weak_candidates("CVE-2017-13077", ["https://www.krackattacks.com/"], [],
                                                  frozenset())} == {"reference_site"}
