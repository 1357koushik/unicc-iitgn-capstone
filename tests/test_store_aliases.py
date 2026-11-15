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
    assert nick(cs) == {("WordPress", "camel")}  # 'cache' is a parameter; WordPress is filtered later (product)
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


def test_select_rejects_wide_spread_and_year_spread_and_weak_support():
    cands = [_c(f"CVE-2010-{i:04d}", "Widgetron", f"r{i}") for i in range(20)]                  # product-like
    cands += [_c("CVE-2005-0001", "Oldname", "a"), _c("CVE-2012-0001", "Oldname", "b"),
              _c("CVE-2019-0001", "Oldname", "c")]                                          # spans years
    cands += [_c("CVE-2014-6271", "Shellshock", f"m{i}") for i in range(4)]
    cands += [_c(c, "Shellshock", "e1", n=3) for c in ("CVE-2014-6271", "CVE-2014-3659", "CVE-2014-3671")]
    cands += [_c("CVE-2021-44228", "Log4Shell", "x", pos="camel")]
    cands += [_c("CVE-2021-0100", "SharePoint", "y", pos="camel")]
    sel = A.select(cands, frozenset({"sharepoint"}))
    got = {(c.cve_id, c.alias) for c in sel.rows}
    assert ("CVE-2014-6271", "Shellshock") in got and ("CVE-2021-44228", "Log4Shell") in got
    assert not any(a == "Widgetron" for _, a in got)
    assert not any(a == "Oldname" for _, a in got)
    assert ("CVE-2014-3659", "Shellshock") not in got  # only shares a multi-CVE exploit record
    assert ("CVE-2021-0100", "SharePoint") not in got   # bare CamelCase that is a CPE product name
    assert sel.rejected_names[alias_norm("Widgetron")] == "spread_too_wide"
    assert sel.rejected_names[alias_norm("Oldname")] == "spread_over_years"
    assert sel.reasons["low_relative_support"] >= 1


@pytest.mark.parametrize("source", sorted(A.QUERY_SIDE_SOURCES))
def test_query_side_sources_are_refused(source):
    with pytest.raises(ValueError):
        A.candidates_from_record(source, "1", ["CVE-2021-44228"], "Log4Shell")


def test_allowed_sources_exclude_every_query_side_source():
    assert not set(A.ALLOWED_SOURCES) & A.QUERY_SIDE_SOURCES
    assert {"ghsa_reviewed", "et_open_rules", "sigma_rules", "acsc_advisories", "ncsc_uk_advisories"} <= A.QUERY_SIDE_SOURCES
