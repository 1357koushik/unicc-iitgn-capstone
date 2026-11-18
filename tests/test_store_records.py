"""C1 document store: per-record rules (parsing, state, description choice, CPE product rule, humanised names,
KEV/EPSS joins, CVSS versions, dense text). Inline fixtures only."""
import json

import pytest

from threat_retrieval_engine.store import feeds as F
from threat_retrieval_engine.store import merge as M
from threat_retrieval_engine.store import text as T

from store_fixtures import CHROME_DESC, cpe_match, cvelist_record, nvd_cve

CTX = {"cwe_names": {"CWE-476": "NULL Pointer Dereference", "CWE-502": "Deserialization of Untrusted Data"},
       "kev_file": "cisa_kev-2026-11-10.csv", "epss_file": "epss_scores-2026-11-11.csv",
       "epss_meta": {"model_version": "v2026.06.15", "score_date": "2026-11-11T12:00:22Z"}, "store_version": "test"}


def nvd(wrapper, idx=0, name="2021.json"):
    raw = json.dumps(wrapper)
    rec, rej = F.compact_nvd(wrapper, raw, name, idx)
    assert rej is None
    return rec


def cl(record, rel=None):
    cid = record["cveMetadata"]["cveId"]
    rel = rel or f"{cid.split('-')[1]}/0xxx/{cid}.json"
    rec, rej = F.compact_cvelist(record, rel, "0" * 64)
    assert rej is None, rej
    return rec


def row(cid, n=None, c=None, kev=None, epss=None):
    r, side = M.build_row(cid, n, c, kev, epss, CTX)
    return r


# --------------------------------------------------------------------------- streaming NVD reader
def test_nvd_stream_reads_every_element_across_chunk_boundaries(tmp_path):
    wrappers = [nvd_cve(f"CVE-2021-000{i}", f"Issue number {i} in Example Product allows things.") for i in range(1, 6)]
    p = tmp_path / "2021.json"
    p.write_text(json.dumps({"format": "NVD_CVE", "vulnerabilities": wrappers}, indent=2), encoding="utf-8")
    got = list(F.iter_json_array(p, "vulnerabilities", chunk=97))
    assert [v["cve"]["id"] for _, v, _ in got] == [w["cve"]["id"] for w in wrappers]
    assert all(json.loads(raw) == v for _, v, raw in got)


def test_nvd_stream_reports_truncated_tail(tmp_path):
    p = tmp_path / "2021.json"
    p.write_text('{"vulnerabilities": [ {"cve": {"id": "CVE-2021-0001"}}, {"cve": {"id": "CVE-20', encoding="utf-8")
    got = list(F.iter_json_array(p, "vulnerabilities", chunk=16))
    assert got[0][1]["cve"]["id"] == "CVE-2021-0001"
    assert got[-1][1] is None and "unparseable" in got[-1][2]


def test_nvd_record_without_valid_id_is_rejected_with_reason():
    rec, rej = F.compact_nvd({"cve": {"id": "CVE-21-1"}}, "{}", "2021.json", 3)
    assert rec is None and rej.reason == "malformed_cve_id" and rej.record_id == "2021.json#3"
    rec, rej = F.compact_nvd({"nope": 1}, "{}", "2021.json", 4)
    assert rec is None and rej.reason == "malformed_record"


def test_cvelist_filename_mismatch_is_rejected():
    rec, rej = F.compact_cvelist(cvelist_record("CVE-2021-0001", "x y z w"), "2021/0xxx/CVE-2021-0002.json", "0")
    assert rec is None and rej.reason == "cve_id_filename_mismatch"


# --------------------------------------------------------------------------- state and description choice
def test_rejected_nvd_record_is_stored_not_searchable():
    r = row("CVE-2018-0001", n=nvd(nvd_cve("CVE-2018-0001", "Rejected reason: withdrawn by the CNA.", status="Rejected")))
    assert r["state"] == "rejected" and r["searchable"] == 0
    assert r["description"].startswith("Rejected reason") and r["dense_text"] is None


def test_rejected_cvelist_record_uses_rejection_reason():
    c = cl(cvelist_record("CVE-2021-0003", None, state="REJECTED", rejected_reason="Duplicate of CVE-2021-0001."))
    r = row("CVE-2021-0003", c=c)
    assert r["state"] == "rejected" and r["searchable"] == 0
    assert r["description_source"] == "cve_list_cna_rejected_reason"


def test_reserved_placeholder_is_reserved():
    n = nvd(nvd_cve("CVE-2018-0002", "** RESERVED ** This candidate has been reserved by an organization.",
                    status="Received"))
    r = row("CVE-2018-0002", n=n)
    assert r["state"] == "reserved" and r["searchable"] == 0 and r["description_kind"] == "reserved"


def test_cve_list_state_is_authoritative_and_conflict_recorded():
    n = nvd(nvd_cve("CVE-2021-0009", "Rejected reason: duplicate.", status="Rejected"))
    c = cl(cvelist_record("CVE-2021-0009", "A real flaw in Example Product allows remote attackers to crash it."))
    r = row("CVE-2021-0009", n=n, c=c)
    assert r["state"] == "published" and r["searchable"] == 1
    assert r["provenance"]["conflicts"]["state"] == {"cve_list": "PUBLISHED", "nvd": "Rejected"}


def test_description_prefers_cna_then_nvd_then_kev():
    n = nvd(nvd_cve("CVE-2021-0010", "NVD wording of the Example Product flaw that allows file reads."))
    c = cl(cvelist_record("CVE-2021-0010", "CNA wording of the Example Product flaw that allows file reads."))
    r = row("CVE-2021-0010", n=n, c=c)
    assert r["description_source"] == "cve_list_cna" and r["description"].startswith("CNA wording")
    assert r["provenance"]["fields"]["description_nvd_differs"] is True
    c2 = cl(cvelist_record("CVE-2021-0010", "n/a"))
    r2 = row("CVE-2021-0010", n=n, c=c2)
    assert r2["description_source"] == "nvd" and r2["searchable"] == 1
    kev = {"row": 2, "sha": "x", "vulnerability_name": "Example Product Path Traversal Vulnerability",
           "short_description": "Example Product contains a path traversal vulnerability.", "product": "Product",
           "vendor_project": "Example"}
    r3 = row("CVE-2021-0011", kev=kev)
    assert r3["description_source"] == "kev" and r3["searchable"] == 1 and r3["state"] == "published"


def test_placeholder_only_description_is_not_searchable():
    r = row("CVE-2021-0012", c=cl(cvelist_record("CVE-2021-0012", "N/A")))
    assert r["state"] == "published" and r["searchable"] == 0 and r["description_kind"] == "placeholder"


@pytest.mark.parametrize("text,kind", [("", "empty"), ("** RESERVED ** x", "reserved"), ("tbd", "placeholder"),
                                       ("Rejected reason: dup", "rejected"), ("XSS in foo", "ok")])
def test_description_kind(text, kind):
    assert T.description_kind(text) == kind


# --------------------------------------------------------------------------- vendor / product
def test_platform_cpes_of_a_chrome_bug_are_not_its_product():
    """CVE-2018-6116: NVD lists Red Hat and Debian CPEs as vulnerable; only Chrome is named by the CVE."""
    cfg = [
        {"nodes": [{"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*")]}]},
        {"nodes": [{"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:o:redhat:linux_desktop:6.0:*:*:*:*:*:*:*"),
                                                    cpe_match("cpe:2.3:o:redhat:linux_server:6.0:*:*:*:*:*:*:*")]}]},
        {"nodes": [{"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*")]}]},
    ]
    r = row("CVE-2018-6116", n=nvd(nvd_cve("CVE-2018-6116", CHROME_DESC, configurations=cfg), name="2018.json"))
    assert r["vendor_product"] == "Google Chrome"
    assert r["provenance"]["fields"]["vendor_product"]["method"] == "nvd_cpe_named"
    assert len(r["cpe"]) == 4  # every CPE match is still kept in the structured column


def test_platform_side_of_and_configuration_never_counts():
    cfg = [{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:a:example:example_gallery:1.2:*:*:*:*:*:*:*")]},
        {"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", vulnerable=False)]}]}]
    desc = "Cross-site scripting in Example Gallery 1.2 on Microsoft Windows allows script injection via captions."
    r = row("CVE-2021-0001", n=nvd(nvd_cve("CVE-2021-0001", desc, configurations=cfg)))
    assert r["vendor_product"] == "Example Gallery"
    roles = {m["criteria"].split(":")[4]: m["role"] for m in r["cpe"]}
    assert roles == {"example_gallery": "vulnerable", "windows": "platform"}


def test_unnamed_cpe_falls_back_to_cna_affected_humanised():
    cfg = [{"nodes": [{"operator": "OR", "cpeMatch": [cpe_match("cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*")]}]}]
    n = nvd(nvd_cve("CVE-2021-0004", "SQL injection in the login form allows reading the user table remotely.",
                    configurations=cfg))
    c = cl(cvelist_record("CVE-2021-0004", "SQL injection in the login form allows reading the user table remotely.",
                          affected=[{"vendor": "n/a", "product": "n/a"},
                                    {"vendor": "Acme_Corp", "product": "Widget_Server",
                                     "versions": [{"version": "3.1", "status": "affected"}]}]))
    r = row("CVE-2021-0004", n=n, c=c)
    assert r["vendor_product"] == "Acme Corp Widget Server"
    assert "_" not in r["vendor_product"]
    assert r["provenance"]["fields"]["vendor_product"]["method"] == "cve_list_cna_affected"


def test_vendor_product_cap_and_dedup():
    affected = [{"vendor": "Acme", "product": f"Product {i}"} for i in range(15)] + [{"vendor": "ACME", "product": "product 1"}]
    r = row("CVE-2021-0013", c=cl(cvelist_record("CVE-2021-0013", "Several Acme products share a hard-coded key.",
                                                 affected=affected)))
    labels = r["vendor_product"].split("; ")
    assert len(labels) == 10 and len({T.name_key(x) for x in labels}) == 10


@pytest.mark.parametrize("vendor,product,label", [
    ("google", "chrome", "google chrome"), ("Apache", "Apache HTTP Server", "Apache HTTP Server"),
    ("n/a", "Widget_Server", "Widget Server"), ("microsoft", "windows_server_2019", "microsoft windows server 2019"),
    ("joomla", "joomla\\!", "joomla!"), (None, "OpenSSL", "OpenSSL")])
def test_humanised_vendor_product_labels(vendor, product, label):
    assert T.vendor_product_label(vendor, product) == label


def test_find_span_matches_product_slug_in_text():
    assert T.find_span(T.slug_tokens("e-studio_6525"), "Toshiba e-STUDIO6525 printers") == "e-STUDIO6525"
    assert T.find_span(T.slug_tokens("linux_server"), CHROME_DESC) is None


# --------------------------------------------------------------------------- KEV, EPSS, CVSS, CWE
def test_kev_and_epss_join_without_severity_override():
    metrics = {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                  "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                                               "baseScore": 1.8, "baseSeverity": "LOW"}}]}
    n = nvd(nvd_cve("CVE-2021-0020", "A low severity local flaw in Example Product leaks a timestamp.", metrics=metrics))
    kev = {"row": 7, "sha": "k", "vendor_project": "Example", "product": "Product",
           "vulnerability_name": "Example Product Information Disclosure Vulnerability", "date_added": "2026-01-02",
           "short_description": "Example Product leaks data.", "required_action": "Apply updates.",
           "due_date": "2026-01-16", "ransomware_use": "Unknown", "notes": None, "cwes": ["CWE-200"]}
    r = row("CVE-2021-0020", n=n, kev=kev, epss=(0.00011, 0.0123))
    assert r["kev_listed"] == 1 and r["kev"]["date_added"] == "2026-01-02" and r["kev"]["ransomware_use"] == "Unknown"
    assert r["kev_text"] == "Example Product Information Disclosure Vulnerability. Example Product leaks data."
    assert [e["severity"] for e in r["cvss"]] == ["LOW"]  # KEV listing never changes severity
    assert r["epss"] == {"score": 0.00011, "percentile": 0.0123, "date": "2026-11-11",
                         "score_date": "2026-11-11T12:00:22Z", "model_version": "v2026.06.15"}
    assert r["epss_score"] == 0.00011  # low scores are kept: no threshold
    assert "CWE-200" in r["cwe_ids"]


def test_cvss_every_version_with_sources_merged_and_never_invented():
    metrics = {
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 7.5}}],
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                           "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
                          {"source": "cna@example.org", "type": "Secondary",
                           "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        "baseScore": 8.1, "baseSeverity": "HIGH"}}],
    }
    n = nvd(nvd_cve("CVE-2021-0021", "Remote code execution in Example Product via crafted requests to the API.",
                    metrics=metrics))
    c = cl(cvelist_record("CVE-2021-0021", "Remote code execution in Example Product via crafted requests to the API.",
                          metrics=[{"cvssV3_1": {"version": "3.1", "baseScore": 8.1, "baseSeverity": "HIGH",
                                                 "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                                   {"cvssV2_0": {"version": "2.0", "baseScore": 6.8,
                                                 "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:P"}},
                                   {"cvssV4_0": {"version": "4.0", "baseScore": 9.2, "baseSeverity": "CRITICAL",
                                                 "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]))
    r = row("CVE-2021-0021", n=n, c=c)
    by = {(e["version"], e["score"]): e for e in r["cvss"]}
    assert set(by) == {("2.0", 7.5), ("2.0", 6.8), ("3.1", 9.8), ("3.1", 8.1), ("4.0", 9.2)}
    assert by[("2.0", 7.5)]["severity"] == "HIGH"
    assert by[("2.0", 6.8)]["severity"] is None  # the CNA gave no V2 severity: none is invented
    assert {s["origin"] for s in by[("3.1", 8.1)]["sources"]} == {"nvd", "cna"}  # same assessment, two sources
    assert all(e["vector"] for e in r["cvss"])


def test_weakness_names_from_catalogue_and_free_text():
    n = nvd(nvd_cve("CVE-2018-6116", CHROME_DESC, weaknesses=[
        {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-476"}]},
        {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]}]),
        name="2018.json")
    c = cl(cvelist_record("CVE-2018-6116", CHROME_DESC, problem_types=[
        {"descriptions": [{"lang": "en", "type": "text", "description": "Out of bounds memory access"}]},
        {"descriptions": [{"lang": "en", "type": "CWE", "cweId": "CWE-9999", "description": "CWE-9999 Made Up Weakness"}]}]))
    r = row("CVE-2018-6116", n=n, c=c)
    assert r["cwe_ids"] == ["CWE-476", "CWE-9999"]
    assert r["weakness"] == ("CWE-476 NULL Pointer Dereference; CWE-9999 Made Up Weakness; "
                             "Out of bounds memory access")
    names = {e.get("id"): e.get("name_source") for e in r["weaknesses"] if e.get("id")}
    assert names == {"CWE-476": "cwe_catalog", "CWE-9999": "cve_list_cna"}


# --------------------------------------------------------------------------- dense text
def test_dense_text_has_no_cve_ids_and_no_boilerplate():
    n = nvd(nvd_cve("CVE-2021-0030", "Example Gallery 1.2 mishandles uploads, a different vulnerability than "
                                     "CVE-2021-0031 and CVE-2021-0032. See (CVE-2021-0033) for details."))
    c = cl(cvelist_record("CVE-2021-0030", None, title="CVE-2021-0030 Example Gallery upload flaw",
                          affected=[{"vendor": "Example", "product": "Uploader", "versions": [{"version": "1.2", "status": "affected"}]}]))
    r = row("CVE-2021-0030", n=n, c=c)
    d = r["dense_text"]
    assert "CVE-" not in d
    for label in ("Document:", "Section:", "Content:", "CVEs:", "Malware:", "TTPs:", "none |"):
        assert label not in d
    assert d.startswith("Example Gallery upload flaw.") and "Example Uploader." in d
    assert "()" not in d and " ." not in d


def test_strip_cve_ids_tidies_sentence():
    s = T.strip_cve_ids("This is a different vulnerability than CVE-2015-1234 and CVE-2015-5678.")
    assert "CVE" not in s and s.endswith("than.")
    assert T.strip_cve_ids("Fix (CVE-2020-0001) applied") == "Fix applied"
    assert "CVE" not in T.strip_cve_ids("Running OnAnyCVE-2025-41233 6.8")  # glued table cells


def test_content_hash_covers_searchable_fields_only():
    base = {"searchable": 1, "title": "t", "description": "d", "vendor_product": "v", "weakness": "w",
            "aliases": None, "kev_text": None, "dense_text": "t. d."}
    h = M.content_hash(base)
    assert M.content_hash(dict(base, epss_score=0.5)) == h
    assert M.content_hash(dict(base, aliases="Log4Shell")) != h
