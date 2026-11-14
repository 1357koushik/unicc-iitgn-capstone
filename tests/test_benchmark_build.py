"""Unit tests for the B2 collection builder (no real data needed).

Includes an end-to-end build on a small synthetic fixture, run twice, that must be byte-identical.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from benchmarks_v2.build import sealed
from benchmarks_v2.build.equivalence import _duplicate_targets
from benchmarks_v2.build.leakage import TextIndex
from benchmarks_v2.build.model import Item, assign_splits, qrel
from benchmarks_v2.build.noise import perturb
from benchmarks_v2.build.common import rng
from benchmarks_v2.build.slice_products import cpe_applies, cna_applies, vparse
from benchmarks_v2.build.slices_rules import et_query, informative
from benchmarks_v2.build.text import content_tokens, contains_name, overlap, raw_tokens, strip_cve_ids, token_set


def test_content_tokens_drop_ids_and_stopwords():
    assert content_tokens("What is CVE-2021-44228 in Apache Log4j 2.14.1?") == {"apache", "log4j", "2.14.1"}


def test_overlap_share_of_query_tokens():
    doc = token_set("Apache Struts 2 allows remote attackers to execute arbitrary code")
    assert overlap("apache struts remote code", doc) == 1.0
    assert overlap("struts deserialization flaw", doc) == pytest.approx(1 / 3)


def test_strip_cve_variants():
    assert "2021" not in strip_cve_ids("CVE-2021-1234 / cve_2021_1235 and CVE 2021 1236")


def test_contains_name_joined_tokens():
    assert contains_name("Citrix Bleed", raw_tokens("https://example.com/citrix-bleed-analysis"))
    assert contains_name("PrintNightmare", raw_tokens("the print-nightmare bug"))
    assert not contains_name("GHOST", raw_tokens("ghostscript overflow"))


def test_et_prefix_and_ids_stripped():
    text, stripped = et_query("ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228) M2")
    assert text == "Apache Log4j RCE Attempt"
    assert stripped["vendor_prefix"] == "ET EXPLOIT" and stripped["ids"] and stripped["variant_markers"] == ["M2"]
    assert not informative("Possible Exploitation Attempt")


def test_versions():
    assert vparse("2.3.0") == vparse("2.3") and vparse("1.0-beta") is None
    specs = [["*", "2.0", "", "", "2.5.3"]]
    assert cpe_applies(specs, vparse("2.4")) is True
    assert cpe_applies(specs, vparse("2.5.3")) is False
    assert cpe_applies([["*", "", "", "", ""]], vparse("1.0")) is None
    e = [{"ver": [["1.0", "affected", "1.4", "", "semver"]], "dflt": ""}]
    assert cna_applies(e, vparse("1.2")) is True and cna_applies(e, vparse("1.4")) is False


def test_duplicate_reason_parsing():
    r = ("Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2017-1000117. Reason: This candidate "
         "is a reservation duplicate of CVE-2017-1000117. Notes: All CVE users should reference CVE-2017-1000117.")
    assert _duplicate_targets("CVE-2017-9999", r) == ["CVE-2017-1000117"]
    assert _duplicate_targets("CVE-2017-9999", "Rejected reason: withdrawn by its CNA.") == []


def test_leakage_index_detects_copies_and_skips_ids():
    idx = TextIndex([("a", "Microsoft IIS 5.0 - WebDAV Remote Overflow", True), ("b", "Log4Shell PoC", False)])
    assert idx.collisions("microsoft iis 5.0 webdav remote overflow")
    assert idx.collisions("Microsoft IIS WebDAV Remote Overflow")      # covered by title
    assert not idx.collisions("are we exposed to Log4Shell?")
    assert not idx.collisions("CVE-2021-44228")                        # identifier only


def test_perturb_deterministic():
    a = perturb("remote code execution in the Windows server", "abbreviation", rng(1, "x"))
    b = perturb("remote code execution in the Windows server", "abbreviation", rng(1, "x"))
    for kind in ("typo", "spacing", "log_fragment"):
        assert perturb("remote code execution in the Windows server", kind, rng(2, kind)) ==             perturb("remote code execution in the Windows server", kind, rng(2, kind))
    assert a == b and a != "remote code execution in the Windows server"


def test_splits_group_by_cve():
    items = []
    for i in range(40):
        items.append(Item(slice="T3", text=f"q{i}", qrels=[qrel(f"CVE-2020-{1000 + i % 10}", 2, "known_item")],
                          source={"name": "x"}))
    items.append(Item(slice="T2", text="nick", qrels=[qrel("CVE-2020-1000", 2, "known_item")], source={"name": "x"}))
    assign_splits(items, None, 7)
    by_cve = {}
    for it in items:
        by_cve.setdefault(it.qrels[0]["doc_id"], set()).add(it.split)
    assert all(len(v) == 1 for v in by_cve.values())
    assert by_cve["CVE-2020-1000"] != {"train"}     # shares a T2 query, so no train


def test_sealed_guard(tmp_path, monkeypatch):
    d = tmp_path / "sealed"
    d.mkdir()
    (d / "queries.jsonl").write_text("", encoding="utf-8")
    (d / "qrels.jsonl").write_text("", encoding="utf-8")
    monkeypatch.delenv(sealed.ENV, raising=False)
    with pytest.raises(sealed.SealedAccessError):
        sealed.open_sealed(tmp_path)
    with pytest.raises(sealed.SealedAccessError):
        sealed.audit_sealed(tmp_path, "evaluation")
    monkeypatch.setenv(sealed.ENV, "E1")
    assert sealed.open_sealed(tmp_path) == ([], [])


# ---------------------------------------------------------------------------------------- end to end
def _write_source(root: Path, name: str, role: str, records: list[dict]) -> None:
    d = root / name / "2026-01-01"
    d.mkdir(parents=True)
    (root / name / "LATEST").write_text("2026-01-01", encoding="utf-8")
    (d / "records.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    (d / "manifest.json").write_text(json.dumps({"source": name, "role": role, "status": "ok",
                                                 "license": {"name": "test"}, "record_count": len(records),
                                                 "records_sha256": None, "upstream_version": {}}), encoding="utf-8")


def _fixture(root: Path) -> tuple[Path, Path, Path]:
    feeds, srcs = root / "feeds", root / "sources"
    (feeds / "nvd_cve_data").mkdir(parents=True)
    (feeds / "cvelistV5-live" / "cves").mkdir(parents=True)
    comps = ["login", "admin", "upload", "search", "report", "export", "profile", "basket"]
    vulns = []
    for i in range(48):
        cid = f"CVE-2021-{1000 + i}"
        cwe = ["CWE-89", "CWE-79", "CWE-22", "CWE-352"][i % 4]
        desc = (f"The {comps[i % 8]}_{i}.php page in Acme Widget before 1.{i % 6 + 1} lets attackers tamper with "
                f"records number {i}.")
        vulns.append({"cve": {"id": cid, "published": f"2021-0{i % 9 + 1}-1{i % 9}T00:00:00", "vulnStatus": "Analyzed",
                              "descriptions": [{"lang": "en", "value": desc}],
                              "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
                              "configurations": [{"nodes": [{"cpeMatch": [
                                  {"vulnerable": True, "criteria": f"cpe:2.3:a:acme:widget:1.{i % 6}:*:*:*:*:*:*:*"},
                                  {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                   "versionStartIncluding": "1.0", "versionEndExcluding": f"1.{i % 6 + 1}"}]}]}],
                              "references": [{"url": f"https://example.org/advisory/{i}"}]}})
    vulns.append({"cve": {"id": "CVE-2021-2000", "vulnStatus": "Rejected", "published": "2021-05-01T00:00:00",
                          "descriptions": [{"lang": "en", "value": "Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. "
                                            "ConsultIDs: CVE-2021-1001. Reason: This candidate is a duplicate of "
                                            "CVE-2021-1001."}]}})
    (feeds / "nvd_cve_data" / "2021.json").write_text(json.dumps({"format": "NVD_CVE", "vulnerabilities": vulns}),
                                                      encoding="utf-8")
    (feeds / "cisa_kev-2026-01-01.csv").write_text(
        "cveID,vendorProject,product,vulnerabilityName,dateAdded\nCVE-2021-1003,Acme,Widget,Acme Widget Flaw,2022-01-01\n",
        encoding="utf-8")
    (feeds / "epss_scores-2026-01-01.csv").write_text("#model\ncve,epss,percentile\nCVE-2021-1000,0.1,0.5\n",
                                                      encoding="utf-8")
    _write_source(srcs, "ghsa_reviewed", "query", [
        {"ghsa_id": f"GHSA-{i:04d}", "cve_ids": [f"CVE-2021-{1000 + i}"] if i != 1 else ["CVE-2021-2000"],
         "summary": f"Widget tampering issue variant {['alpha', 'beta', 'gamma', 'delta'][i % 4]} {i}",
         "details": "", "packages": [{"ecosystem": "npm", "name": f"pkg{i}"}], "published": "2021-01-01",
         "withdrawn": None} for i in range(20)])
    _write_source(srcs, "et_open_rules", "query", [
        {"sid": 2030000 + i, "msg": f"ET WEB_SPECIFIC_APPS Acme tampering probe {['red', 'blue', 'green'][i % 3]} "
                                    f"route {i} (CVE-2021-{1020 + i})", "cve_ids": [f"CVE-2021-{1020 + i}"],
         "enabled": True, "classtype": "web-application-attack"} for i in range(10)])
    _write_source(srcs, "sigma_rules", "query", [
        {"rule_id": "r1", "title": "Acme Widget Suspicious Tampering Request", "description": "Detects things",
         "cve_ids": ["CVE-2021-1040"], "author": "tester", "status": "test", "path": "x.yml"}])
    for name in ("exploitdb", "metasploit_modules", "nuclei_templates", "poc_in_github"):
        _write_source(srcs, name, "expansion", [{"title": "Acme Widget 1.0 - SQL Injection", "name": "Acme Widget RCE",
                                                 "description": "exploit for acme", "cve_ids": ["CVE-2021-1000"]}])
    att = [{"kind": "group", "attack_id": "G0001", "name": "Grey Panda", "aliases": ["Ash Lynx"],
            "description": "Grey Panda is a group that targets widgets.", "stix_id": "intrusion-set--1",
            "revoked": False, "deprecated": False},
           {"kind": "software", "attack_id": "S0001", "name": "WidgetRAT", "aliases": [],
            "description": "WidgetRAT is a remote access tool.", "stix_id": "malware--1", "revoked": False,
            "deprecated": False},
           {"kind": "technique", "attack_id": "T1001", "name": "Data Obfuscation", "aliases": [],
            "description": "Adversaries obfuscate data.", "stix_id": "attack-pattern--1", "revoked": False,
            "deprecated": False, "is_subtechnique": False},
           {"kind": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1",
            "target_ref": "malware--1", "stix_id": "relationship--1", "revoked": False, "deprecated": False},
           {"kind": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--1",
            "target_ref": "attack-pattern--1", "stix_id": "relationship--2", "revoked": False, "deprecated": False}]
    _write_source(srcs, "attack_enterprise", "attack", att)
    team3 = root / "benchmark_data.py"
    team3.write_text("BENCHMARK_CASES = [{'case_id': 'TC-1', 'description': 'x', 'raw_text': "
                     "'Grey Panda used WidgetRAT after exploiting CVE-2021-1005 in the Acme portal.', "
                     "'ground_truth_entities': {'threat_actors': ['Grey Panda'], 'malware_families': ['WidgetRAT'], "
                     "'cves': ['CVE-2021-1005']}}]\n", encoding="utf-8")
    return feeds, srcs, team3


def test_end_to_end_build_is_byte_identical(tmp_path, capsys):
    from benchmarks_v2.build.build_collection import build, parse_args
    feeds, srcs, team3 = _fixture(tmp_path)
    outs = []
    for k in ("a", "b"):
        out = tmp_path / f"out_{k}"
        args = parse_args(["--version", "vtest", "--out", str(out), "--sources", str(srcs), "--feeds", str(feeds),
                           "--team3-file", str(team3), "--workers", "1", "--build-date", "2026-01-01"])
        outs.append(build(args))
    capsys.readouterr()
    files_a = sorted(p.relative_to(outs[0]).as_posix() for p in outs[0].rglob("*") if p.is_file())
    files_b = sorted(p.relative_to(outs[1]).as_posix() for p in outs[1].rglob("*") if p.is_file())
    assert files_a == files_b
    for rel in files_a:
        assert (outs[0] / rel).read_bytes() == (outs[1] / rel).read_bytes(), rel
    m = json.loads((outs[0] / "manifest.json").read_text(encoding="utf-8"))
    assert m["counts"].get("T1") and m["counts"].get("T7")
    assert all(sealed.is_read_only(p) for p in (outs[0] / "sealed").iterdir())
    qs = [json.loads(x) for x in (outs[0] / "queries.jsonl").read_text(encoding="utf-8").splitlines()]
    assert qs and all(q["split"] != "test" for q in qs)
    eq = [json.loads(x) for x in (outs[0] / "equivalence.jsonl").read_text(encoding="utf-8").splitlines()]
    assert eq and eq[0]["members"] == ["CVE-2021-1001", "CVE-2021-2000"]
    for o in outs:
        sealed.unprotect_tree(o)
    os.environ.pop("TRE_OPEN_SEALED", None)
