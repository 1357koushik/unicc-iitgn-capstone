"""Small inline fixtures for the C1 document store tests (raw-feed shaped, no large data)."""
from __future__ import annotations

import csv
import json
from pathlib import Path


def nvd_cve(cid: str, desc: str, status: str = "Analyzed", configurations=None, metrics=None, weaknesses=None,
            published: str = "2021-12-10T10:15:09.143", modified: str = "2026-01-01T00:00:00.000",
            affected=None, references=None) -> dict:
    c = {
        "id": cid, "sourceIdentifier": "security@example.org", "published": published, "lastModified": modified,
        "vulnStatus": status, "cveTags": [],
        "descriptions": [{"lang": "en", "value": desc}, {"lang": "es", "value": "texto"}],
        "metrics": metrics or {}, "weaknesses": weaknesses or [], "configurations": configurations or [],
        "references": references or [{"url": f"https://example.org/{cid}", "source": "security@example.org"}],
    }
    if affected is not None:
        c["affected"] = affected
    return {"cve": c}


def nvd_file(path: Path, wrappers: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"resultsPerPage": len(wrappers), "startIndex": 0, "totalResults": len(wrappers), "format": "NVD_CVE",
           "version": "2.0", "timestamp": "2026-11-11T03:00:02.418822", "vulnerabilities": wrappers}
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def cpe_match(criteria: str, vulnerable: bool = True, **ranges) -> dict:
    d = {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "00000000-0000-0000-0000-000000000000"}
    d.update(ranges)
    return d


def cvelist_record(cid: str, desc: str | None, state: str = "PUBLISHED", title: str | None = None,
                   affected=None, problem_types=None, metrics=None, rejected_reason: str | None = None,
                   published: str = "2021-12-10T00:00:00.000Z", adp=None) -> dict:
    cna: dict = {"providerMetadata": {"orgId": "org-1", "shortName": "acme", "dateUpdated": "2025-01-01T00:00:00Z"},
                 "references": [{"url": f"https://example.org/{cid}"}]}
    if desc is not None:
        cna["descriptions"] = [{"lang": "en", "value": desc}]
    if title:
        cna["title"] = title
    if affected is not None:
        cna["affected"] = affected
    if problem_types is not None:
        cna["problemTypes"] = problem_types
    if metrics is not None:
        cna["metrics"] = metrics
    if rejected_reason:
        cna["rejectedReasons"] = [{"lang": "en", "value": rejected_reason}]
    meta = {"cveId": cid, "assignerOrgId": "org-1", "assignerShortName": "acme", "state": state,
            "dateReserved": "2021-11-26T00:00:00.000Z", "dateUpdated": "2025-10-21T23:25:23.121Z"}
    if state == "PUBLISHED":
        meta["datePublished"] = published
    if state == "REJECTED":
        meta["dateRejected"] = "2022-01-01T00:00:00.000Z"
    containers: dict = {"cna": cna}
    if adp:
        containers["adp"] = adp
    return {"dataType": "CVE_RECORD", "dataVersion": "5.1", "cveMetadata": meta, "containers": containers}


def cvelist_write(root: Path, rec: dict) -> Path:
    cid = rec["cveMetadata"]["cveId"]
    _, y, n = cid.split("-")
    p = root / "cvelistV5-live" / "cves" / y / f"{int(n) // 1000}xxx" / f"{cid}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec), encoding="utf-8")
    return p


KEV_HEADER = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
              "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes", "cwes"]


def kev_file(path: Path, rows: list[list[str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(KEV_HEADER)
        w.writerows(rows)


def epss_file(path: Path, rows: list[tuple[str, str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("#model_version:v2026.06.15,score_date:2026-11-11T12:00:22Z\n")
        f.write("cve,epss,percentile\n")
        for r in rows:
            f.write(",".join(r) + "\n")


def source_dir(root: Path, name: str, role: str, records: list[dict]) -> Path:
    d = root / name / "2026-11-14"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "records.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    (d / "manifest.json").write_text(json.dumps({
        "source": name, "role": role, "status": "ok", "record_count": len(records),
        "license": {"name": "test", "url": "https://example.org", "permits": "test"},
        "retrieved_at_utc": "2026-11-14T00:00:00Z", "upstream_version": {"cwe_version": "5.0"}}), encoding="utf-8")
    (root / name / "LATEST").write_text("2026-11-14\n", encoding="utf-8")
    return d


CHROME_DESC = ("A nullptr dereference in WebAssembly in Google Chrome prior to 66.0.3359.117 allowed a remote "
               "attacker to potentially perform out of bounds memory access via a crafted HTML page.")
LOG4J_DESC = ("Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and "
              "parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.")
TWIN_DESC = ("Cross-site scripting vulnerability in Example Gallery 1.2 allows remote attackers to inject "
             "arbitrary web script or HTML via the caption field of an uploaded picture.")


def make_feeds(root: Path) -> Path:
    """A miniature feeds directory exercising every rule the build implements."""
    feeds = root / "feeds"
    chrome_cfg = [
        {"nodes": [{"operator": "OR", "negate": False,
                    "cpeMatch": [cpe_match("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                           versionEndExcluding="66.0.3359.117")]}]},
        {"nodes": [{"operator": "OR", "negate": False,
                    "cpeMatch": [cpe_match("cpe:2.3:o:redhat:linux_desktop:6.0:*:*:*:*:*:*:*"),
                                 cpe_match("cpe:2.3:o:redhat:linux_server:6.0:*:*:*:*:*:*:*")]}]},
        {"nodes": [{"operator": "OR", "negate": False,
                    "cpeMatch": [cpe_match("cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*")]}]},
    ]
    log4j_metrics = {
        "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                           "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                        "baseScore": 10.0, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "baseScore": 9.3}}],
    }
    nvd_file(feeds / "nvd_cve_data" / "2018.json", [
        nvd_cve("CVE-2018-6116", CHROME_DESC, configurations=chrome_cfg, published="2018-12-04T00:00:00.000",
                weaknesses=[{"source": "nvd@nist.gov", "type": "Primary",
                             "description": [{"lang": "en", "value": "CWE-476"}]}]),
        nvd_cve("CVE-2018-0001", "Rejected reason: This candidate was withdrawn by its CNA.", status="Rejected"),
        nvd_cve("CVE-2018-0002", "** RESERVED ** This candidate has been reserved by an organization or "
                                 "individual that will use it when announcing a new security problem.",
                status="Received"),
        nvd_cve("CVE-2018-0003", "Buffer overflow in the Example Daemon 2.0 allows remote attackers to cause a "
                                 "denial of service via a long hostname.", published="2018-01-02T00:00:00.000"),
        nvd_cve("CVE-2018-0003", "Buffer overflow in the Example Daemon 2.0 allows remote attackers to cause a "
                                 "denial of service via a long hostname.", published="2018-01-02T00:00:00.000"),
    ])
    nvd_file(feeds / "nvd_cve_data" / "2021.json", [
        nvd_cve("CVE-2021-44228", LOG4J_DESC + " NOTE: this differs from CVE-2021-45046.", metrics=log4j_metrics,
                configurations=[{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
                    cpe_match("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", versionEndExcluding="2.15.0")]}]}],
                weaknesses=[{"source": "nvd@nist.gov", "type": "Primary",
                             "description": [{"lang": "en", "value": "CWE-917"}]},
                            {"source": "security@apache.org", "type": "Secondary",
                             "description": [{"lang": "en", "value": "CWE-502"}]}]),
        nvd_cve("CVE-2021-0001", TWIN_DESC, configurations=[{"operator": "AND", "nodes": [
            {"operator": "OR", "negate": False,
             "cpeMatch": [cpe_match("cpe:2.3:a:example:example_gallery:1.2:*:*:*:*:*:*:*")]},
            {"operator": "OR", "negate": False,
             "cpeMatch": [cpe_match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", vulnerable=False)]}]}]),
        nvd_cve("CVE-2021-0002", TWIN_DESC),
        nvd_cve("CVE-2021-0007", "An information disclosure issue in Widget_Server allows reading the admin "
                                 "configuration over the network without authentication."),
    ])
    root_cl = feeds
    cvelist_write(root_cl, cvelist_record(
        "CVE-2018-6116", CHROME_DESC, published="2018-12-04T00:00:00.000Z",
        affected=[{"vendor": "Google", "product": "Chrome",
                   "versions": [{"version": "unspecified", "lessThan": "66.0.3359.117", "status": "affected",
                                 "versionType": "custom"}]}],
        problem_types=[{"descriptions": [{"lang": "en", "type": "text", "description": "Out of bounds memory access"}]}]))
    cvelist_write(root_cl, cvelist_record(
        "CVE-2021-44228", LOG4J_DESC, title="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
        affected=[{"vendor": "Apache Software Foundation", "product": "Apache Log4j2",
                   "versions": [{"version": "2.0-beta9", "lessThan": "2.15.0", "status": "affected"}]}],
        problem_types=[{"descriptions": [{"lang": "en", "type": "CWE", "cweId": "CWE-502",
                                          "description": "CWE-502 Deserialization of Untrusted Data"}]}],
        metrics=[{"cvssV3_1": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                               "baseScore": 10.0, "baseSeverity": "CRITICAL"}},
                 {"cvssV4_0": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                               "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]))
    cvelist_write(root_cl, cvelist_record("CVE-2021-0003", None, state="REJECTED",
                                          rejected_reason="This CVE ID has been rejected as a duplicate of CVE-2021-0001."))
    cvelist_write(root_cl, cvelist_record(
        "CVE-2021-0004", "SQL injection in the Acme Widget Server login form allows remote attackers to read the "
                         "user table.",
        affected=[{"vendor": "Acme_Corp", "product": "Widget_Server", "versions": [{"version": "3.1", "status": "affected"}]}]))
    cvelist_write(root_cl, cvelist_record(
        "CVE-2021-0007", "n/a",
        affected=[{"vendor": "n/a", "product": "n/a"},
                  {"vendor": "Acme_Corp", "product": "Widget_Server", "versions": [{"version": "4.0", "status": "affected"}]}]))
    bad = feeds / "cvelistV5-live" / "cves" / "2021" / "0xxx" / "CVE-2021-0005.json"
    bad.write_text("{ not json", encoding="utf-8")
    (feeds / "cvelistV5-live" / "cves" / "2021" / "0xxx" / "README.md").write_text("not a record", encoding="utf-8")
    kev_file(feeds / "cisa_kev-2026-11-10.csv", [
        ["CVE-2021-44228", "Apache", "Log4j2", "Apache Log4j2 Remote Code Execution Vulnerability", "2021-12-10",
         "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled "
         "JNDI-related endpoints, allowing for remote code execution.", "Apply updates per vendor instructions.",
         "2021-12-24", "Known", "https://logging.apache.org/log4j/2.x/security.html", "CWE-20, CWE-400, CWE-502"],
        ["CVE-2021-0004", "Acme", "Widget Server", "Acme Widget Server SQL Injection Vulnerability", "2022-01-05",
         "Acme Widget Server contains a SQL injection vulnerability.", "Apply updates.", "2022-01-19", "Unknown",
         "", "CWE-89"],
        ["CVE-21-1", "Bad", "Row", "Malformed", "2022-01-01", "x", "y", "2022-01-02", "Unknown", "", ""],
    ])
    epss_file(feeds / "epss_scores-2026-11-11.csv", [
        ("CVE-2021-44228", "0.94358", "0.99962"), ("CVE-2018-6116", "0.00052", "0.16321"),
        ("CVE-2021-0006", "0.00010", "0.00300"), ("CVE-2021-0004", "0.12000", "0.90000"),
        ("not-a-cve", "0.1", "0.1"),
    ])
    return feeds


def make_sources(root: Path) -> Path:
    src = root / "sources"
    source_dir(src, "exploitdb", "expansion", [
        {"edb_id": 50592, "title": "Apache Log4j 2 - 'Log4Shell' Remote Code Execution", "cve_ids": ["CVE-2021-44228"]},
        {"edb_id": 50593, "title": "Google Chrome - Remote Code Execution (Metasploit)", "cve_ids": ["CVE-2018-6116"]},
        {"edb_id": 50594, "title": "Unknown App - 'Bogusname' Overflow", "cve_ids": ["CVE-2030-0001"]},
    ])
    source_dir(src, "metasploit_modules", "expansion", [
        {"module_path": "auxiliary/scanner/http/log4shell_scanner", "name": "Log4Shell HTTP Scanner",
         "description": "Check for Log4Shell.", "cve_ids": ["CVE-2021-44228"]},
    ])
    source_dir(src, "nuclei_templates", "expansion", [
        {"template_id": "CVE-2021-44228", "name": "Apache Log4j2 - Remote Code Execution (Log4Shell)",
         "cve_ids": ["CVE-2021-44228"]},
    ])
    source_dir(src, "cwe_catalog", "expansion", [
        {"cwe_id": "CWE-476", "name": "NULL Pointer Dereference", "kind": "weakness", "status": "Stable"},
        {"cwe_id": "CWE-502", "name": "Deserialization of Untrusted Data", "kind": "weakness", "status": "Draft"},
        {"cwe_id": "CWE-917", "name": "Improper Neutralization of Special Elements used in an Expression "
                                      "Language Statement ('Expression Language Injection')", "kind": "weakness",
         "status": "Incomplete"},
    ])
    # a benchmark query-side source holding a tempting nickname: it must never reach the alias table
    source_dir(src, "ghsa_reviewed", "query", [
        {"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "summary": "Remote code injection in Log4j (LeakedQueryName)",
         "cve_ids": ["CVE-2021-44228"]},
    ])
    return src
