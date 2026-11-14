"""Offline unit tests for the B1 source collectors (inline fixtures, no network)."""
import json
import sys
from pathlib import Path

import pytest

_COLLECT = Path(__file__).resolve().parent.parent / "scripts" / "collect"
if str(_COLLECT) not in sys.path:
    sys.path.insert(0, str(_COLLECT))

import attack_enterprise  # noqa: E402
import cisa_advisories  # noqa: E402
import collect_common as cc  # noqa: E402
import et_open_rules  # noqa: E402
import exploitdb  # noqa: E402
import ghsa_reviewed  # noqa: E402
import kev_attack_mappings  # noqa: E402
import metasploit_modules  # noqa: E402
import nuclei_templates  # noqa: E402
import poc_in_github  # noqa: E402
import sigma_rules  # noqa: E402


def norm(values):
    good, _bad = cc.normalize_cves(values)
    return good


# ---------------------------------------------------------------- CVE normaliser
def test_normalize_cve_id_cases():
    assert cc.normalize_cve_id("cve-2021-44228") == "CVE-2021-44228"
    assert cc.normalize_cve_id("  CVE-2014-0160 ") == "CVE-2014-0160"
    assert cc.normalize_cve_id("CVE-2023-123456") == "CVE-2023-123456"


@pytest.mark.parametrize("bad", ["CVE-2021-123", "CVE-21-1234", "CAN-2004-1060", "CVE-n/a", "CVE-2015- 5698",
                                 "CVE-2017-18344.", "CVE-1998-0001", "", None, 12345])
def test_normalize_cve_id_rejects(bad):
    assert cc.normalize_cve_id(bad) is None


def test_normalize_cves_dedup_and_count():
    good, bad = cc.normalize_cves(["cve-2021-44228", "CVE-2021-44228", "CVE-2020-1", "CVE-2019-0708"])
    assert good == ["CVE-2019-0708", "CVE-2021-44228"]
    assert bad == 1


def test_find_cves_in_text():
    t = "Exploits CVE-2021-44228 and cve-2021-45046, not XCVE-2020-1234 or CVE-2020-12."
    assert cc.find_cves(t) == ["CVE-2021-44228", "CVE-2021-45046"]


def test_context_counts_malformed():
    ctx = cc.Context(spec=exploitdb.SPEC, raw_dir=Path("."))
    assert ctx.cves(["CVE-2020-0001", "bogus"]) == ["CVE-2020-0001"]
    assert ctx.malformed_cve_ids == 1


def test_spec_roles_valid_and_unique_per_source():
    mods = [attack_enterprise, cisa_advisories, et_open_rules, exploitdb, ghsa_reviewed, kev_attack_mappings,
            metasploit_modules, nuclei_templates, poc_in_github, sigma_rules]
    roles = {m.SPEC.name: m.SPEC.role for m in mods}
    assert len(roles) == 10
    assert set(roles.values()) <= set(cc.ROLES)
    assert roles["ghsa_reviewed"] == "query" and roles["exploitdb"] == "expansion"
    assert roles["cisa_advisories"] == "incident" and roles["attack_enterprise"] == "attack"


# ---------------------------------------------------------------- CSV (Exploit-DB)
EDB_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,"
    "aliases,screenshot_url,application_url,source_url\n"
    '16929,exploits/aix/dos/16929.rb,"AIX Calendar Manager - Buffer Overflow (Metasploit)",2010-11-11,Metasploit,'
    "dos,aix,,2010-11-11,2011-03-06,1,CVE-2009-3699;OSVDB-58726,,,,,\n"
    '100,exploits/php/webapps/100.txt,"Some App - SQLi",2004-01-01,x,webapps,php,,2004-01-01,2004-01-01,0,OSVDB-1,,,,,\n'
    '200,exploits/php/webapps/200.txt,"Other App - XSS",2005-01-01,x,webapps,php,,2005-01-01,2005-01-01,0,'
    "cve-2005-0001;CVE-n/a,,,,,\n"
)


def test_exploitdb_csv_parser():
    recs, total = exploitdb.parse_exploit_rows(EDB_CSV, norm)
    assert total == 3
    assert [r["edb_id"] for r in recs] == [16929, 200]
    assert recs[0]["cve_ids"] == ["CVE-2009-3699"] and recs[0]["verified"] is True
    assert recs[1]["cve_ids"] == ["CVE-2005-0001"] and recs[1]["verified"] is False
    assert recs[0]["platform"] == "aix" and recs[0]["type"] == "dos"


# ---------------------------------------------------------------- JSON (GHSA, Metasploit, KEV mappings, PoC)
def test_ghsa_parser():
    doc = {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2021-23337", "cve-2021-23337", "SNYK-JS-1"],
           "summary": "Command injection in lodash", "details": "details here",
           "published": "2021-02-15T00:00:00Z", "modified": "2021-03-01T00:00:00Z",
           "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}},
                        {"package": {"ecosystem": "npm", "name": "lodash"}}],
           "database_specific": {"severity": "HIGH"}}
    r = ghsa_reviewed.parse_advisory(doc, norm)
    assert r["ghsa_id"] == "GHSA-xxxx-yyyy-zzzz" and r["cve_ids"] == ["CVE-2021-23337"]
    assert r["packages"] == [{"ecosystem": "npm", "name": "lodash"}]
    assert ghsa_reviewed.parse_advisory({"aliases": []}, norm) is None


def test_metasploit_parser():
    data = {
        "exploit/a/b": {"name": "A Exploit", "fullname": "exploit/a/b", "rank": 600,
                        "disclosure_date": "2020-01-01", "type": "exploit",
                        "description": "line one\n     line two",
                        "references": ["CVE-2020-0001", "URL-http://x", "CVE-bad"]},
        "aux/c": {"name": "No CVE", "references": ["OSVDB-1"]},
    }
    recs, total = metasploit_modules.parse_modules(data, norm)
    assert total == 2 and len(recs) == 1
    assert recs[0]["cve_ids"] == ["CVE-2020-0001"] and recs[0]["description"] == "line one line two"
    assert recs[0]["rank"] == 600


def test_kev_mapping_parser():
    doc = {"metadata": {"attack_version": "16.1", "mapping_framework_version": "07/28/2025"},
           "mapping_objects": [
               {"capability_id": "CVE-2024-34102", "attack_object_id": "T1190", "mapping_type": "exploitation_technique",
                "attack_object_name": "Exploit Public-Facing Application", "capability_group": "xxe", "status": "complete"},
               {"capability_id": "not-a-cve", "attack_object_id": "T1059"}]}
    recs = kev_attack_mappings.parse_mappings(doc, norm)
    assert len(recs) == 1
    assert recs[0]["cve_id"] == "CVE-2024-34102" and recs[0]["attack_technique_id"] == "T1190"
    assert recs[0]["mapping_type"] == "exploitation_technique" and recs[0]["attack_version"] == "16.1"


def test_poc_parser():
    repos = [{"full_name": "u/CVE-2024-3094-info", "html_url": "https://github.com/u/CVE-2024-3094-info",
              "description": None, "stargazers_count": 55, "created_at": "2024-03-29T17:03:01Z",
              "updated_at": "2026-11-08T20:29:44Z", "fork": False},
             {"full_name": "u/CVE-2024-3094-info"}]
    recs = poc_in_github.parse_poc_file("CVE-2024-3094", repos, norm)
    assert len(recs) == 1 and recs[0]["stars"] == 55 and recs[0]["cve_id"] == "CVE-2024-3094"
    assert poc_in_github.parse_poc_file("README", repos, norm) == []


# ---------------------------------------------------------------- YAML (Sigma, nuclei)
def test_sigma_yaml_parser():
    import yaml
    doc = yaml.safe_load(
        "title: Exploit CVE-2021-44228 Log4Shell\n"
        "id: 11111111-2222-3333-4444-555555555555\n"
        "status: test\n"
        "description: Detects JNDI\n"
        "references:\n  - https://nvd.nist.gov/vuln/detail/CVE-2021-45046\n"
        "tags:\n  - attack.initial-access\n  - cve.2021-44228\n"
        "level: high\n")
    r = sigma_rules.parse_sigma_doc(doc, "rules/web/x.yml", norm)
    assert r["cve_ids"] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert r["rule_id"].startswith("1111") and r["path"] == "rules/web/x.yml"
    assert sigma_rules.parse_sigma_doc({"title": "t", "tags": ["attack.execution"]}, "p", norm) is None


def test_nuclei_template_parser():
    import yaml
    y = yaml.safe_load("id: CVE-2021-1\ninfo:\n  name: X\n  severity: high\n  tags: cve,cve2021,rce\n"
                       "  classification:\n    cve-id: CVE-2021-0001\n")
    row = {"ID": "CVE-2021-0001", "Info": {"Name": "Some RCE", "Severity": "critical"},
           "file_path": "http/cves/2021/CVE-2021-0001.yaml"}
    r = nuclei_templates.parse_template(row, y, row["file_path"], norm)
    assert r["template_id"] == "CVE-2021-0001" and r["cve_ids"] == ["CVE-2021-0001"]
    assert r["name"] == "Some RCE" and r["severity"] == "critical" and r["tags"] == ["cve", "cve2021", "rce"]
    assert nuclei_templates.parse_template({"ID": "not-cve"}, None, "p", norm) is None


# ---------------------------------------------------------------- Suricata rule line
RULE_OK = ('alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ET EXPLOIT Apache Log4j RCE (CVE-2021-44228)"; '
           'flow:established,to_server; content:"jndi"; reference:cve,2021-44228; reference:url,x.org/a; '
           'classtype:attempted-admin; sid:2034647; rev:3; metadata:created_at 2021_12_10;)')


def test_suricata_rule_parser():
    r = et_open_rules.parse_rule_line(RULE_OK, norm)
    assert r["sid"] == 2034647 and r["cve_ids"] == ["CVE-2021-44228"]
    assert r["classtype"] == "attempted-admin" and r["enabled"] is True
    assert "Log4j" in r["msg"]
    disabled = et_open_rules.parse_rule_line("#" + RULE_OK, norm)
    assert disabled["enabled"] is False
    assert et_open_rules.parse_rule_line("# just a comment reference:cve,2020-0001;", norm) is None
    no_cve = RULE_OK.replace("reference:cve,2021-44228; ", "")
    assert et_open_rules.parse_rule_line(no_cve, norm) is None
    assert et_open_rules.parse_rule_line(RULE_OK.replace("2021-44228;", "21-4;"), norm) is None


# ---------------------------------------------------------------- STIX (ATT&CK)
def _ext(aid):
    return [{"source_name": "mitre-attack", "external_id": aid, "url": f"https://attack.mitre.org/x/{aid}"}]


def test_attack_stix_parser():
    grp = {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT29", "aliases": ["APT29", "Cozy Bear"],
           "external_references": _ext("G0016"), "description": "Used CVE-2020-1472 in attacks."}
    tech = {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Exploit Public-Facing Application",
            "external_references": _ext("T1190"), "x_mitre_is_subtechnique": False, "x_mitre_platforms": ["Linux"]}
    rel = {"type": "relationship", "id": "relationship--1", "relationship_type": "uses",
           "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"}
    sw = {"type": "tool", "id": "tool--1", "name": "Mimikatz", "external_references": _ext("S0002"),
          "x_mitre_deprecated": True}
    other = {"type": "identity", "id": "identity--1"}
    g = attack_enterprise.parse_object(grp, norm)
    assert g["kind"] == "group" and g["attack_id"] == "G0016" and g["aliases"] == ["Cozy Bear"]
    assert g["cve_ids"] == ["CVE-2020-1472"]
    t = attack_enterprise.parse_object(tech, norm)
    assert t["kind"] == "technique" and t["is_subtechnique"] is False and t["cve_ids"] == []
    r = attack_enterprise.parse_object(rel, norm)
    assert r["kind"] == "relationship" and r["source_ref"] == "intrusion-set--1"
    s = attack_enterprise.parse_object(sw, norm)
    assert s["kind"] == "software" and s["deprecated"] is True
    assert attack_enterprise.parse_object(other, norm) is None


# ---------------------------------------------------------------- CISA feed / HTML
def test_cisa_feed_and_html_parsers():
    xml = ('<rss><channel>'
           '<item><title>Alert A</title><link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a</link>'
           '<pubDate>Wed, 01 Mar 2023 12:00:00 +0000</pubDate></item>'
           '<item><title>ICS</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-23-100-01</link></item>'
           '</channel></rss>')
    items = cisa_advisories.parse_feed(xml)
    assert len(items) == 1 and items[0]["advisory_id"] == "AA23-061A"
    text = cisa_advisories.html_to_text("<html><nav>menu</nav><p>Exploited CVE-2022-1234.</p><script>x()</script></html>")
    assert "menu" not in text and "x()" not in text and "CVE-2022-1234" in text


# ---------------------------------------------------------------- runner behaviour
class _FakeMod:
    SPEC = cc.SourceSpec(name="fake", role="query", urls=["http://x"], license_name="MIT", license_url="http://l",
                         license_note="ok")

    @staticmethod
    def collect(ctx):
        ctx.cves(["CVE-2020-0001", "bad"])
        (ctx.raw_dir / "a.txt").write_text("hi")
        yield {"id": 1, "cve_ids": ["CVE-2020-0001"]}
        yield {"id": 2, "cve_ids": []}


class _UnavailMod:
    SPEC = cc.SourceSpec(name="gone", role="incident", urls=["http://x"], license_name="n", license_url="u",
                         license_note="n")

    @staticmethod
    def collect(ctx):
        raise cc.SourceUnavailable("blocked")
        yield  # pragma: no cover


def test_run_source_writes_manifest_and_is_rerunnable(tmp_path):
    m1 = cc.run_source(_FakeMod, tmp_path, "2026-01-01")
    d = tmp_path / "fake" / "2026-01-01"
    assert (tmp_path / "fake" / "LATEST").read_text().strip() == "2026-01-01"
    man = json.loads((d / "manifest.json").read_text())
    assert man["record_count"] == 2 and man["malformed_cve_ids_dropped"] == 1 and man["role"] == "query"
    assert man["records_sha256"] == cc.sha256_file(d / "records.jsonl") == m1["records_sha256"]
    (d / "stale.txt").write_text("old")
    cc.run_source(_FakeMod, tmp_path, "2026-01-01")  # same-day re-run replaces the directory
    assert not (d / "stale.txt").exists()


def test_run_source_unavailable_manifest(tmp_path):
    m = cc.run_source(_UnavailMod, tmp_path, "2026-01-01")
    assert m["status"] == "unavailable" and m["reason"] == "blocked" and m["record_count"] == 0
