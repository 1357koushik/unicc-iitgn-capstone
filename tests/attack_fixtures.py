"""Small inline fixtures for the C9 ATT&CK tests: a miniature STIX bundle and KEV-to-ATT&CK mapping file in the
B1 source layout, built against the miniature C1 store of `store_fixtures` (no network, no big data)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ATTACK_LICENCE = "MITRE ATT&CK Terms of Use (royalty-free licence)"
KEV_FILE = "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json"
MARKING = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
IDENTITY = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"


def _ref(aid: str, kind_path: str) -> dict:
    return {"source_name": "mitre-attack", "external_id": aid,
            "url": f"https://attack.mitre.org/{kind_path}/{aid.replace('.', '/')}"}


def obj(stype: str, sid: str, aid: str | None, name: str, desc: str = "", revoked: bool = False,
        deprecated: bool = False, **extra) -> dict:
    path = {"intrusion-set": "groups", "malware": "software", "tool": "software", "attack-pattern": "techniques",
            "course-of-action": "mitigations", "campaign": "campaigns"}.get(stype, "x")
    refs = [_ref(aid, path)] if aid else []
    refs += extra.pop("refs", [])
    o = {"type": stype, "spec_version": "2.1", "id": f"{stype}--{sid}", "created": "2020-01-01T00:00:00.000Z",
         "modified": "2026-01-01T00:00:00.000Z", "created_by_ref": IDENTITY, "name": name, "description": desc,
         "revoked": revoked, "x_mitre_deprecated": deprecated, "external_references": refs,
         "object_marking_refs": [MARKING], "x_mitre_domains": ["enterprise-attack"], "x_mitre_version": "1.0"}
    o.update(extra)
    return o


def rel(rid: str, src: str, rtype: str, dst: str, desc: str = "", **extra) -> dict:
    r = {"type": "relationship", "spec_version": "2.1", "id": f"relationship--{rid}", "relationship_type": rtype,
         "source_ref": src, "target_ref": dst, "description": desc, "created": "2021-01-01T00:00:00.000Z",
         "modified": "2026-01-01T00:00:00.000Z", "revoked": False, "x_mitre_deprecated": False,
         "external_references": extra.pop("refs", [])}
    r.update(extra)
    return r


def tech(sid: str, aid: str, name: str, tactic: str = "execution", **kw) -> dict:
    return obj("attack-pattern", sid, aid, name, kw.pop("desc", f"Adversaries may use {name}."),
               kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
               x_mitre_is_subtechnique="." in aid, x_mitre_platforms=["Windows"], **kw)


def bundle() -> dict:
    G16, G07 = "intrusion-set--g16", "intrusion-set--g07"
    objs = [
        {"type": "marking-definition", "id": MARKING, "spec_version": "2.1", "name": "copyright"},
        {"type": "identity", "id": IDENTITY, "spec_version": "2.1", "name": "The MITRE Corporation"},
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK",
         "x_mitre_version": "20.1", "modified": "2026-11-05T00:00:00.000Z"},
        {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "name": "Enterprise ATT&CK"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--exec", "name": "Execution", "x_mitre_shortname": "execution",
         "external_references": [_ref("TA0002", "tactics")]},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--lm", "name": "Lateral Movement",
         "x_mitre_shortname": "lateral-movement", "external_references": [_ref("TA0008", "tactics")]},
        {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--d1", "name": "Detect PowerShell",
         "external_references": [_ref("DET0001", "detectionstrategies")]},
        # groups
        obj("intrusion-set", "g16", "G0016", "APT29",
            "[APT29](https://attack.mitre.org/groups/G0016) is a threat group attributed to Russia's SVR."
            "(Citation: White House Imposing Costs RU Gov April 2021) It exploited CVE-2021-44228 in "
            "**VMware** servers.(Citation: Some (nested) report)",
            aliases=["APT29", "Cozy Bear", "NOBELIUM", "apt 29"],
            refs=[{"source_name": "Vendor report CVE-2021-0004", "url": "https://example.org/r",
                   "description": "Report on CVE-2021-0004 and CVE-2030-9999 exploitation."}]),
        obj("intrusion-set", "g07", "G0007", "APT28", "<code>APT28</code> is a group.", aliases=["APT28", "Sofacy"]),
        obj("intrusion-set", "g9001", "G9001", "Dark Halo", "Merged into APT29.", revoked=True, aliases=["Dark Halo"]),
        obj("intrusion-set", "g9002", "G9002", "Old Crew", "No longer tracked.", deprecated=True, aliases=["Old Crew"]),
        # groups whose analyst short forms are derived ("Sandworm", "Lazarus"), one whose short form is a corpus
        # term ("Remote": restricted), one whose short form collides with a real software name ("Carbon")
        obj("intrusion-set", "g34", "G0034", "Sandworm Team", "A group.", aliases=["Sandworm Team", "ELECTRUM"]),
        obj("intrusion-set", "g32", "G0032", "Lazarus Group", "A group.", aliases=["Lazarus Group", "HIDDEN COBRA"]),
        obj("intrusion-set", "g9010", "G9010", "Remote Team", "A group.", aliases=["Remote Team"]),
        obj("intrusion-set", "g9011", "G9011", "Carbon Team", "A group.", aliases=["Carbon Team"]),
        obj("malware", "s9012", "S9012", "Carbon", "Carbon is a backdoor.", x_mitre_aliases=["Carbon"], is_family=True),
        obj("malware", "s1199", "S1199", "LockBit 2.0", "Ransomware.", x_mitre_aliases=["LockBit 2.0"], is_family=True),
        obj("malware", "s1202", "S1202", "LockBit 3.0", "Ransomware.", x_mitre_aliases=["LockBit 3.0", "LockBit Black"],
            is_family=True),
        obj("malware", "s9013", "S9013", "T9000", "Glued digits are part of the name.", is_family=True),
        # software
        obj("tool", "s154", "S0154", "Cobalt Strike", "[Cobalt Strike](https://attack.mitre.org/software/S0154) is a "
            "commercial framework.(Citation: cobaltstrike manual)", x_mitre_aliases=["Cobalt Strike", "CobaltStrike"],
            x_mitre_platforms=["Windows", "Linux"]),
        obj("tool", "s039", "S0039", "Net", "The net utility is part of Windows.", x_mitre_aliases=["Net", "net.exe"]),
        obj("tool", "s110", "S0110", "at", "at schedules tasks.", x_mitre_aliases=["at", "at.exe"]),
        obj("malware", "s046", "S0046", "CozyCar", "CozyCar is malware used by APT29.",
            x_mitre_aliases=["CozyCar", "CozyDuke", "Cozy Bear"], is_family=True),
        obj("malware", "s9003", "S9003", "Attacker", "A test malware with a common word as name.", is_family=True),
        obj("malware", "s9004", "S9004", "BADNEWS", "BADNEWS is malware.", is_family=True),
        obj("malware", "s9005", "S9005", "OldBeacon", "Renamed.", revoked=True, x_mitre_aliases=["OldBeacon"]),
        # techniques
        tech("t1059", "T1059", "Command and Scripting Interpreter"),
        tech("t1059001", "T1059.001", "PowerShell", desc="Adversaries may abuse PowerShell (T1059.001)."),
        tech("t1086", "T1086", "PowerShell", revoked=True),
        tech("t1021", "T1021", "Remote Services", tactic="lateral-movement"),
        tech("t1021002", "T1021.002", "SMB/Windows Admin Shares", tactic="lateral-movement"),
        tech("t1087", "T1087", "Account Discovery"),
        tech("t1087002", "T1087.002", "Domain Account"),
        tech("t1136", "T1136", "Create Account"),
        tech("t1136002", "T1136.002", "Domain Account"),
        tech("t1190", "T1190", "Exploit Public-Facing Application"),
        tech("t9999", "T9999", "Old Technique", deprecated=True),
        # mitigations, including a legacy mitigation that reuses a technique ID
        obj("course-of-action", "m1042", "M1042", "Disable or Remove Feature or Program", "Remove features."),
        obj("course-of-action", "legacy", "T1059", "Command-Line Interface Mitigation", "Legacy.", deprecated=True),
        # campaign
        obj("campaign", "c24", "C0024", "SolarWinds Compromise", "A campaign.", aliases=["SolarWinds Compromise"],
            first_seen="2019-08-01T05:00:00.000Z", last_seen="2021-01-01T05:00:00.000Z"),
        # an object of an included type without an ATT&CK ID
        obj("malware", "noid", None, "Nameless"),
    ]
    T = lambda s: f"attack-pattern--{s}"  # noqa: E731
    rels = [
        rel("u1", G16, "uses", T("t1059001"), "[APT29](https://attack.mitre.org/groups/G0016) used PowerShell "
            "after exploiting CVE-2018-6116.(Citation: x)",
            refs=[{"source_name": "Report", "description": "Exploitation of CVE-2021-0001 seen."}]),
        rel("u2", G16, "uses", "tool--s154"),
        rel("u3", "tool--s154", "uses", T("t1059001")),
        rel("u4", "tool--s154", "uses", T("t1021002")),
        rel("u5", G07, "uses", T("t1086"), "APT28 used PowerShell via CVE-2018-0001."),  # revoked target -> redirect
        rel("u6", G16, "uses", T("t1086")),                    # redirect duplicates u1 -> dropped
        rel("u7", G16, "uses", T("t9999"), "Mentions CVE-2021-0002."),  # deprecated endpoint -> dropped
        rel("u8", "campaign--c24", "uses", "tool--s154"),
        rel("u9", "campaign--c24", "attributed-to", G16),
        rel("u10", "intrusion-set--g9002", "uses", T("t1190")),  # deprecated source
        rel("s1", T("t1059001"), "subtechnique-of", T("t1059")),
        rel("s2", T("t1021002"), "subtechnique-of", T("t1021")),
        rel("s3", T("t1087002"), "subtechnique-of", T("t1087")),
        rel("s4", T("t1136002"), "subtechnique-of", T("t1136")),
        rel("m1", "course-of-action--m1042", "mitigates", T("t1059001")),
        rel("m2", "course-of-action--legacy", "mitigates", T("t1059")),  # legacy mitigation not stored
        rel("r1", T("t1086"), "revoked-by", T("t1059001")),
        rel("r2", "intrusion-set--g9001", "revoked-by", G16),
        rel("r3", "malware--s9005", "revoked-by", "tool--s154"),
        rel("d1", "x-mitre-detection-strategy--d1", "detects", T("t1059001")),
        rel("x1", G07, "uses", "tool--missing"),
        rel("x2", G07, "uses", "tool--s039", revoked=True),
        rel("x3", G07, "uses", "tool--s110", x_mitre_deprecated=True),
    ]
    return {"type": "bundle", "id": "bundle--test", "objects": objs + rels}


def kev_mappings() -> dict:
    def m(cve, tech_id, mtype, name="x"):
        return {"capability_id": cve, "capability_description": f"{cve} vulnerability", "mapping_type": mtype,
                "attack_object_id": tech_id, "attack_object_name": name, "capability_group": "code_execution",
                "comments": "test", "references": ["https://example.org"], "status": "complete"}
    return {"metadata": {"attack_version": "16.1", "mapping_framework": "kev", "mapping_framework_version": "07/28/2025",
                         "technology_domain": "enterprise", "creation_date": "07/28/2025", "last_update": "08/28/2025"},
            "mapping_objects": [
                m("CVE-2021-44228", "T1190", "exploitation_technique"),
                m("CVE-2021-44228", "T1086", "primary_impact"),     # revoked -> T1059.001
                m("CVE-2021-0004", "T9999", "primary_impact"),      # deprecated technique
                m("CVE-2030-0001", "T1190", "exploitation_technique"),  # not in the store
                m("CVE-2021-0004", "T1234", "secondary_impact"),    # not in the build
                m("CVE-2021-44228", "T1190", "exploitation_technique"),  # duplicate
                m("CVE-2018-0001", "T1190", "exploitation_technique"),   # rejected CVE in the store
            ]}


def _write_source(root: Path, name: str, files: dict[str, bytes], licence: str, upstream: dict) -> Path:
    d = root / name / "2026-11-14"
    raw = d / "raw"
    listing = []
    for rel_path, data in files.items():
        p = raw / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        listing.append({"path": rel_path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    (d / "manifest.json").write_text(json.dumps({
        "source": name, "role": "attack", "status": "ok", "reason": None,
        "license": {"name": licence, "url": "https://example.org/licence", "permits": "test"},
        "raw_files": listing, "retrieved_at_utc": "2026-11-14T00:00:00Z", "upstream_version": upstream}),
        encoding="utf-8")
    (root / name / "LATEST").write_text("2026-11-14\n", encoding="utf-8")
    return d


def make_attack_sources(root: Path, kev_licence: str = "Apache-2.0", bundle_obj: dict | None = None) -> Path:
    src = root / "attack_sources"
    _write_source(src, "attack_enterprise", {
        "enterprise-attack.json": json.dumps(bundle_obj or bundle()).encode("utf-8"),
        "LICENSE.txt": b"Copyright The MITRE Corporation. Test licence text."},
        ATTACK_LICENCE, {"attack_version": "20.1", "commit": "test"})
    _write_source(src, "kev_attack_mappings", {f"mappings-explorer/{KEV_FILE}": json.dumps(kev_mappings()).encode()},
                  kev_licence, {"attack_version": "16.1", "mapping_file": KEV_FILE})
    return src


# A policy with a low common-word threshold, so the miniature store can exercise the rule:
# "attacker" is written in lower case in two fixture CVE descriptions.
def low_df_policy() -> dict:
    from threat_retrieval_engine.attack.gazetteer import POLICY
    p = json.loads(json.dumps(POLICY))
    p["corpus_term_min_df"] = 2
    return p
