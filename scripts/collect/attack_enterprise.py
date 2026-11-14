"""MITRE ATT&CK Enterprise STIX 2.1 bundle (role: attack)."""
from __future__ import annotations

import json
from collections import Counter

from collect_common import (Context, SourceSpec, find_cves, git_ls_remote_head, http_download)

REPO = "https://github.com/mitre-attack/attack-stix-data.git"
RAW = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ref}/{path}"
SPEC = SourceSpec(
    name="attack_enterprise",
    role="attack",
    urls=[RAW.format(ref="master", path="enterprise-attack/enterprise-attack.json"), REPO],
    license_name="MITRE ATT&CK Terms of Use (royalty-free licence)",
    license_url="https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
    license_note=("Non-exclusive royalty-free licence for research, development and commercial use; any copy must "
                  "reproduce MITRE's copyright notice and the licence (kept in raw/LICENSE.txt). Storing and "
                  "ingesting as documents is permitted."),
    description="enterprise-attack.json STIX bundle; records are groups, software, techniques, mitigations, relationships.",
)

KIND = {"intrusion-set": "group", "malware": "software", "tool": "software",
        "attack-pattern": "technique", "course-of-action": "mitigation", "relationship": "relationship"}


def attack_id(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") in ("mitre-attack",) and ref.get("external_id"):
            return ref["external_id"], ref.get("url")
    return None, None


def parse_object(obj: dict, cve_normalizer) -> dict | None:
    kind = KIND.get(obj.get("type"))
    if kind is None:
        return None
    base = {"stix_id": obj["id"], "stix_type": obj["type"], "kind": kind,
            "revoked": bool(obj.get("revoked")), "deprecated": bool(obj.get("x_mitre_deprecated"))}
    if kind == "relationship":
        base.update({"relationship_type": obj.get("relationship_type"),
                     "source_ref": obj.get("source_ref"), "target_ref": obj.get("target_ref")})
        return base
    aid, url = attack_id(obj)
    text_cves = find_cves(obj.get("description"))
    for ref in obj.get("external_references") or []:
        text_cves += find_cves(" ".join(str(ref.get(k, "")) for k in ("url", "description", "external_id")))
    names = obj.get("aliases") or obj.get("x_mitre_aliases") or []
    base.update({
        "attack_id": aid, "url": url, "name": obj.get("name"),
        "aliases": [a for a in names if a != obj.get("name")],
        "description": obj.get("description") or "",
        "cve_ids": cve_normalizer(text_cves) if text_cves else [],
        "platforms": obj.get("x_mitre_platforms") or [],
        "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")) if kind == "technique" else None,
    })
    return base


def collect(ctx: Context):
    sha = git_ls_remote_head(REPO)
    ctx.upstream["commit"] = sha
    path = "enterprise-attack/enterprise-attack.json"
    info = http_download(RAW.format(ref=sha, path=path), ctx.raw_dir / "enterprise-attack.json")
    ctx.upstream.update({"etag": info["etag"], "sha256": info["sha256"]})
    http_download(RAW.format(ref=sha, path="LICENSE.txt"), ctx.raw_dir / "LICENSE.txt")
    bundle = json.loads((ctx.raw_dir / "enterprise-attack.json").read_text(encoding="utf-8"))
    if bundle.get("type") != "bundle":
        raise ValueError("enterprise-attack.json is not a STIX bundle")
    for o in bundle["objects"]:
        if o.get("type") == "x-mitre-collection":
            ctx.upstream["attack_version"] = o.get("x_mitre_version")
            ctx.upstream["collection_modified"] = o.get("modified")
    counts: Counter = Counter()
    active: Counter = Counter()
    out = []
    for o in bundle["objects"]:
        rec = parse_object(o, ctx.cves)
        if rec:
            counts[rec["kind"]] += 1
            if not rec["revoked"] and not rec["deprecated"]:
                active[rec["kind"]] += 1
            out.append(rec)
    ctx.extra["counts"] = dict(counts)
    ctx.extra["counts_active_not_revoked_or_deprecated"] = dict(active)
    ctx.extra["objects_with_cve_ids"] = sum(1 for r in out if r.get("cve_ids"))
    out.sort(key=lambda r: (r["kind"], r["stix_id"]))
    yield from out
