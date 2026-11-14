"""CTID KEV-to-ATT&CK mappings from mappings-explorer (role: attack)."""
from __future__ import annotations

import json
import re

from collect_common import (CollectError, Context, SourceSpec, git_clone, git_finish, git_head,
                            git_sparse_set)

REPO = "https://github.com/center-for-threat-informed-defense/mappings-explorer.git"
SPEC = SourceSpec(
    name="kev_attack_mappings",
    role="attack",
    urls=[REPO, "https://center-for-threat-informed-defense.github.io/mappings-explorer/"],
    license_name="Apache-2.0",
    license_url="https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/main/LICENSE.txt",
    license_note=("Apache 2.0: storing, deriving and redistributing is allowed with licence and notice kept. "
                  "Underlying KEV catalogue is a CISA public list."),
    description="mappings/kev/<attack-version>/<kev-version>/enterprise JSON (latest versions); one record per mapping.",
)


def parse_mappings(doc: dict, cve_normalizer) -> list[dict]:
    meta = doc.get("metadata") or {}
    out = []
    for o in doc.get("mapping_objects") or []:
        cves = cve_normalizer([o.get("capability_id")])
        tid = o.get("attack_object_id")
        if not cves or not tid:
            continue
        out.append({
            "cve_id": cves[0],
            "attack_technique_id": tid,
            "attack_technique_name": o.get("attack_object_name"),
            "mapping_type": o.get("mapping_type"),
            "capability_group": o.get("capability_group"),
            "status": o.get("status"),
            "attack_version": meta.get("attack_version"),
            "kev_version": meta.get("mapping_framework_version"),
        })
    out.sort(key=lambda r: (r["cve_id"], r["attack_technique_id"], r["mapping_type"] or ""))
    return out


def _ver(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s))


def pick_latest(repo_kev) -> object:
    """Highest attack-X.Y dir, then newest kev-MM.DD.YYYY dir (date order), enterprise JSON inside."""
    attack_dirs = sorted((d for d in repo_kev.iterdir() if d.name.startswith("attack-")),
                         key=lambda d: _ver(d.name))
    if not attack_dirs:
        raise CollectError("no attack-* directory under mappings/kev")
    kev_dirs = [d for d in attack_dirs[-1].iterdir() if d.name.startswith("kev-")]
    kev_dirs.sort(key=lambda d: (_ver(d.name)[2:3], _ver(d.name)[:2]))
    files = sorted((kev_dirs[-1] / "enterprise").glob("*.json"))
    if not files:
        raise CollectError(f"no enterprise JSON in {kev_dirs[-1]}")
    return files[0]


def collect(ctx: Context):
    repo = ctx.raw_dir / "mappings-explorer"
    ctx.log("sparse shallow clone of mappings/kev")
    git_clone(REPO, repo, sparse=True)
    git_sparse_set(repo, ["mappings/kev"])
    ctx.upstream["commit"] = git_head(repo)
    git_finish(repo)
    f = pick_latest(repo / "mappings" / "kev")
    ctx.upstream["mapping_file"] = str(f.relative_to(repo)).replace("\\", "/")
    doc = json.loads(f.read_text(encoding="utf-8"))
    ctx.upstream["attack_version"] = (doc.get("metadata") or {}).get("attack_version")
    ctx.upstream["kev_version"] = (doc.get("metadata") or {}).get("mapping_framework_version")
    recs = parse_mappings(doc, ctx.cves)
    ctx.extra["mapping_objects_total"] = len(doc.get("mapping_objects") or [])
    ctx.extra["distinct_cves"] = len({r["cve_id"] for r in recs})
    yield from recs
