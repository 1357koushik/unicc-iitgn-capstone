"""SigmaHQ detection rules carrying a CVE tag or reference (role: query)."""
from __future__ import annotations

import os
from pathlib import Path

from collect_common import (Context, SourceSpec, find_cves, git_clone, git_finish, git_head,
                            git_sparse_set)

REPO = "https://github.com/SigmaHQ/sigma.git"
RULE_DIRS = ["rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance",
             "rules-dfir", "rules-placeholder"]
SPEC = SourceSpec(
    name="sigma_rules",
    role="query",
    urls=[REPO],
    license_name="Detection Rule License (DRL) 1.1",
    license_url="https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md",
    license_note=("DRL 1.1: use, modify, store and redistribute rules provided the rule author is attributed "
                  "(keep the `author` field); deriving queries from titles is permitted."),
    description="Sigma rule YAML (rules* dirs, sparse shallow clone); rules with a cve.* tag or CVE reference.",
)


def parse_sigma_doc(doc: dict, path: str, cve_normalizer) -> dict | None:
    if not isinstance(doc, dict) or not doc.get("title"):
        return None
    tags = [str(t) for t in doc.get("tags") or []]
    refs = [str(r) for r in doc.get("references") or []]
    raw: list[str] = []
    for t in tags:
        tl = t.lower()
        if tl.startswith("cve."):
            raw.append("CVE-" + tl[4:].replace(".", "-", 1))
    for r in refs:
        raw.extend(find_cves(r))
    if not raw:
        return None
    return {
        "rule_id": doc.get("id"),
        "title": str(doc["title"]),
        "description": str(doc.get("description") or "").strip(),
        "cve_ids": cve_normalizer(raw),
        "tags": tags,
        "path": path,
        "status": doc.get("status"),
        "level": doc.get("level"),
        "author": doc.get("author"),
    }


def collect(ctx: Context):
    import yaml

    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    repo = ctx.raw_dir / "sigma"
    ctx.log("sparse shallow clone of rule directories")
    git_clone(REPO, repo, sparse=True)
    git_sparse_set(repo, RULE_DIRS)
    ctx.upstream["commit"] = git_head(repo)
    git_finish(repo)
    n_files = parse_errors = 0
    out = []
    for d in RULE_DIRS:
        for r, _dirs, fs in os.walk(repo / d):
            for fn in sorted(fs):
                if not fn.endswith((".yml", ".yaml")):
                    continue
                n_files += 1
                p = Path(r) / fn
                rel = str(p.relative_to(repo)).replace("\\", "/")
                try:
                    docs = list(yaml.load_all(p.read_text(encoding="utf-8"), Loader=loader))
                except Exception:
                    parse_errors += 1
                    continue
                for doc in docs:
                    rec = parse_sigma_doc(doc, rel, ctx.cves)
                    if rec and rec["cve_ids"]:
                        out.append(rec)
    ctx.extra.update({"yaml_files_scanned": n_files, "yaml_parse_errors": parse_errors})
    out.sort(key=lambda d: (d["path"], d["rule_id"] or ""))
    yield from out
