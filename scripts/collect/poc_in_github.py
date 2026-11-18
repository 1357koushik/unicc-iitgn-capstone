"""nomi-sec/PoC-in-GitHub aggregated PoC repository list (role: expansion)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from collect_common import (Context, SourceSpec, git_clone, git_finish, git_head)

REPO = "https://github.com/nomi-sec/PoC-in-GitHub.git"
SPEC = SourceSpec(
    name="poc_in_github",
    role="expansion",
    urls=[REPO],
    license_name="CC0-1.0 (list); linked repositories keep their own licences",
    license_url="https://github.com/nomi-sec/PoC-in-GitHub/blob/master/LICENSE",
    license_note=("CC0 for the list itself: storing and redistributing is allowed. Repository descriptions come from "
                  "GitHub users and are untrusted; the list contains fake and malicious PoCs, so entries are "
                  "candidates only, never trusted."),
    description="Per-CVE JSON files of GitHub repositories (shallow clone, year directories).",
)


def parse_poc_file(cve_file_id: str, repos: list, cve_normalizer) -> list[dict]:
    """One CVE-*.json file (list of GitHub repo objects) -> records."""
    cves = cve_normalizer([cve_file_id])
    if not cves or not isinstance(repos, list):
        return []
    out = []
    seen = set()
    for r in repos:
        if not isinstance(r, dict) or not r.get("full_name") or r["full_name"] in seen:
            continue
        seen.add(r["full_name"])
        out.append({
            "cve_id": cves[0],
            "full_name": r["full_name"],
            "html_url": r.get("html_url"),
            "description": r.get("description"),
            "stars": r.get("stargazers_count"),
            "created_at": r.get("created_at"),
            "updated_at": r.get("updated_at"),
            "fork": bool(r.get("fork")),
        })
    return out


def collect(ctx: Context):
    repo = ctx.raw_dir / "PoC-in-GitHub"
    ctx.log("shallow clone")
    git_clone(REPO, repo, sparse=False)
    ctx.upstream["commit"] = git_head(repo)
    git_finish(repo)
    out = []
    n_files = 0
    for ydir in sorted(p for p in repo.iterdir() if p.is_dir() and re.fullmatch(r"\d{4}", p.name)):
        for r, _d, fs in os.walk(ydir):
            for fn in fs:
                if not fn.endswith(".json"):
                    continue
                n_files += 1
                data = json.loads((Path(r) / fn).read_text(encoding="utf-8"))
                out.extend(parse_poc_file(fn[:-5], data, ctx.cves))
    ctx.extra["cve_files"] = n_files
    out.sort(key=lambda d: (d["cve_id"], d["full_name"].lower()))
    yield from out
