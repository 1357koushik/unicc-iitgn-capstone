"""GitHub Advisory Database, reviewed advisories only (role: query)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from collect_common import (Context, SourceSpec, git_clone, git_finish, git_head,
                            git_sparse_set, http_get_text, long_path)

REPO = "https://github.com/github/advisory-database.git"
RAW = "https://raw.githubusercontent.com/github/advisory-database/{commit}/{path}"
SPEC = SourceSpec(
    name="ghsa_reviewed",
    role="query",
    urls=[REPO, "https://github.com/github/advisory-database/tree/main/advisories/github-reviewed"],
    license_name="CC-BY-4.0",
    license_url="https://creativecommons.org/licenses/by/4.0/",
    license_note=("CC-BY 4.0: storing, deriving benchmark queries and redistribution are allowed "
                  "with attribution to the GitHub Advisory Database."),
    description="OSV-format reviewed GitHub security advisories (sparse shallow clone of advisories/github-reviewed).",
)


def parse_advisory(doc: dict, cve_normalizer) -> dict | None:
    """Pure parser for one OSV advisory document. `cve_normalizer(list)->list` normalises CVE aliases."""
    gid = doc.get("id")
    if not gid:
        return None
    aliases = [a for a in doc.get("aliases") or [] if isinstance(a, str) and a.upper().startswith("CVE")]
    pkgs = set()
    for aff in doc.get("affected") or []:
        p = (aff or {}).get("package") or {}
        if p.get("name"):
            pkgs.add((p.get("ecosystem") or "", p["name"]))
    return {
        "ghsa_id": gid,
        "cve_ids": cve_normalizer(aliases),
        "summary": doc.get("summary") or "",
        "details": doc.get("details") or "",
        "packages": [{"ecosystem": e, "name": n} for e, n in sorted(pkgs)],
        "published": doc.get("published"),
        "modified": doc.get("modified"),
        "withdrawn": doc.get("withdrawn"),
        "severity": (doc.get("database_specific") or {}).get("severity"),
    }


def collect(ctx: Context):
    repo = ctx.raw_dir / "advisory-database"
    ctx.log("sparse shallow clone of advisories/github-reviewed")
    git_clone(REPO, repo, sparse=True)
    git_sparse_set(repo, ["advisories/github-reviewed"])
    ctx.upstream["commit"] = git_head(repo)
    git_finish(repo)
    base = repo / "advisories" / "github-reviewed"
    files = sorted(Path(r) / f for r, _d, fs in os.walk(long_path(base)) for f in fs if f.endswith(".json"))
    ctx.log(f"{len(files)} advisory files")
    with_cve = 0
    fetched_over_http: list[str] = []
    commit = ctx.upstream["commit"]
    for p in files:
        try:
            with open(p, encoding="utf-8") as fh:  # p already carries the \\?\ prefix
                doc = json.load(fh)
        except OSError:
            # Some advisories describe malware; a local antivirus may block the checked-out file.
            # Re-read the identical blob from the pinned commit in memory (not saved to disk).
            rel = str(p).split("\\advisory-database\\", 1)[1].replace("\\", "/")
            fetched_over_http.append(rel)
            ctx.log(f"local file unreadable, fetching from upstream commit: {rel}")
            doc = json.loads(http_get_text(RAW.format(commit=commit, path=rel)))
        rec = parse_advisory(doc, ctx.cves)
        if rec:
            with_cve += bool(rec["cve_ids"])
            yield rec
    ctx.extra["records_with_cve"] = with_cve
    ctx.extra["locally_unreadable_files_fetched_from_upstream"] = fetched_over_http
    ctx.extra["selection"] = "all advisories/github-reviewed; records without CVE alias kept with empty cve_ids"
