"""Metasploit module metadata (role: expansion)."""
from __future__ import annotations

import json
import re

from collect_common import (Context, SourceSpec, git_ls_remote_head, http_download)

REPO = "https://github.com/rapid7/metasploit-framework.git"
RAW = "https://raw.githubusercontent.com/rapid7/metasploit-framework/{ref}/{path}"
SPEC = SourceSpec(
    name="metasploit_modules",
    role="expansion",
    urls=[RAW.format(ref="master", path="db/modules_metadata_base.json"), REPO],
    license_name="BSD-3-Clause",
    license_url="https://github.com/rapid7/metasploit-framework/blob/master/COPYING",
    license_note=("BSD 3-clause: storing, deriving and redistributing metadata is allowed provided the copyright "
                  "notice is kept; no endorsement implied."),
    description="db/modules_metadata_base.json; modules with at least one CVE reference.",
)


def parse_modules(data: dict, cve_normalizer) -> tuple[list[dict], int]:
    out = []
    for key, m in data.items():
        refs = [r for r in m.get("references") or [] if isinstance(r, str) and r.upper().startswith("CVE-")]
        cves = cve_normalizer(refs)
        if not cves:
            continue
        out.append({
            "module_path": m.get("fullname") or key,
            "name": m.get("name") or "",
            "description": re.sub(r"\s+", " ", m.get("description") or "").strip(),
            "cve_ids": cves,
            "rank": m.get("rank"),
            "disclosure_date": m.get("disclosure_date"),
            "type": m.get("type"),
        })
    out.sort(key=lambda r: r["module_path"])
    return out, len(data)


def collect(ctx: Context):
    sha = git_ls_remote_head(REPO)
    ctx.upstream["commit"] = sha
    info = http_download(RAW.format(ref=sha, path="db/modules_metadata_base.json"),
                         ctx.raw_dir / "modules_metadata_base.json")
    ctx.upstream.update({"etag": info["etag"], "sha256": info["sha256"]})
    http_download(RAW.format(ref=sha, path="COPYING"), ctx.raw_dir / "COPYING")
    data = json.loads((ctx.raw_dir / "modules_metadata_base.json").read_text(encoding="utf-8"))
    recs, total = parse_modules(data, ctx.cves)
    ctx.extra["modules_total"] = total
    yield from recs
