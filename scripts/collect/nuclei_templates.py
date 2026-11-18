"""projectdiscovery/nuclei-templates CVE templates (role: expansion)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from collect_common import (Context, SourceSpec, git_clone, git_finish, git_head,
                            git_sparse_set)

REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
SPEC = SourceSpec(
    name="nuclei_templates",
    role="expansion",
    urls=[REPO],
    license_name="MIT",
    license_url="https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md",
    license_note=("MIT: storing, deriving and redistributing is allowed with the copyright notice kept."),
    description="cves.json index joined with YAML template headers (tags); sparse shallow clone.",
)


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    return [x.strip() for x in str(v).split(",") if x.strip()]


def parse_template(index_row: dict | None, yaml_doc: dict | None, path: str, cve_normalizer) -> dict | None:
    """Merge one cves.json row (may be None) with the template YAML (may be None)."""
    info_idx = (index_row or {}).get("Info") or {}
    info_y = (yaml_doc or {}).get("info") or {}
    tid = (index_row or {}).get("ID") or (yaml_doc or {}).get("id")
    if not tid:
        return None
    raw = [tid]
    cls = info_y.get("classification") or {}
    raw += [c for c in _as_list(cls.get("cve-id")) if str(c).upper().startswith("CVE")]
    cves = cve_normalizer(raw)
    if not cves:
        return None
    return {
        "template_id": tid,
        "name": info_idx.get("Name") or info_y.get("name") or "",
        "cve_ids": cves,
        "severity": info_idx.get("Severity") or info_y.get("severity"),
        "tags": [str(t) for t in _as_list(info_y.get("tags"))],
        "path": path,
    }


def collect(ctx: Context):
    import yaml

    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    repo = ctx.raw_dir / "nuclei-templates"
    ctx.log("sparse shallow clone")
    git_clone(REPO, repo, sparse=True)
    ctx.upstream["commit"] = git_head(repo)
    index_file = repo / "cves.json"
    index: list[dict] = []
    if index_file.exists():
        for line in index_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                index.append(json.loads(line))
        dirs = sorted({"/".join(Path(r["file_path"]).parts[:2]) for r in index if r.get("file_path")})
        ctx.extra["index"] = "cves.json"
    else:
        dirs = ["http/cves", "network/cves", "dns/cves", "file/cves", "code/cves"]
        ctx.extra["index"] = "none (YAML headers parsed)"
    git_sparse_set(repo, dirs)
    git_finish(repo)
    ctx.extra["template_dirs"] = dirs

    def load(rel: str):
        p = repo / rel
        if not p.exists():
            return None
        try:
            return yaml.load(p.read_text(encoding="utf-8"), Loader=loader)
        except Exception:
            ctx.extra["yaml_parse_errors"] = ctx.extra.get("yaml_parse_errors", 0) + 1
            return None

    out = []
    if index:
        for row in index:
            rel = row.get("file_path", "")
            rec = parse_template(row, load(rel) if rel else None, rel, ctx.cves)
            if rec:
                out.append(rec)
    else:
        for d in dirs:
            for r, _dd, fs in os.walk(repo / d):
                for fn in fs:
                    if fn.startswith("CVE-") and fn.endswith(".yaml"):
                        rel = str((Path(r) / fn).relative_to(repo)).replace("\\", "/")
                        rec = parse_template(None, load(rel), rel, ctx.cves)
                        if rec:
                            out.append(rec)
    seen = {}
    for r in out:
        seen[r["template_id"]] = r
    for k in sorted(seen):
        yield seen[k]
