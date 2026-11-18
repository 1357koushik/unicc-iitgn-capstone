"""MITRE CWE catalogue: ID, name, kind and status of every weakness, category and view (role: expansion).

Used by the C1 document store to turn the CWE IDs carried by NVD, the CVE List and KEV into readable
weakness names. One record per CWE entry, deprecated entries included (NVD still cites some of them).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from collect_common import CollectError, Context, SourceSpec, http_download

URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
TERMS_URL = "https://cwe.mitre.org/about/termsofuse.html"
SPEC = SourceSpec(
    name="cwe_catalog",
    role="expansion",
    urls=[URL, TERMS_URL],
    license_name="CWE Terms of Use (royalty-free licence)",
    license_url=TERMS_URL,
    license_note=("MITRE grants a non-exclusive, royalty-free licence to use CWE for research, development and "
                  "commercial purposes; any copy must reproduce MITRE's copyright designation and the licence. "
                  "Storing the catalogue and using CWE names as document text is permitted."),
    description="cwec_latest.xml.zip; one record per Weakness, Category/Grouping and View (ID, name, kind, status).",
)

# CWE schema 8 (CWE 5.0) renamed Category to Grouping; both are accepted.
_KINDS = {"Weakness": "weakness", "Category": "category", "Grouping": "grouping", "View": "view"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_catalog(xml_bytes: bytes) -> tuple[list[dict], dict]:
    """Records sorted by numeric ID, plus catalogue metadata (name, version, date)."""
    root = ET.fromstring(xml_bytes)
    if _local(root.tag) != "Weakness_Catalog":
        raise CollectError(f"unexpected CWE root element {_local(root.tag)!r}")
    meta = {"catalog_name": root.get("Name"), "cwe_version": root.get("Version"), "catalog_date": root.get("Date")}
    out: dict[int, dict] = {}
    for el in root.iter():
        kind = _KINDS.get(_local(el.tag))
        if kind is None or el.get("ID") is None or el.get("Name") is None:
            continue
        if not re.fullmatch(r"\d{1,5}", el.get("ID", "")):
            continue
        num = int(el.get("ID"))
        rec = {"cwe_id": f"CWE-{num}", "name": re.sub(r"\s+", " ", el.get("Name")).strip(), "kind": kind,
               "status": el.get("Status")}
        if kind == "weakness":
            rec["abstraction"] = el.get("Abstraction")
        if num in out:
            raise CollectError(f"duplicate CWE ID {num} in catalogue")
        out[num] = rec
    if not out:
        raise CollectError("no CWE entries parsed")
    return [out[k] for k in sorted(out)], meta


def read_zip(path: Path) -> bytes:
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".xml")]
        if len(names) != 1:
            raise CollectError(f"expected one XML file in {path.name}, found {names}")
        return z.read(names[0])


def collect(ctx: Context):
    info = http_download(URL, ctx.raw_dir / "cwec_latest.xml.zip")
    ctx.upstream.update({"sha256": info["sha256"], "etag": info["etag"], "last_modified": info["last_modified"]})
    terms = http_download(TERMS_URL, ctx.raw_dir / "termsofuse.html")
    ctx.extra["terms_page_sha256"] = terms["sha256"]
    recs, meta = parse_catalog(read_zip(ctx.raw_dir / "cwec_latest.xml.zip"))
    ctx.upstream["cwe_version"] = meta["cwe_version"]
    ctx.extra.update(meta)
    ctx.extra["counts"] = {k: sum(1 for r in recs if r["kind"] == k) for k in sorted(set(_KINDS.values()))}
    ctx.log(f"CWE {meta['cwe_version']} ({meta['catalog_date']}): {len(recs)} entries {ctx.extra['counts']}")
    yield from recs
