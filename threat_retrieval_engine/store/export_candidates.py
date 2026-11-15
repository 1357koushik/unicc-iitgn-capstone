"""Export the nickname candidates of a built store for vetting.

    python -m threat_retrieval_engine.store.export_candidates [--store DIR] [--out FILE] [--status pending]

Writes one JSON line per candidate (alias_norm, sorted cve_ids) with its evidence (source, record ID,
position, the form found, and a snippet: the exploit title, PoC repository, reference URL or the CVE's own
text) and, per CVE, the title, vendor/product and the start of the description, so a judge can decide
whether the name really denotes those CVEs. The build writes the same file to
data/store/<build>/nickname_candidates.jsonl.

Verdicts go to threat_retrieval_engine/store/data/nickname_verdicts.jsonl, one line per candidate:
{alias_norm, cve_ids, verdict: accept|reject, judge, adjudicator, date, evidence_sha256}; the
evidence_sha256 must be copied from the candidate line, so a verdict lapses when the evidence changes.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

from .reader import resolve_build


def iter_candidates(db: sqlite3.Connection, status: str | None = None):
    where = "WHERE status = ?" if status else ""
    rows = db.execute(
        "SELECT alias_norm, group_alias, group_cves, evidence_sha256, status, cve_id, alias, source, "
        f"source_record_id, position, record_cves, snippet FROM alias_candidates {where} "
        "ORDER BY alias_norm, group_cves, cve_id, source, source_record_id, position, alias",
        (status,) if status else ()).fetchall()
    groups: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for norm, galias, gcves, sha, st, cid, alias, src, rid, pos, n, snip in rows:
        key = (norm, gcves)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"alias_norm": norm, "alias": galias, "cve_ids": gcves.split(","),
                               "evidence_sha256": sha, "status": st, "evidence": []}
            order.append(key)
        g["evidence"].append({"cve_id": cid, "source": src, "record_id": rid, "position": pos, "form": alias,
                              "record_cves": n, "snippet": snip})
    cve_info: dict[str, dict] = {}
    ids = sorted({c for g in groups.values() for c in g["cve_ids"]})
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        for cid, title, vp, desc in db.execute(
                f"SELECT cve_id, title, vendor_product, description FROM cve WHERE cve_id IN "
                f"({','.join('?' * len(part))})", part):
            cve_info[cid] = {"cve_id": cid, "title": title, "vendor_product": vp, "description": (desc or "")[:400]}
    for key in order:
        g = groups[key]
        g["cves"] = [cve_info.get(c, {"cve_id": c}) for c in g["cve_ids"]]
        yield g


def write_candidates(store_db: Path, out: Path, status: str | None = None) -> int:
    db = sqlite3.connect(f"file:{Path(store_db).as_posix()}?mode=ro", uri=True)
    n = 0
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        for g in iter_candidates(db, status):
            f.write(json.dumps(g, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    db.close()
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", type=Path, default=None, help="build directory or store root (default data/store)")
    ap.add_argument("--out", type=Path, default=None, help="default <build>/nickname_candidates.jsonl")
    ap.add_argument("--status", choices=["pending", "accepted", "rejected", "stale"], default=None)
    a = ap.parse_args(argv)
    bdir = resolve_build(a.store)
    out = a.out or bdir / "nickname_candidates.jsonl"
    n = write_candidates(bdir / "store.sqlite", out, a.status)
    print(f"wrote {n} candidates to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
