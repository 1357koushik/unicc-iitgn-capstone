"""Counts and coverage figures for a built store (written into manifest.json and printed by check_c1)."""
from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict


def _q(db: sqlite3.Connection, sql: str, *args):
    return db.execute(sql, args).fetchone()[0]


def store_report(db: sqlite3.Connection, kev_rows: dict | None = None, epss_rows: dict | None = None) -> dict:
    r: dict = {}
    r["universe"] = _q(db, "SELECT COUNT(*) FROM cve")
    r["by_state"] = dict(db.execute("SELECT state, COUNT(*) FROM cve GROUP BY state ORDER BY state").fetchall())
    r["searchable"] = _q(db, "SELECT COUNT(*) FROM cve WHERE searchable = 1")
    r["not_searchable_by_reason"] = {
        f"{s}/{k}": n for s, k, n in db.execute(
            "SELECT state, description_kind, COUNT(*) FROM cve WHERE searchable = 0 GROUP BY 1, 2 ORDER BY 1, 2")}
    r["published_without_usable_description"] = _q(
        db, "SELECT COUNT(*) FROM cve WHERE state = 'published' AND searchable = 0")
    combos = Counter()
    present = Counter()
    for (s,) in db.execute("SELECT sources FROM cve"):
        combos[s] += 1
        for x in s.split(","):
            present[x] += 1
    r["rows_with_source"] = dict(sorted(present.items()))
    r["rows_by_source_combination"] = dict(combos.most_common())
    total_s = r["searchable"] or 1
    ds = dict(db.execute("SELECT description_source, COUNT(*) FROM cve WHERE searchable = 1 GROUP BY 1").fetchall())
    r["description_source_searchable"] = {k: {"count": v, "share": round(v / total_s, 4)} for k, v in sorted(ds.items())}
    r["description_cna_differs_from_nvd"] = _q(
        db, "SELECT COUNT(*) FROM cve WHERE searchable = 1 AND "
            "json_extract(provenance, '$.fields.description_nvd_differs') = 1")

    # vendor/product coverage per publication year (searchable rows)
    per_year: dict[str, Counter] = defaultdict(Counter)
    for pub, vp, method in db.execute(
            "SELECT substr(published, 1, 4), vendor_product IS NOT NULL, "
            "json_extract(provenance, '$.fields.vendor_product.method') FROM cve WHERE searchable = 1"):
        y = pub or "unknown"
        per_year[y]["searchable"] += 1
        per_year[y]["with_vendor_product"] += int(vp)
        per_year[y][f"method:{method}"] += 1 if method else 0
    cov = {}
    for y in sorted(per_year):
        c = per_year[y]
        cov[y] = {"searchable": c["searchable"], "with_vendor_product": c["with_vendor_product"],
                  "coverage": round(c["with_vendor_product"] / c["searchable"], 4),
                  "by_method": {k[7:]: v for k, v in sorted(c.items()) if k.startswith("method:") and v}}
    r["vendor_product_coverage_by_year"] = cov
    tot_vp = _q(db, "SELECT COUNT(*) FROM cve WHERE searchable = 1 AND vendor_product IS NOT NULL")
    r["vendor_product_coverage_overall"] = round(tot_vp / total_s, 4)
    r["vendor_product_method_overall"] = dict(db.execute(
        "SELECT json_extract(provenance, '$.fields.vendor_product.method') m, COUNT(*) FROM cve "
        "WHERE searchable = 1 GROUP BY m ORDER BY 2 DESC").fetchall())

    # KEV / EPSS joins
    r["kev"] = {
        "listed_rows": _q(db, "SELECT COUNT(*) FROM cve WHERE kev_listed = 1"),
        "without_nvd_record": _q(db, "SELECT COUNT(*) FROM cve WHERE kev_listed = 1 AND instr(sources, 'nvd') = 0"),
        "without_nvd_record_searchable": _q(
            db, "SELECT COUNT(*) FROM cve WHERE kev_listed = 1 AND instr(sources, 'nvd') = 0 AND searchable = 1"),
        "listed_searchable": _q(db, "SELECT COUNT(*) FROM cve WHERE kev_listed = 1 AND searchable = 1"),
    }
    r["epss"] = {
        "scored_rows": _q(db, "SELECT COUNT(*) FROM cve WHERE epss IS NOT NULL"),
        "without_nvd_record": _q(db, "SELECT COUNT(*) FROM cve WHERE epss IS NOT NULL AND instr(sources, 'nvd') = 0"),
        "without_nvd_record_searchable": _q(
            db, "SELECT COUNT(*) FROM cve WHERE epss IS NOT NULL AND instr(sources, 'nvd') = 0 AND searchable = 1"),
        "scored_searchable": _q(db, "SELECT COUNT(*) FROM cve WHERE epss IS NOT NULL AND searchable = 1"),
    }
    if kev_rows is not None:
        r["kev"]["catalogue_rows"] = len(kev_rows)
    if epss_rows is not None:
        r["epss"]["file_rows"] = len(epss_rows)

    # weaknesses and CVSS
    r["rows_with_cwe"] = _q(db, "SELECT COUNT(*) FROM cve WHERE cwe_ids != '[]'")
    missing_names = Counter()
    for (w,) in db.execute("SELECT weaknesses FROM cve WHERE cwe_ids != '[]'"):
        for e in json.loads(w):
            if e.get("id") and not e.get("name"):
                missing_names[e["id"]] += 1
    r["cwe_ids_without_name"] = {"distinct": len(missing_names), "rows": sum(missing_names.values()),
                                 "top": dict(missing_names.most_common(10))}
    vers = Counter()
    for (c,) in db.execute("SELECT cvss FROM cve WHERE cvss != '[]'"):
        for v in {e["version"] for e in json.loads(c)}:
            vers[v] += 1
    r["rows_with_cvss"] = _q(db, "SELECT COUNT(*) FROM cve WHERE cvss != '[]'")
    r["rows_with_cvss_version"] = dict(sorted(vers.items()))
    r["rows_with_title"] = _q(db, "SELECT COUNT(*) FROM cve WHERE title IS NOT NULL")
    r["rows_with_aliases"] = _q(db, "SELECT COUNT(*) FROM cve WHERE aliases IS NOT NULL")
    r["rows_in_similar_group"] = _q(db, "SELECT COUNT(*) FROM cve WHERE similar_group IS NOT NULL")
    return r
