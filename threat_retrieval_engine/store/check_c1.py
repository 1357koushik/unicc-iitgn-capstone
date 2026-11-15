"""C1 acceptance check: prints PASS/FAIL per item, exit 1 if any FAIL.

    python -m threat_retrieval_engine.store.check_c1 [--store DIR] [--feeds DIR] [--benchmark DIR] [--skip-tests]

--store      a build directory or the store root holding LATEST (default data/store)
--feeds      raw feeds directory, for the independent universe and KEV/EPSS re-check
             (default knowledge_foundation/feeds)
--benchmark  benchmark v2.0 directory; only queries.jsonl and qrels.jsonl are read, only for the T2 dev
             slice, only after the build, to measure alias coverage. The sealed/ directory is never opened.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from . import aliases as A
from .reader import resolve_build

A_VERDICTS = Path(__file__).resolve().parent / "data" / "nickname_verdicts.jsonl"
from .text import alias_norm, normalize_cve_id

REPO_ROOT = Path(__file__).resolve().parents[2]
_fails = 0
# Template boilerplate v1 put into embedded text (validator.build_context and the KEV/EPSS stubs). Source
# descriptions may legitimately contain words such as "Product:"; only the template forms are searched for.
BOILERPLATE = re.compile(r"^Document: |\| (?:Section|Content|CVEs|Malware|TTPs|Vendor|Product|Required Action|"
                         r"Notes): |\b(?:CVEs|Malware|TTPs): none\b|has an EPSS exploitation probability score|"
                         r"Normalized Vulnerability Record|^Vulnerability: .* \| ")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def report(ok: bool, label: str, detail: str = "") -> None:
    global _fails
    _fails += (not ok)
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""), flush=True)


def info(label: str, detail: str) -> None:
    print(f"INFO  {label}  -- {detail}", flush=True)


# --------------------------------------------------------------------------- independent universe
def scan_feed_ids(feeds: Path) -> tuple[set[str], set[str], set[str], set[str]]:
    """IDs named by each feed, found without the build's parsers (regex / file names / csv)."""
    pat = re.compile(rb'"id"\s*:\s*"(CVE-\d{4}-\d{4,})"')
    nvd: set[str] = set()
    for p in sorted((feeds / "nvd_cve_data").glob("*.json")):
        with open(p, "rb") as f:
            tail = b""
            for chunk in iter(lambda: f.read(1 << 24), b""):
                data = tail + chunk
                nvd.update(m.decode() for m in pat.findall(data))
                tail = data[-64:]
    cl: set[str] = set()
    for dp, _dn, fn in os.walk(feeds / "cvelistV5-live" / "cves"):
        for f in fn:
            if f.upper().startswith("CVE-") and f.lower().endswith(".json"):
                c = normalize_cve_id(f[:-5])
                if c:
                    cl.add(c)
    kev: set[str] = set()
    kp = sorted(feeds.glob("cisa_kev-*.csv"))[-1]
    with open(kp, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            c = normalize_cve_id(r.get("cveID"))
            if c:
                kev.add(c)
    epss: set[str] = set()
    ep = sorted(feeds.glob("epss_scores-*.csv"))[-1]
    with open(ep, encoding="utf-8") as f:
        for line in f:
            c = normalize_cve_id(line.split(",", 1)[0])
            if c:
                epss.add(c)
    return nvd, cl, kev, epss


# --------------------------------------------------------------------------- T2 dev alias coverage
def t2_dev_coverage(db: sqlite3.Connection, bench: Path) -> dict:
    qpath, rpath = bench / "queries.jsonl", bench / "qrels.jsonl"
    assert "sealed" not in {p.lower() for p in qpath.parts}
    queries = []
    with open(qpath, encoding="utf-8") as f:
        for line in f:
            q = json.loads(line)
            if q.get("slice") == "T2" and q.get("split") == "dev":
                queries.append(q)
    want = {q["qid"] for q in queries}
    targets: dict[str, set[str]] = defaultdict(set)
    with open(rpath, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["qid"] in want and r.get("grade", 1) > 0:
                targets[r["qid"]].add(r["doc_id"])
    alias_rows: dict[str, list[tuple[str, str]]] = defaultdict(list)
    tids = sorted({t for ts in targets.values() for t in ts})
    for i in range(0, len(tids), 500):
        part = tids[i:i + 500]
        for cid, norm, kind in db.execute(
                f"SELECT cve_id, alias_norm, kind FROM aliases WHERE cve_id IN ({','.join('?' * len(part))})", part):
            alias_rows[cid].append((norm, kind))
    cand_rows: dict[str, set[str]] = defaultdict(set)
    for i in range(0, len(tids), 500):
        part = tids[i:i + 500]
        for cid, norm in db.execute(
                f"SELECT cve_id, alias_norm FROM alias_candidates WHERE cve_id IN ({','.join('?' * len(part))})", part):
            cand_rows[cid].add(norm)
    texts = {}
    for i in range(0, len(tids), 500):
        part = tids[i:i + 500]
        for cid, t, d, k in db.execute(
                f"SELECT cve_id, title, description, kev_text FROM cve WHERE cve_id IN ({','.join('?' * len(part))})",
                part):
            texts[cid] = alias_norm(" ".join(x or "" for x in (t, d, k)))
    per_name: dict[str, dict] = {}
    exact_q = loose_q = cand_q = 0
    for q in queries:
        name = q["meta"].get("nickname") or q["meta"].get("canonical_name")
        n = alias_norm(name)
        ts = targets.get(q["qid"], set())
        exact = any(norm == n and kind != "title" for t in ts for norm, kind in alias_rows.get(t, []))
        loose = exact or any(n in norm for t in ts for norm, _ in alias_rows.get(t, [])) or \
            any(n and n in texts.get(t, "") for t in ts)
        cand = any(n in cand_rows.get(t, set()) for t in ts)
        exact_q += exact
        loose_q += loose
        cand_q += cand
        e = per_name.setdefault(name, {"queries": 0, "exact": exact, "loose": loose, "cand": cand,
                                       "targets": sorted(ts)})
        e["queries"] += 1
    names = len(per_name)
    return {
        "dev_queries": len(queries), "distinct_names": names,
        "query_coverage_exact_alias": round(exact_q / max(1, len(queries)), 4),
        "query_coverage_alias_or_text": round(loose_q / max(1, len(queries)), 4),
        "query_coverage_nickname_candidates": round(cand_q / max(1, len(queries)), 4),
        "name_coverage_nickname_candidates": round(sum(v["cand"] for v in per_name.values()) / max(1, names), 4),
        "missing_from_candidates": sorted(k for k, v in per_name.items() if not v["cand"]),
        "name_coverage_exact_alias": round(sum(v["exact"] for v in per_name.values()) / max(1, names), 4),
        "name_coverage_alias_or_text": round(sum(v["loose"] for v in per_name.values()) / max(1, names), 4),
        "missing_exact": sorted(k for k, v in per_name.items() if not v["exact"]),
        "missing_even_in_text": sorted(k for k, v in per_name.items() if not v["loose"]),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", type=Path, default=None)
    ap.add_argument("--feeds", type=Path, default=REPO_ROOT / "knowledge_foundation" / "feeds")
    ap.add_argument("--benchmark", type=Path, default=REPO_ROOT / "data" / "benchmark" / "v2.0")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--json-out", type=Path, default=None, help="also write the figures to this JSON file")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    bdir = resolve_build(a.store)
    man = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
    db = sqlite3.connect(f"file:{(bdir / 'store.sqlite').as_posix()}?mode=ro", uri=True)
    q = lambda s, *p: db.execute(s, p).fetchone()[0]  # noqa: E731
    figures: dict = {"build_id": man["build_id"]}
    print(f"C1 acceptance check for build {man['build_id']} ({bdir})\n")

    # 1. one row per CVE of the universe
    rows = q("SELECT COUNT(*) FROM cve")
    distinct = q("SELECT COUNT(DISTINCT cve_id) FROM cve")
    ids = {r[0] for r in db.execute("SELECT cve_id FROM cve")}
    nvd, cl, kev, epss = scan_feed_ids(a.feeds)
    scanned = nvd | cl | kev | epss
    missing = scanned - ids
    rej_text = defaultdict(list)
    for src, rid, reason, detail in db.execute("SELECT source, record_id, reason, detail FROM rejected_records"):
        for c in set(_CVE.findall(f"{rid} {detail or ''}".upper())):
            rej_text[c].append(reason)
    unexplained_missing = sorted(c for c in missing if c not in rej_text)
    extra = sorted(ids - scanned)
    report(rows == distinct == man["report"]["universe"], "exactly one row per CVE",
           f"{rows} rows, {distinct} distinct IDs")
    report(not unexplained_missing and not extra, "rows match the CVE universe found independently in the feeds",
           f"feeds name {len(scanned)} IDs (NVD {len(nvd)}, CVE List {len(cl)}, KEV {len(kev)}, EPSS {len(epss)}); "
           f"{len(missing)} only in rejected records, {len(unexplained_missing)} unexplained, {len(extra)} extra"
           + (f"; e.g. {unexplained_missing[:3] or extra[:3]}" if unexplained_missing or extra else ""))

    # 2. searchable rows
    bad_s = q("SELECT COUNT(*) FROM cve WHERE searchable = 1 AND (state != 'published' OR description_kind != 'ok')")
    missed = q("SELECT COUNT(*) FROM cve WHERE searchable = 0 AND state = 'published' AND description_kind = 'ok'")
    searchable = q("SELECT COUNT(*) FROM cve WHERE searchable = 1")
    report(bad_s == 0 and missed == 0, "searchable row for every non-rejected CVE with a usable description",
           f"{searchable} searchable; {missed} usable published rows not searchable; {bad_s} rejected/reserved/"
           f"placeholder rows searchable")
    no_text = q("SELECT COUNT(*) FROM cve WHERE searchable = 1 AND (dense_text IS NULL OR description IS NULL)")
    report(no_text == 0, "every searchable row has description and dense_text", f"{no_text} without")

    # 3. reconciliation
    recon = man["reconciliation"]
    rej_counts = dict(db.execute("SELECT source, COUNT(*) FROM rejected_records GROUP BY source").fetchall())
    recon_ok = all(v["unexplained"] == 0 and v["read"] == v["stored_or_merged"] + v["rejected"] for v in recon.values())
    table_ok = all(rej_counts.get(k, 0) == v["rejected"] for k, v in recon.items())
    report(recon_ok and table_ok, "feed reconciliation: read = stored/merged + rejected, zero unexplained",
           "; ".join(f"{k} {v['read']}={v['stored_or_merged']}+{v['rejected']}" for k, v in recon.items()))
    misfiled = q("SELECT COUNT(*) FROM rejected_records WHERE reason = 'misfiled_cve_year'")
    report(misfiled == 0, "no record lost to a misfiled year", f"{misfiled}")
    empty_reason = q("SELECT COUNT(*) FROM rejected_records WHERE reason IS NULL OR reason = ''")
    report(empty_reason == 0, "every rejected record has a reason",
           "; ".join(f"{k}: {v}" for k, v in list(man["report"]["rejected_by_source_and_reason"].items())[:12]))

    # 4. section 5 counts
    rp = man["report"]
    v1 = man.get("v1_comparison")
    needed = ["universe", "searchable", "by_state", "kev", "epss", "vendor_product_coverage_by_year",
              "description_source_searchable"]
    report(all(k in rp for k in needed) and v1 is not None and "missing_by_reason" in v1,
           "section 5 counts reported (universe, searchable, rejected/reserved, v1 comparison, KEV/EPSS gaps)",
           f"universe {rp['universe']}, searchable {rp['searchable']}, states {rp['by_state']}")
    if v1:
        info("v1 comparison", f"v1 lacks {v1['store_cves_missing_from_v1']} store CVEs: {v1['missing_by_reason']}; "
                              f"likely near-duplicate drops {v1['likely_near_duplicate_drops']['count']} "
                              f"(verified Jaccard>=0.90: {v1['likely_near_duplicate_drops']['verified_jaccard_ge_0_90']})")
        kg = v1["kev_cves_without_v1_nvd_row"]["v1_kev_rows_without_nvd_row"]
        eg = v1["epss_cves_without_v1_nvd_row"]["v1_epss_rows_without_nvd_row"]
        report(kg["present_in_store"] == kg["count"] and eg["present_in_store"] == eg["count"],
               "KEV and EPSS CVEs that v1 had without an NVD row are now full rows",
               f"KEV {kg['present_in_store']}/{kg['count']} present ({kg['searchable_in_store']} searchable); "
               f"EPSS {eg['present_in_store']}/{eg['count']} present ({eg['searchable_in_store']} searchable)")

    # 5. KEV and EPSS columns, re-checked against the CSVs
    kp = sorted(a.feeds.glob("cisa_kev-*.csv"))[-1]
    ep = sorted(a.feeds.glob("epss_scores-*.csv"))[-1]
    kev_csv = {}
    with open(kp, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            c = normalize_cve_id(r.get("cveID"))
            if c and c not in kev_csv:
                kev_csv[c] = r
    epss_csv = {}
    with open(ep, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")
            c = normalize_cve_id(parts[0])
            if c and len(parts) == 3 and c not in epss_csv:
                epss_csv[c] = (float(parts[1]), float(parts[2]))
    kev_bad = epss_bad = 0
    for cid, k in db.execute("SELECT cve_id, kev FROM cve WHERE kev_listed = 1"):
        k = json.loads(k)
        r = kev_csv.get(cid)
        kev_bad += r is None or k.get("date_added") != (r.get("dateAdded") or None) or \
            k.get("due_date") != (r.get("dueDate") or None)
    for cid, s, p in db.execute("SELECT cve_id, epss_score, epss_percentile FROM cve WHERE epss IS NOT NULL"):
        epss_bad += epss_csv.get(cid) != (s, p)
    kev_n, epss_n = q("SELECT COUNT(*) FROM cve WHERE kev_listed = 1"), q("SELECT COUNT(*) FROM cve WHERE epss IS NOT NULL")
    report(kev_n == len(kev_csv) and kev_bad == 0, "KEV present as columns for every KEV CVE (values match the CSV)",
           f"{kev_n} rows vs {len(kev_csv)} CSV CVEs, {kev_bad} mismatches")
    report(epss_n == len(epss_csv) and epss_bad == 0, "EPSS present for every scored CVE (no threshold; values match)",
           f"{epss_n} rows vs {len(epss_csv)} CSV CVEs, {epss_bad} mismatches; "
           f"{q('SELECT COUNT(*) FROM cve WHERE epss_score < 0.5')} below 0.5 kept")
    sev_override = 0
    for (c,) in db.execute("SELECT cvss FROM cve WHERE kev_listed = 1"):
        for e in json.loads(c):
            sev_override += any(s.get("origin") == "kev" for s in e["sources"])
    report(sev_override == 0, "no CVSS entry derived from KEV (no severity override)", f"{sev_override}")
    no_vec = 0
    for (c,) in db.execute("SELECT cvss FROM cve WHERE cvss != '[]'"):
        no_vec += sum(1 for e in json.loads(c) if not e.get("vector") or not e.get("sources"))
    report(no_vec == 0, "every CVSS entry has a vector and a source", f"{no_vec} without; versions "
                                                                       f"{rp['rows_with_cvss_version']}")

    # 6. dense_text
    with_id = with_bp = 0
    examples = []
    for cid, d in db.execute("SELECT cve_id, dense_text FROM cve WHERE dense_text IS NOT NULL"):
        if _CVE.search(d):
            with_id += 1
            examples.append(cid)
        if BOILERPLATE.search(d):
            with_bp += 1
            examples.append(cid)
    report(with_id == 0, "no CVE ID in dense_text", f"{with_id} rows" + (f" e.g. {examples[:3]}" if with_id else ""))
    report(with_bp == 0, "no boilerplate labels in dense_text", f"{with_bp} rows")

    # 7. vendor_product
    us = q("SELECT COUNT(*) FROM cve WHERE instr(vendor_product, '_') > 0")
    over = 0
    for v, n in db.execute("SELECT vendor_product, json_array_length(provenance, '$.fields.vendor_product.pairs') "
                           "FROM cve WHERE vendor_product IS NOT NULL"):
        over += len(v.split("; ")) > 10 or (n or 0) > 10
    report(us == 0 and over == 0, "no underscores and at most 10 pairs in vendor_product", f"{us} with '_', {over} over cap")
    chrome = db.execute("SELECT vendor_product FROM cve WHERE cve_id = 'CVE-2018-6116'").fetchone()
    report(chrome is not None and chrome[0] == "Google Chrome",
           "platform CPEs excluded (CVE-2018-6116 Chrome bug with Red Hat/Debian CPEs)", str(chrome and chrome[0]))
    cov = rp["vendor_product_coverage_by_year"]
    info("vendor/product coverage by publication year",
         ", ".join(f"{y}: {v['coverage']:.1%}" for y, v in cov.items()) + f"; overall {rp['vendor_product_coverage_overall']:.1%}")
    info("description source (searchable)", json.dumps(rp["description_source_searchable"]))

    # 8. aliases: statistics, T2 dev coverage, leakage guard
    al = rp["aliases"]
    info("aliases", f"{al['rows']} rows {al['rows_by_kind']}; CVEs with any alias {al['cves_with_any_alias']}, with "
                    f"nickname/advisory ID {al['cves_with_nickname_or_advisory_id']}, distinct nicknames "
                    f"{al['distinct_nicknames']}; by source {al['rows_by_source']}")
    # nickname vetting: only accepted (alias, CVE set) pairs with a matching evidence hash are served
    vet = rp.get("nickname_vetting") or {}
    verdict_path = Path(vet.get("verdict_file") or A_VERDICTS)
    verdicts = A.load_verdicts(verdict_path) if verdict_path.is_file() else None
    report(verdicts is not None, "nickname verdict file present and well-formed", str(verdict_path))
    groups: dict[tuple[str, str], dict] = {}
    for norm, gcves, sha, st, cid, alias, src, rid, pos in db.execute(
            "SELECT alias_norm, group_cves, evidence_sha256, status, cve_id, alias, source, source_record_id, position "
            "FROM alias_candidates"):
        g = groups.setdefault((norm, gcves), {"sha": sha, "status": st, "rows": []})
        g["rows"].append(A.Candidate(cid, alias, norm, "nickname", src, rid, pos, 1))
    bad_hash = sum(1 for g in groups.values() if A.evidence_sha256(g["rows"]) != g["sha"])
    report(bad_hash == 0, "candidate evidence hashes reproduce", f"{bad_hash} of {len(groups)} differ")
    served = defaultdict(set)
    for cid, norm in db.execute("SELECT cve_id, alias_norm FROM aliases WHERE kind = 'nickname'"):
        served[norm].add(cid)
    unvetted = []
    for norm, cids in served.items():
        ok = False
        for (gnorm, gcves), g in groups.items():
            if gnorm != norm or set(gcves.split(",")) != cids or g["status"] != "accepted":
                continue
            v = (verdicts or {}).get((norm, tuple(gcves.split(","))))
            ok = v is not None and v["verdict"] == "accept" and v["evidence_sha256"] == g["sha"] == \
                A.evidence_sha256(g["rows"])
        if not ok:
            unvetted.append(norm)
    report(not unvetted, "every served nickname has an accept verdict with a matching evidence hash",
           f"{len(served)} served names; {len(unvetted)} without" + (f" e.g. {unvetted[:5]}" if unvetted else ""))
    st = Counter(g["status"] for g in groups.values())
    info("nickname vetting", f"{len(groups)} candidate groups: {dict(st)}; verdicts {vet.get('verdicts')}, "
                             f"verdicts without a current candidate {vet.get('verdicts_without_candidate')}")
    bad_frag = [n for (n, _), g in groups.items()
                if any(A._IDENT_PREFIX.match(t) or A._SHORT_ALNUM.match(t) for t in
                       (x.lower() for x in A._tokens(g["rows"][0].alias)))]
    report(not bad_frag, "no identifier fragments (apsb20, GHSA w3hj ...) among nickname candidates",
           f"{len(bad_frag)}" + (f" e.g. {bad_frag[:5]}" if bad_frag else ""))
    wid = q("SELECT COUNT(*) FROM cve WHERE weakness LIKE '%CVE-%'")
    rel = q("SELECT COUNT(*) FROM cve WHERE related_cves != '[]'")
    report(wid == 0, "no CVE IDs in weakness text (moved to related_cves)", f"{wid} rows; {rel} rows with related_cves")
    srcs = {r[0] for r in db.execute("SELECT DISTINCT source FROM aliases")}
    report(srcs <= set(A.ALLOWED_SOURCES) and not srcs & A.QUERY_SIDE_SOURCES,
           "leakage guard: alias rows only from expansion sources, none from query-side sources", f"{sorted(srcs)}")
    if (a.benchmark / "queries.jsonl").is_file():
        t2 = t2_dev_coverage(db, a.benchmark)
        figures["t2_dev"] = t2
        report(t2["dev_queries"] > 0, "T2 dev alias coverage reported",
               f"{t2['dev_queries']} dev queries / {t2['distinct_names']} names: exact alias "
               f"{t2['query_coverage_exact_alias']:.1%} of queries ({t2['name_coverage_exact_alias']:.1%} of names); "
               f"alias or record text {t2['query_coverage_alias_or_text']:.1%}; nickname candidates (unvetted) "
               f"{t2['query_coverage_nickname_candidates']:.1%} of queries")
        info("T2 dev names not among the nickname candidates", ", ".join(t2["missing_from_candidates"]) or "none")
        info("T2 dev names without an exact alias", ", ".join(t2["missing_exact"]) or "none")
        info("T2 dev names found nowhere (alias or record text)", ", ".join(t2["missing_even_in_text"]) or "none")
    else:
        report(False, "T2 dev alias coverage reported", f"{a.benchmark / 'queries.jsonl'} not found")

    # 9. similar groups and content hashes
    sg = rp["similar_groups"]
    bad_g = q("SELECT COUNT(*) FROM (SELECT similar_group g, COUNT(*) n, SUM(cve_id = similar_group) c FROM cve "
              "WHERE similar_group IS NOT NULL GROUP BY g) WHERE n < 2 OR c != 1")
    report(bad_g == 0, "similar groups: every group has >= 2 members and its canonical is a member",
           f"{sg['groups']} groups, {sg['cves_in_groups']} CVEs, largest {sg['largest_group']}; method: {sg['method']}")
    no_hash = q("SELECT COUNT(*) FROM cve WHERE content_hash IS NULL OR length(content_hash) != 64")
    report(no_hash == 0, "content_hash on every row (incremental re-embedding)", f"{no_hash} without")

    # 10. build time and size
    tm = man["timings"]
    size = (bdir / "store.sqlite").stat().st_size
    report(bool(tm.get("total_s")) and size > 0, "build time and store size reported",
           f"build {tm.get('total_s')} s (+ v1 comparison {tm.get('v1_compare_s', 0)} s), store {size / 1e9:.2f} GB")
    figures.update({"build_seconds": tm.get("total_s"), "store_bytes": size})

    # 11. test suite
    if not a.skip_tests:
        p = subprocess.run([sys.executable, "-m", "pytest", "verify", "tests", "-q"], cwd=REPO_ROOT,
                           capture_output=True, text=True)
        last = [ln for ln in p.stdout.strip().splitlines() if ln.strip()][-1:] or [""]
        report(p.returncode == 0, "full test suite: python -m pytest verify tests -q", last[0])
    db.close()
    if a.json_out:
        a.json_out.write_text(json.dumps(figures, indent=2), encoding="utf-8")
    print(f"\n{'ALL PASS' if not _fails else str(_fails) + ' FAILED'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
