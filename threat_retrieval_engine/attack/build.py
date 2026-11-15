"""Build the C9 ATT&CK store: documents, graph, CVE links and the entity-name gazetteer.

    python -m threat_retrieval_engine.attack.build --sources <data/sources> --store <C1 build or root>
        --out <data/attack> [--build-id ID]

Inputs (read only):
  <sources>/attack_enterprise/<LATEST>/raw/enterprise-attack.json     ATT&CK Enterprise STIX 2.1 bundle
  <sources>/kev_attack_mappings/<LATEST>/raw/mappings-explorer/<mapping_file named in the manifest>
  the C1 store build (CVE existence for links; CVE descriptions for the common-word measurement)

Each source's manifest must have role `attack`, status `ok`, a licence this build accepts (LICENCE_DECISIONS)
and raw-file hashes that match the bytes read. A source whose licence is not accepted is not ingested and the
reason is written to the manifest (for ATT&CK itself the build then fails, since nothing can be built).

Output: <out>/<build_id>/{attack.sqlite, manifest.json}, build_id = <UTC timestamp>-<short input hash>, and
<out>/LATEST naming the newest successful build. The build is written to a temporary directory and renamed
into place only after reconciliation passes: STIX objects read = stored + rejected with a reason; STIX
relationships read = stored edges + rejected; CVE-link candidates read = stored + rejected; KEV mapping
records read = stored + rejected. Any unexplained record fails the build (exit 1).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from threat_retrieval_engine.store.feeds import git_head
from threat_retrieval_engine.store.reader import Store
from threat_retrieval_engine.store.text import normalize_cve_id

from . import gazetteer as G
from .schema import ATTACK_STORE_VERSION, DDL, OBJECT_COLUMNS
from .stix import LinkCandidate, Parsed, Rejection, json_dump, link_candidates, parse_bundle, resolve_technique

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACK_SOURCE = "attack_enterprise"
KEV_SOURCE = "kev_attack_mappings"
# Licences this build accepts for ingestion, with what was checked. Anything else is not ingested.
LICENCE_DECISIONS = {
    "MITRE ATT&CK Terms of Use (royalty-free licence)":
        "royalty-free licence for research, development and commercial use; storing and ingesting as documents "
        "permitted; MITRE's copyright notice and licence are reproduced from raw/LICENSE.txt into the manifest",
    "Apache-2.0": "storing and deriving permitted with licence and notice kept",
}


class ReconciliationError(RuntimeError):
    pass


class SourceError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def code_fingerprint() -> dict:
    h = hashlib.sha256()
    for p in sorted(Path(__file__).resolve().parent.glob("*.py")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return {"attack_package_sha256": h.hexdigest(), "git_commit": git_head(REPO_ROOT),
            "store_version": ATTACK_STORE_VERSION}


# =========================================================================== inputs
def source_dir(sources: Path, name: str) -> tuple[Path, dict]:
    lf = sources / name / "LATEST"
    if not lf.is_file():
        raise SourceError(f"source {name} not collected: {lf} missing")
    d = sources / name / lf.read_text(encoding="utf-8").strip()
    if "benchmark" in {p.lower() for p in d.resolve().parts}:
        raise SourceError(f"refusing to read benchmark data as an ATT&CK input: {d}")
    mp = d / "manifest.json"
    if not mp.is_file():
        raise SourceError(f"{mp} missing")
    man = json.loads(mp.read_text(encoding="utf-8"))
    if man.get("role") != "attack":
        raise SourceError(f"{name} has role {man.get('role')!r}; only `attack` sources are ingested as content")
    if man.get("status") != "ok":
        raise SourceError(f"{name} status is {man.get('status')!r}: {man.get('reason')}")
    return d, man


def licence_decision(man: dict) -> tuple[bool, str]:
    name = (man.get("license") or {}).get("name") or ""
    if name in LICENCE_DECISIONS:
        return True, LICENCE_DECISIONS[name]
    return False, f"licence {name!r} is not in the accepted list; not ingested"


def verified_raw(d: Path, man: dict, rel: str) -> tuple[Path, str]:
    """A raw file of a source, with its sha256 checked against the manifest."""
    p = d / "raw" / rel
    listed = {f["path"]: f["sha256"] for f in man.get("raw_files") or []}
    if rel not in listed:
        raise SourceError(f"{rel} is not listed in {d / 'manifest.json'}")
    got = sha256_file(p)
    if got != listed[rel]:
        raise SourceError(f"{p}: sha256 {got} differs from the manifest ({listed[rel]})")
    return p, got


def read_kev_mappings(path: Path) -> tuple[list[dict], dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    meta = doc.get("metadata") or {}
    return list(doc.get("mapping_objects") or []), {
        "attack_version": meta.get("attack_version"), "kev_version": meta.get("mapping_framework_version"),
        "technology_domain": meta.get("technology_domain"), "creation_date": meta.get("creation_date"),
        "last_update": meta.get("last_update")}


# =========================================================================== CVE links
def store_cve_states(store: Store, cves: set[str]) -> dict[str, tuple[str, int]]:
    rows = store.get_many(cves, columns=("cve_id", "state", "searchable"))
    return {c: (r["state"], r["searchable"]) for c, r in rows.items()}


def make_links(P: Parsed, cands: list[LinkCandidate], kev: list[dict], kev_meta: dict, kev_ok: bool,
               store: Store) -> tuple[list[tuple], list[Rejection], dict]:
    """(link rows, rejections, reconciliation) for ATT&CK-text candidates and KEV mappings."""
    rows: dict[tuple, tuple] = {}
    rejects: list[Rejection] = []
    kev_cands = []
    seen_kev: Counter = Counter()
    if kev_ok:
        for m in kev:
            cve = (m.get("capability_id") or "").strip().upper()
            tech = (m.get("attack_object_id") or "").strip()
            mtype = m.get("mapping_type") or "unspecified"
            base = f"{cve}|{tech}|{mtype}"
            seen_kev[base] += 1
            kev_cands.append((base if seen_kev[base] == 1 else f"{base}#{seen_kev[base]}", cve, tech, mtype, m))
    all_cves = {c.cve_id for c in cands} | {normalize_cve_id(k[1]) for k in kev_cands if normalize_cve_id(k[1])}
    states = store_cve_states(store, all_cves)

    def cve_problem(cve: str) -> tuple[str, str] | None:
        st = states.get(cve)
        if st is None:
            return "cve_not_in_store", f"{cve} is not in C1 store {store.build_id}"
        if not st[1]:
            return "cve_not_searchable_in_store", f"{cve} has state {st[0]} in C1 store {store.build_id}"
        return None

    recon = {"attack_text": {"read": len(cands), "stored": 0, "rejected": 0},
             "kev_mapping": {"read": len(kev_cands), "stored": 0, "rejected": 0}}
    for c in cands:
        prob = c.reject or cve_problem(c.cve_id)
        if prob:
            rejects.append(Rejection("cve_link", c.record_id, prob[0], prob[1]))
            recon["attack_text"]["rejected"] += 1
            continue
        for doc_id, role in c.targets:
            key = (doc_id, c.cve_id, c.evidence_kind, c.evidence_ref, role)
            rows[key] = key + (json_dump(c.detail),)
        recon["attack_text"]["stored"] += 1
    for rid, cve_raw, tech, mtype, m in kev_cands:
        cve = normalize_cve_id(cve_raw)
        if rid != f"{cve_raw}|{tech}|{mtype}":
            rejects.append(Rejection("kev_mapping", rid, "duplicate_mapping", "same CVE, technique and mapping type"))
            recon["kev_mapping"]["rejected"] += 1
            continue
        if cve is None:
            rejects.append(Rejection("kev_mapping", rid, "malformed_cve_id", cve_raw))
            recon["kev_mapping"]["rejected"] += 1
            continue
        doc_id, via, why = resolve_technique(P, tech)
        prob = (why, f"{tech} (mapping on ATT&CK {kev_meta.get('attack_version')})") if why else cve_problem(cve)
        if prob:
            rejects.append(Rejection("kev_mapping", rid, prob[0], prob[1]))
            recon["kev_mapping"]["rejected"] += 1
            continue
        detail = {"mapping_type": mtype, "attack_object_id": tech, "attack_object_name": m.get("attack_object_name"),
                  "capability_group": m.get("capability_group"), "capability_description": m.get("capability_description"),
                  "comments": m.get("comments"), "references": m.get("references") or [], "status": m.get("status"),
                  "mapping_attack_version": kev_meta.get("attack_version"), "kev_version": kev_meta.get("kev_version")}
        if via:
            detail["redirected_from"] = via
        key = (doc_id, cve, "kev_mapping", f"{tech}|{mtype}", "mapped_technique")
        if key in rows:  # two mapping records that redirect to the same technique and type
            rejects.append(Rejection("kev_mapping", rid, "duplicate_after_redirect", f"{tech} -> {doc_id}"))
            recon["kev_mapping"]["rejected"] += 1
            continue
        rows[key] = key + (json_dump(detail),)
        recon["kev_mapping"]["stored"] += 1
    return [rows[k] for k in sorted(rows)], rejects, recon


# =========================================================================== build
def build(sources: Path, store_path: Path | None, out_root: Path, build_id: str | None = None, log=print,
          policy: dict | None = None) -> Path:
    """Build into <out_root>/<build_id>. `policy` overrides the gazetteer policy (tests only; the default is
    `gazetteer.POLICY`, recorded in the manifest and meta either way)."""
    policy = policy or G.POLICY
    t0 = time.time()
    timings: dict[str, float] = {}
    started = datetime.now(timezone.utc)
    a_dir, a_man = source_dir(sources, ATTACK_SOURCE)
    ok, why = licence_decision(a_man)
    if not ok:
        raise SourceError(f"{ATTACK_SOURCE}: {why}")
    bundle_path, bundle_sha = verified_raw(a_dir, a_man, "enterprise-attack.json")
    licence_text = (a_dir / "raw" / "LICENSE.txt").read_text(encoding="utf-8") \
        if (a_dir / "raw" / "LICENSE.txt").is_file() else None
    k_dir, k_man = source_dir(sources, KEV_SOURCE)
    kev_ok, kev_why = licence_decision(k_man)
    kev_rel = "mappings-explorer/" + ((k_man.get("upstream_version") or {}).get("mapping_file") or "")
    store = Store.open(store_path)

    out_root.mkdir(parents=True, exist_ok=True)
    tmp = out_root / f".tmp-{started.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    try:
        # ---------------------------------------------------------- parse
        t = time.time()
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        P = parse_bundle(bundle)
        kev, kev_meta, kev_sha = [], {}, None
        if kev_ok:
            kev_path, kev_sha = verified_raw(k_dir, k_man, kev_rel)
            kev, kev_meta = read_kev_mappings(kev_path)
        cands = link_candidates(bundle, P)
        timings["parse_s"] = round(time.time() - t, 1)
        log(f"parsed: {len(P.docs)} documents, {len(P.edges)} edges, {len(cands)} CVE-link candidates, "
            f"{len(kev)} KEV mappings ({timings['parse_s']}s)")

        # ---------------------------------------------------------- links
        t = time.time()
        links, link_rejects, link_recon = make_links(P, cands, kev, kev_meta, kev_ok, store)
        timings["links_s"] = round(time.time() - t, 1)

        # ---------------------------------------------------------- gazetteer
        t = time.time()
        entries = G.build_entries(P.docs)
        df = G.corpus_df((r["description"] for r in store.iter_searchable(columns=("description",))), entries,
                              log=log)
        keys = G.assign_policy(entries, df, policy)
        timings["gazetteer_s"] = round(time.time() - t, 1)
        log(f"gazetteer: {len(entries)} names, {len(keys)} keys, "
            f"{sum(k['policy'] == 'restricted' for k in keys)} restricted ({timings['gazetteer_s']}s)")

        # ---------------------------------------------------------- reconciliation
        rejects = P.rejects + link_rejects
        rc = Counter(r.source for r in rejects)
        recon = {
            "stix_objects": {"read": P.objects_read, "stored": len(P.docs), "rejected": rc["stix_object"]},
            "stix_relationships": {"read": P.relationships_read, "stored": len(P.edges),
                                   "rejected": rc["stix_relationship"]},
            "cve_link_candidates": {**link_recon["attack_text"]},
            "kev_mappings": {**link_recon["kev_mapping"], "ingested": kev_ok},
        }
        assert link_recon["attack_text"]["rejected"] == rc["cve_link"]
        assert link_recon["kev_mapping"]["rejected"] == rc["kev_mapping"]
        for v in recon.values():
            v["unexplained"] = v["read"] - v["stored"] - v["rejected"]
        bad = {k: v for k, v in recon.items() if v["unexplained"] != 0}
        if bad:
            raise ReconciliationError(f"reconciliation failed: {bad}")
        dup_ids = [k for k, n in Counter((r.source, r.record_id) for r in rejects).items() if n > 1]
        if dup_ids:
            raise ReconciliationError(f"rejected record IDs are not unique: {dup_ids[:5]}")

        # ---------------------------------------------------------- write
        t = time.time()
        db_path = tmp / "attack.sqlite"
        db = sqlite3.connect(db_path)
        db.executescript(DDL)
        rows = []
        for doc_id in sorted(P.docs):
            r = dict(P.docs[doc_id])
            r["store_version"] = ATTACK_STORE_VERSION
            vals = []
            for c in OBJECT_COLUMNS:
                v = r.get(c)
                vals.append(json_dump(v) if c in ("aliases_list", "tactics_list", "platforms_list", "attrs") else v)
            rows.append(vals)
        db.executemany(f"INSERT INTO objects ({', '.join(OBJECT_COLUMNS)}) VALUES ({','.join('?' * len(OBJECT_COLUMNS))})",
                       rows)
        db.executemany(
            "INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [(e["rel_stix_id"], e["rel_type"], e["src_doc_id"], e["dst_doc_id"], P.docs[e["src_doc_id"]]["attack_id"],
              P.docs[e["dst_doc_id"]]["attack_id"], e["description"] or None, e["orig_src_doc_id"], e["orig_dst_doc_id"],
              e["redirected"], e["created"], e["modified"]) for e in (P.edges[k] for k in sorted(P.edges))])
        db.executemany("INSERT INTO cve_links VALUES (?,?,?,?,?,?)", links)
        db.executemany("INSERT INTO gazetteer VALUES (?,?,?,?,?,?)",
                       [(e["key"], e["doc_id"], e["doc_kind"], e["surface"], e["origin"], e["fine_tokens"])
                        for e in entries])
        db.executemany("INSERT INTO gazetteer_keys VALUES (?,?,?,?,?,?)",
                       [(k["key"], k["n_docs"], k["kinds"], k["policy"], k["reason"], k["df_cve"]) for k in keys])
        db.executemany("INSERT INTO rejected VALUES (?,?,?,?)",
                       [(r.source, r.record_id, r.reason, r.detail) for r in rejects])
        db.commit()
        timings["write_s"] = round(time.time() - t, 1)

        # ---------------------------------------------------------- identity, report, manifest
        inputs = {
            ATTACK_SOURCE: {"dir": str(a_dir), "file": "raw/enterprise-attack.json", "sha256": bundle_sha,
                            "licence": a_man.get("license"), "licence_decision": why,
                            "upstream_version": a_man.get("upstream_version"),
                            "retrieved_at_utc": a_man.get("retrieved_at_utc"), "collection": P.collection},
            KEV_SOURCE: {"dir": str(k_dir), "file": f"raw/{kev_rel}", "sha256": kev_sha, "ingested": kev_ok,
                         "licence": k_man.get("license"), "licence_decision": kev_why,
                         "upstream_version": k_man.get("upstream_version"), "mapping_metadata": kev_meta,
                         "retrieved_at_utc": k_man.get("retrieved_at_utc"),
                         "not_read": "other mapping files in the repository (older ATT&CK/KEV versions, mobile "
                                     "domain): the collector names the latest enterprise file"},
            "c1_store": {"build_id": store.build_id, "dir": str(store.build_dir),
                         "inputs_sha256": store.manifest.get("inputs_sha256")},
        }
        ih = hashlib.sha256(json.dumps({"attack": bundle_sha, "kev": kev_sha, "store": store.build_id,
                                        "policy": policy}, sort_keys=True).encode()).hexdigest()
        bid = build_id or f"{started.strftime('%Y%m%dT%H%M%SZ')}-{ih[:10]}"
        attack_version = (a_man.get("upstream_version") or {}).get("attack_version") or P.collection.get("version")
        meta = {"build_id": bid, "store_version": ATTACK_STORE_VERSION, "inputs_sha256": ih,
                "attack_version": str(attack_version), "c1_store_build_id": store.build_id,
                "gazetteer_policy": json.dumps(policy, sort_keys=True)}
        db.executemany("INSERT INTO meta VALUES (?,?)", sorted(meta.items()))
        db.commit()
        report = build_report(db, P, df, keys)
        db.execute("ANALYZE")
        db.commit()
        db.close()
        timings["total_s"] = round(time.time() - t0, 1)
        manifest = {
            "build_id": bid, "store_version": ATTACK_STORE_VERSION, "attack_version": str(attack_version),
            "created_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "inputs_sha256": ih, "inputs": inputs,
            "code": code_fingerprint(), "copyright_notice": licence_text,
            "method": {"identity": "ATT&CK ID from the mitre-attack external reference; never text similarity",
                       "revoked": "stored, not searchable, revoked_by = final active replacement (revoked-by chain)",
                       "deprecated": "stored, not searchable, no replacement",
                       "edges_touching_revoked": "endpoint redirected to the replacement; dropped if it then "
                                                 "duplicates a stored edge or loops",
                       "edges_touching_deprecated": "dropped (endpoint_deprecated)",
                       "cve_links": "CVE IDs in descriptions and external references of stored objects and "
                                    "relationships, and KEV-to-ATT&CK mappings; only CVEs searchable in the C1 store",
                       "gazetteer_policy": policy},
            "reconciliation": recon, "report": report, "timings": timings,
            "store_bytes": db_path.stat().st_size,
        }
        (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        final = out_root / bid
        if final.exists():
            shutil.rmtree(final)
        os.replace(tmp, final)
        (out_root / "LATEST").write_text(bid + "\n", encoding="utf-8")
        log(f"build {bid}: {len(P.docs)} documents, {len(P.edges)} edges, {len(links)} CVE links "
            f"in {timings['total_s']}s -> {final}")
        return final
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    finally:
        store.close()


def build_report(db: sqlite3.Connection, P: Parsed, df: Counter, keys: list[dict]) -> dict:
    q = lambda s: db.execute(s).fetchall()  # noqa: E731
    restricted = [k for k in keys if k["policy"] == "restricted"]
    surface = dict(q("SELECT key, MIN(surface) FROM gazetteer GROUP BY key"))
    amb = [k for k in keys if k["n_docs"] > 1]
    return {
        "objects_by_kind_state": dict(q("SELECT doc_kind || '/' || state, COUNT(*) FROM objects GROUP BY 1 ORDER BY 1")),
        "software_by_type": dict(q("SELECT software_type, COUNT(*) FROM objects WHERE doc_kind = 'software' "
                                   "GROUP BY 1 ORDER BY 1")),
        "subtechniques": q("SELECT COUNT(*) FROM objects WHERE is_subtechnique = 1")[0][0],
        "searchable": q("SELECT COUNT(*) FROM objects WHERE searchable = 1")[0][0],
        "searchable_by_kind": dict(q("SELECT doc_kind, COUNT(*) FROM objects WHERE searchable = 1 GROUP BY 1 ORDER BY 1")),
        "revoked_mapping_problems": {k: v["problem"] for k, v in sorted(P.revoked_chain.items()) if v["problem"]},
        "edges_by_type": dict(q("SELECT rel_type, COUNT(*) FROM edges GROUP BY 1 ORDER BY 1")),
        "edges_redirected": q("SELECT COUNT(*) FROM edges WHERE redirected IS NOT NULL")[0][0],
        "cve_links_by_evidence": dict(q("SELECT evidence_kind, COUNT(*) FROM cve_links GROUP BY 1 ORDER BY 1")),
        "cve_links_distinct_cves": q("SELECT COUNT(DISTINCT cve_id) FROM cve_links")[0][0],
        "cve_links_distinct_docs": q("SELECT COUNT(DISTINCT doc_id) FROM cve_links")[0][0],
        "rejected_by_source_reason": {f"{s}/{r}": n for s, r, n in
                                      q("SELECT source, reason, COUNT(*) FROM rejected GROUP BY 1, 2 ORDER BY 1, 2")},
        "gazetteer": {
            "names": q("SELECT COUNT(*) FROM gazetteer")[0][0],
            "keys": len(keys),
            "names_by_origin": dict(q("SELECT origin, COUNT(*) FROM gazetteer GROUP BY 1 ORDER BY 1")),
            "keys_by_kinds": dict(Counter(k["kinds"] for k in keys)),
            "ambiguous_keys": len(amb),
            "ambiguous": {surface[k["key"]]: [d for (d,) in db.execute(
                "SELECT doc_id FROM gazetteer WHERE key = ? ORDER BY doc_id", (k["key"],))] for k in amb},
            "restricted_keys": len(restricted),
            "restricted": {surface[k["key"]]: {"reason": k["reason"], "df_cve": k["df_cve"]} for k in restricted},
            "df_cve_histogram": dict(sorted(Counter(min(v, 1000) // 5 * 5 for v in df.values()).items())),
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", type=Path, default=REPO_ROOT / "data" / "sources")
    ap.add_argument("--store", type=Path, default=None, help="C1 build directory or store root (default data/store)")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "attack")
    ap.add_argument("--build-id", default=None, help="override the build ID (tests)")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        build(a.sources, a.store, a.out, build_id=a.build_id, log=lambda m: print(m, flush=True))
    except (ReconciliationError, SourceError) as e:
        print(f"BUILD FAILED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
