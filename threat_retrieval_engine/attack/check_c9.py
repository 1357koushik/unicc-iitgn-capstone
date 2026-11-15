"""C9 acceptance check: prints PASS/FAIL per item, exit 1 if any FAIL.

    python -m threat_retrieval_engine.attack.check_c9 [--attack DIR] [--store DIR] [--benchmark DIR]
        [--skip-tests] [--json-out FILE]

--attack     a C9 build directory or the root holding LATEST (default data/attack)
--store      the C1 store build the links were checked against (default: the one named in the manifest)
--benchmark  benchmark v2.0 directory; only queries.jsonl and qrels.jsonl are read, only for the train and dev
             splits, only after the build, to check that every attack: doc_id they name exists and to measure
             gazetteer coverage of T9 dev exact-name queries. The sealed/ directory is never opened.

Gate (plan section 7): `stix_relationships` contains only relationships traceable to an ATT&CK ID; the
hardcoded lists are gone. Both are tested here through the API layer and by scanning the package source.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from threat_retrieval_engine.store.reader import Store

from .graph import EDGE_STRING, AttackGraph
from .reader import AttackStore, resolve_attack_build
from .stix import TYPE_TO_KIND
from .text import ATTACK_ID_IN_TEXT, CVE_IN_TEXT, alias_norm

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "threat_retrieval_engine"
_fails = 0
# identifiers of the removed v1 stub and lists; finding one in the package source fails the check
REMOVED_IDENTIFIERS = ("COMMON_ACTORS", "COMMON_MALWARE", "TOOL_TO_TECH", "_build_starter_attack_graph",
                       "starter_stub", "mitre_graph", "MitreAttackGraph", "mitre_attack_bundle_path")
MARKUP = re.compile(r"\(Citation:|\]\(https?://|</?code>|\*\*")


def report(ok: bool, label: str, detail: str = "") -> None:
    global _fails
    _fails += (not ok)
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""), flush=True)


def info(label: str, detail: str) -> None:
    print(f"INFO  {label}  -- {detail}", flush=True)


def _short(xs, n: int = 12) -> str:
    xs = list(xs)
    return ", ".join(map(str, xs[:n])) + (f", ... (+{len(xs) - n})" if len(xs) > n else "")


# =========================================================================== API probe
def probe_queries(store: AttackStore) -> list[str]:
    """Queries naming real entities of this build (chosen from the build, never from the benchmark): a group
    with software edges, that software, a technique ID, a revoked technique ID and an alias."""
    group = next(b for b in sorted(store._brief.values(), key=lambda b: b["attack_id"])
                 if b["doc_kind"] == "group" and b["searchable"]
                 and any(store.brief(e["dst_doc_id"])["doc_kind"] == "software" for e in store.edges(b["doc_id"], "out", "uses"))
                 and not store.gazetteer().is_restricted(b["name"]))
    sw = next(store.brief(e["dst_doc_id"]) for e in store.edges(group["doc_id"], "out", "uses")
              if store.brief(e["dst_doc_id"])["doc_kind"] == "software"
              and not store.gazetteer().is_restricted(store.brief(e["dst_doc_id"])["name"]))
    tech = next(store.brief(e["dst_doc_id"]) for e in store.edges(group["doc_id"], "out", "uses")
                if store.brief(e["dst_doc_id"])["doc_kind"] == "technique")
    revoked = next((b for b in sorted(store._brief.values(), key=lambda b: b["attack_id"])
                    if b["doc_kind"] == "technique" and b["state"] == "revoked" and b["revoked_by"]), None)
    alias = next((a for a in (store.get(group["doc_id"], ("aliases_list",)) or {}).get("aliases_list", [])
                  if not store.gazetteer().is_restricted(a) and len(store.find_name(a)) == 1), group["name"])
    qs = [f"{group['name']} deployed {sw['name']} and used {tech['attack_id']}",
          f"incident attributed to {alias}", f"{sw['name']}"]
    if revoked:
        qs.append(f"activity matching {revoked['attack_id']} on a domain controller")
    return qs


def probe_api(graph: AttackGraph, queries: list[str]) -> dict[str, Any]:
    """Run queries through the FastAPI app (POST /api/v1/threats/match, GET /api/v1/health) with the given
    ATT&CK graph and a two-chunk corpus; the engines outside C9 (Qdrant, embedder, reranker, confidence
    model) are replaced by stand-ins. Returns {health, responses: [(query, json)]}."""
    from unittest.mock import MagicMock, patch

    from fastapi.testclient import TestClient

    from threat_retrieval_engine.api import main as api_main
    from threat_retrieval_engine.api import pipeline
    from threat_retrieval_engine.attack import runtime
    from threat_retrieval_engine.search_engine.hybrid_search import HybridResult

    st = graph.store
    probe_doc = next(b for b in sorted(st._brief.values(), key=lambda b: b["attack_id"])
                     if b["doc_kind"] == "group" and b["searchable"] and st.edges(b["doc_id"], "out"))
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, doc_id TEXT, doc_title TEXT, source_org TEXT, "
                "published_date TEXT, char_start INTEGER, char_end INTEGER, text TEXT, enriched_text TEXT, "
                "entities_json TEXT)")
    ents = {"threat_actors": [probe_doc["name"]], "mitre_ttps": [], "malware_families": []}
    con.execute("INSERT INTO corpus VALUES ('chunk_actor', 'REPORT-1', 'Report', 'TEST', '2026-01-01', 0, 100, ?, ?, ?)",
                (f"Activity by {probe_doc['name']} was observed.", f"Activity by {probe_doc['name']}.", json.dumps(ents)))
    con.execute("INSERT INTO corpus VALUES ('chunk_plain', 'REPORT-2', 'Report', 'TEST', '2026-01-01', 0, 100, "
                "'A routine software update.', 'A routine software update.', '{}')")
    con.commit()
    searcher = MagicMock()
    searcher.search.return_value = [HybridResult(chunk_id="chunk_actor", rrf_score=0.9, dense_score=0.8),
                                    HybridResult(chunk_id="chunk_plain", rrf_score=0.5, dense_score=0.4)]
    prev = pipeline._orchestrator
    runtime.set_attack_graph(graph)
    engine = pipeline.ThreatRetrieverEngine(qdrant_client=MagicMock(), sqlite_conn=con, hybrid_searcher=searcher,
                                            reranker=None, confidence_model=MagicMock())
    out: dict[str, Any] = {"responses": []}
    try:
        with patch.object(pipeline, "setup_databases", return_value=(MagicMock(), con)), \
             patch("threat_retrieval_engine.search_engine.reranker.CrossEncoderReranker", side_effect=RuntimeError("stand-in")):
            engine.initialize(sqlite_path=":memory:")
        engine.confidence_model = None
        engine.sqlite_path = None
        pipeline._orchestrator = engine
        headers = {}
        from threat_retrieval_engine.config import get_config
        cfg = get_config()
        if cfg.service_auth_enabled:
            headers[cfg.api_key_header] = cfg.api_key
        client = TestClient(api_main.app)
        with patch.object(pipeline, "exact_lookup", return_value=[]):
            for q in queries:
                r = client.post("/api/v1/threats/match", json={"query": q, "top_k": 5}, headers=headers)
                out["responses"].append((q, r.status_code, r.json()))
        out["health"] = client.get("/api/v1/health").json()
    finally:
        pipeline._orchestrator = prev
    return out


def check_relationship_strings(store: AttackStore, responses) -> tuple[int, list[str]]:
    """(relationship strings seen, problems) for every stix_relationships entry in the responses."""
    seen, bad = 0, []
    for q, code, body in responses:
        if code != 200:
            bad.append(f"{q!r}: HTTP {code}")
            continue
        for m in body.get("top_matches", []):
            for s in m.get("stix_relationships", []):
                seen += 1
                prefix, _, rest = s.partition("] ")
                em = EDGE_STRING.match(rest) if prefix in ("[QUERY_CONTEXT", "[DOCUMENT") else None
                if em is None:
                    bad.append(f"unparseable: {s!r}")
                    continue
                src, dst = store.brief(em["src"]), store.brief(em["dst"])
                if src is None or dst is None or not store.has_edge(em["src"], em["rel"], em["dst"]):
                    bad.append(f"not a stored edge: {s!r}")
                elif em["src_name"] != src["title"] or em["dst_name"] != dst["title"]:
                    bad.append(f"names differ from the build: {s!r}")
    return seen, bad


# =========================================================================== hardcoded lists
def scan_hardcoded(store: AttackStore, root: Path = PACKAGE_ROOT) -> list[str]:
    """Source of the package: removed stub identifiers anywhere, and string literals (not docstrings) that are
    exactly an ATT&CK group, software or campaign name/alias of this build (a hardcoded entity list)."""
    keys = {k for k, v in store.gazetteer().key_info.items()
            if v["policy"] == "anywhere" and len(k) >= 4 and set(v["kinds"].split(",")) & {"group", "software", "campaign"}}
    me = Path(__file__).resolve()
    hits = []
    for p in sorted(root.rglob("*.py")):
        if p.resolve() == me:
            continue
        src = p.read_text(encoding="utf-8")
        rel = p.relative_to(root.parent).as_posix()
        for ident in REMOVED_IDENTIFIERS:
            if re.search(rf"\b{re.escape(ident)}\b", src):
                hits.append(f"{rel}: {ident}")
        tree = ast.parse(src)
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                    docstrings.add(id(first.value))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                if alias_norm(node.value) in keys:
                    hits.append(f"{rel}:{node.lineno}: string literal {node.value!r} is an ATT&CK name")
    return hits


# =========================================================================== benchmark
def read_split_files(bench: Path) -> tuple[dict[str, dict], list[dict]]:
    """train and dev queries and their qrels; the sealed directory is never touched."""
    queries = {}
    with open(bench / "queries.jsonl", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                q = json.loads(line)
                if q.get("split") in ("train", "dev"):
                    queries[q["qid"]] = q
    qrels = []
    with open(bench / "qrels.jsonl", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                if r["qid"] in queries:
                    qrels.append(r)
    return queries, qrels


# =========================================================================== main
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attack", type=Path, default=REPO_ROOT / "data" / "attack")
    ap.add_argument("--store", type=Path, default=None)
    ap.add_argument("--benchmark", type=Path, default=REPO_ROOT / "data" / "benchmark" / "v2.0")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--json-out", type=Path, default=None)
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    figures: dict[str, Any] = {}

    bdir = resolve_attack_build(a.attack)
    st = AttackStore.open(bdir)
    man = st.manifest
    db = sqlite3.connect(f"file:{(bdir / 'attack.sqlite').as_posix()}?mode=ro", uri=True)
    q1 = lambda s, p=(): db.execute(s, p).fetchone()[0]  # noqa: E731
    print(f"C9 check of build {st.build_id} (ATT&CK {st.attack_version}) at {bdir}\n")
    figures["build_id"] = st.build_id

    # 1. reconciliation, from the manifest and recounted independently from the raw bundle
    rec = man["reconciliation"]
    report(all(v["unexplained"] == 0 for v in rec.values()), "reconciliation: read = stored + rejected, zero unexplained",
           "; ".join(f"{k} {v['read']} = {v['stored']} + {v['rejected']}" for k, v in rec.items()))
    by_src = dict(db.execute("SELECT source, COUNT(*) FROM rejected GROUP BY source"))
    ok = (by_src.get("stix_object", 0) == rec["stix_objects"]["rejected"]
          and by_src.get("stix_relationship", 0) == rec["stix_relationships"]["rejected"]
          and by_src.get("cve_link", 0) == rec["cve_link_candidates"]["rejected"]
          and by_src.get("kev_mapping", 0) == rec["kev_mappings"]["rejected"]
          and q1("SELECT COUNT(*) FROM objects") == rec["stix_objects"]["stored"]
          and q1("SELECT COUNT(*) FROM edges") == rec["stix_relationships"]["stored"])
    report(ok, "rejected table and stored rows match the reconciliation counts", json.dumps(by_src))
    raw = Path(man["inputs"]["attack_enterprise"]["dir"]) / man["inputs"]["attack_enterprise"]["file"]
    bundle = json.loads(raw.read_text(encoding="utf-8"))["objects"]
    n_obj = sum(1 for o in bundle if o.get("type") != "relationship")
    n_rel = sum(1 for o in bundle if o.get("type") == "relationship")
    stored_stix = {r[0] for r in db.execute("SELECT stix_id FROM objects")}
    rej_obj = {r[0] for r in db.execute("SELECT record_id FROM rejected WHERE source = 'stix_object'")}
    edge_ids = {r[0] for r in db.execute("SELECT rel_stix_id FROM edges")}
    rej_rel = {r[0] for r in db.execute("SELECT record_id FROM rejected WHERE source = 'stix_relationship'")}
    unacc_o = [o["id"] for o in bundle if o.get("type") != "relationship" and o["id"] not in stored_stix | rej_obj]
    unacc_r = [o["id"] for o in bundle if o.get("type") == "relationship" and o["id"] not in edge_ids | rej_rel]
    report(n_obj == rec["stix_objects"]["read"] and n_rel == rec["stix_relationships"]["read"] and not unacc_o
           and not unacc_r, "independent recount of the raw bundle: every object and relationship stored or rejected",
           f"{n_obj} objects, {n_rel} relationships; unaccounted {len(unacc_o)} + {len(unacc_r)}")
    info("rejected by source/reason", json.dumps(man["report"]["rejected_by_source_reason"]))
    included = [o for o in bundle if o.get("type") in TYPE_TO_KIND]
    report(len(stored_stix) + sum(1 for o in included if o["id"] in rej_obj) == len(included),
           "identity by ATT&CK ID: every object of an ingested type is one document or one rejection",
           f"{len(included)} objects of ingested types")

    # 2. documents and text fields
    rp = man["report"]
    info("documents by kind/state", json.dumps(rp["objects_by_kind_state"]))
    info("software by type", json.dumps(rp["software_by_type"]) + f"; sub-techniques {rp['subtechniques']}")
    report(q1("SELECT COUNT(*) FROM objects WHERE searchable = 1 AND state != 'active'") == 0
           and q1("SELECT COUNT(*) FROM objects WHERE searchable = 0 AND state = 'active'") == 0,
           "revoked and deprecated documents stored but not searchable; every active document searchable",
           f"searchable {rp['searchable']} {json.dumps(rp['searchable_by_kind'])}")
    missing_text, markup, ids_in_dense = [], [], []
    for r in st.iter_searchable(columns=("doc_id", "title", "description", "dense_text", "content_hash", "aliases",
                                         "aliases_list")):
        if not (r["title"] and r["dense_text"] and r["content_hash"] and r["description"]):
            missing_text.append(r["doc_id"])
        if (r["aliases"] or None) != ("; ".join(r["aliases_list"]) or None):
            missing_text.append(r["doc_id"] + " (aliases)")
        for f in ("description", "dense_text"):
            if r[f] and MARKUP.search(r[f]):
                markup.append(f"{r['doc_id']}.{f}")
        if ATTACK_ID_IN_TEXT.search(r["dense_text"] or "") or CVE_IN_TEXT.search(r["dense_text"] or ""):
            ids_in_dense.append(r["doc_id"])
    report(not missing_text, "every searchable document has title, description, dense_text, content_hash, aliases",
           _short(missing_text) or f"{rp['searchable']} documents")
    report(not markup, "descriptions and dense_text free of markdown links, citations and HTML", _short(markup) or "none")
    report(not ids_in_dense, "dense_text carries no ATT&CK or CVE IDs", _short(ids_in_dense) or "none")

    # 3. revocation
    revoked = db.execute("SELECT doc_id, revoked_by FROM objects WHERE state = 'revoked'").fetchall()
    bad_rev = [d for d, rb in revoked if not rb or (st.brief(rb) or {}).get("state") != "active"]
    rb_edges = q1("SELECT COUNT(DISTINCT src_doc_id) FROM edges WHERE rel_type = 'revoked-by'")
    sample = [st.resolve_id(d)["doc_id"] == rb for d, rb in revoked if rb]
    report(not bad_rev and rb_edges == len(revoked) and all(sample),
           "every revoked object maps to an active replacement (revoked-by chain), resolve_id follows it",
           f"{len(revoked)} revoked, {rb_edges} with revoked-by edges; problems: {_short(bad_rev) or 'none'}")

    # 4. graph
    info("edges by type", json.dumps(rp["edges_by_type"]) + f"; redirected from revoked endpoints {rp['edges_redirected']}")
    brief = {r[0]: r[1:] for r in db.execute("SELECT doc_id, attack_id, state FROM objects")}
    bad_e = []
    for rid, rt, s, d, sa, da, os_, od in db.execute(
            "SELECT rel_stix_id, rel_type, src_doc_id, dst_doc_id, src_attack_id, dst_attack_id, orig_src_doc_id, "
            "orig_dst_doc_id FROM edges"):
        if s not in brief or d not in brief or os_ not in brief or od not in brief:
            bad_e.append(f"{rid}: endpoint missing")
        elif brief[s][0] != sa or brief[d][0] != da or not sa or not da:
            bad_e.append(f"{rid}: ATT&CK ID mismatch")
        elif not rid.startswith("relationship--"):
            bad_e.append(f"{rid}: not a STIX relationship ID")
        elif rt != "revoked-by" and (brief[s][1] != "active" or brief[d][1] != "active"):
            bad_e.append(f"{rid}: touches a {brief[s][1]}/{brief[d][1]} object")
    report(not bad_e, "every edge: both endpoints stored, ATT&CK IDs and STIX relationship ID carried; "
                      "non-revocation edges join active documents only", _short(bad_e) or f"{len(brief)} documents")

    # 5. CVE links
    c1_dir = a.store or Path(man["inputs"]["c1_store"]["dir"])
    with Store.open(c1_dir) as cs:
        same = cs.build_id == st.c1_store_build_id
        links = db.execute("SELECT doc_id, cve_id, evidence_kind, evidence_ref, detail FROM cve_links").fetchall()
        states = cs.get_many({c for _, c, _, _, _ in links}, columns=("cve_id", "searchable"))
    bad_l = [f"{d} {c}" for d, c, k, ref, det in links
             if c not in states or not states[c]["searchable"] or (st.brief(d) or {}).get("searchable") != 1
             or not ref or not json.loads(det)]
    report(same and not bad_l, "CVE links: every link names a searchable document and a CVE searchable in the C1 "
                               "store, with evidence", f"store {st.c1_store_build_id}; {len(links)} links; "
                                                       f"problems {_short(bad_l) or 'none'}")
    info("CVE links by evidence", json.dumps(rp["cve_links_by_evidence"]) +
         f"; {rp['cve_links_distinct_cves']} CVEs, {rp['cve_links_distinct_docs']} documents")
    kev = man["inputs"]["kev_attack_mappings"]
    report(bool(kev["licence_decision"]) and (kev["ingested"] or "not in the accepted list" in kev["licence_decision"]),
           "KEV-to-ATT&CK licence decision recorded", f"{(kev['licence'] or {}).get('name')}: ingested="
                                                     f"{kev['ingested']} ({kev['licence_decision']})")

    # 6. gazetteer
    gz = rp["gazetteer"]
    g = st.gazetteer()
    pol = st.gazetteer_policy
    info("gazetteer", f"{gz['names']} names, {gz['keys']} keys, by origin {json.dumps(gz['names_by_origin'])}; "
                      f"{gz['ambiguous_keys']} ambiguous, {gz['restricted_keys']} restricted "
                      f"(short <= {pol['short_max_chars']} chars or CVE-corpus term df >= {pol['corpus_term_min_df']})")
    info("ambiguous names", _short(f"{k} -> {'/'.join(v)}" for k, v in gz["ambiguous"].items()))
    info("restricted names", _short((f"{k} ({v['reason']}, df {v['df_cve']})" for k, v in
                                     sorted(gz["restricted"].items(), key=lambda x: -x[1]["df_cve"])), 40))
    bad_g = []
    for key, info_ in g.key_info.items():
        if info_["policy"] != "restricted":
            continue
        surface = g.entries[key][0].surface
        if not any(set(m.doc_ids) == {c.doc_id for c in g.entries[key]} for m in g.match(surface)):
            bad_g.append(f"{surface}: whole query does not resolve")
        if any(m.key == key for m in g.match(f"we saw {surface} in the logs yesterday", query=True)):
            bad_g.append(f"{surface}: matched inside a sentence without a marker")
    report(not bad_g, "short/common-word policy applied: every restricted name resolves as a whole query and not "
                      "inside a sentence without a marker", _short(bad_g) or f"{gz['restricted_keys']} names tested")

    # 7. API layer: stix_relationships traceable; health
    graph = AttackGraph(st)
    qs = probe_queries(st)
    res = probe_api(graph, qs)
    n_rel, bad_r = check_relationship_strings(st, res["responses"])
    report(n_rel > 0 and not bad_r, "API: every stix_relationships entry is a stored edge named by ATT&CK IDs",
           f"{n_rel} relationship strings over {len(qs)} queries; problems {_short(bad_r) or 'none'}")
    hb = res["health"]
    report(hb["components"].get("knowledge_graph") == "available"
           and hb.get("builds", {}).get("attack", {}).get("build_id") == st.build_id,
           "API: /api/v1/health reports the ATT&CK component available with its build ID",
           json.dumps(hb.get("builds", {}).get("attack")))
    sample = next((s for _, _, b in res["responses"] for m in b.get("top_matches", []) for s in m["stix_relationships"]), "")
    info("sample relationship string", sample)

    # 8. hardcoded lists gone
    hits = scan_hardcoded(st)
    report(not hits, "hardcoded ATT&CK stub and actor/malware/tool lists gone from threat_retrieval_engine/",
           _short(hits) or "no removed identifiers, no ATT&CK names as string literals")

    # 9. benchmark: attack: doc_ids of train/dev qrels exist; T9 dev exact-name coverage
    bench = a.benchmark
    if (bench / "queries.jsonl").is_file() and (bench / "qrels.jsonl").is_file():
        queries, qrels = read_split_files(bench)
        named = sorted({r["doc_id"] for r in qrels if r["doc_id"].startswith("attack:")})
        missing = [d for d in named if st.brief(d) is None]
        nonsearch = [f"{d} ({st.brief(d)['state']})" for d in named if st.brief(d) and not st.brief(d)["searchable"]]
        report(not missing and not nonsearch, "every attack: doc_id in train/dev qrels exists and is searchable",
               f"{len(named)} doc_ids; missing {_short(missing) or 'none'}; revoked/deprecated {_short(nonsearch) or 'none'}")
        t9 = [q for q in queries.values() if q["slice"] == "T9" and q["split"] == "dev"]
        rel_by_q: dict[str, set] = {}
        for r in qrels:
            if r["grade"] >= 2:
                rel_by_q.setdefault(r["qid"], set()).add(r["doc_id"])
        cov = {}
        for form in ("exact_name", "id", "alias"):
            qq = [q for q in t9 if q["meta"].get("query_type") == form]
            hit, unamb, misses = 0, 0, []
            for q in qq:
                target = rel_by_q.get(q["qid"], set())
                # exact_name: the mention must be the whole query; id and alias: anywhere in the query
                ms = [m for m in g.match(q["text"], query=True) if set(m.doc_ids) & target
                      and (form != "exact_name" or m.key == alias_norm(q["text"]))]
                if ms:
                    hit += 1
                    unamb += any(set(m.doc_ids) <= target for m in ms)
                else:
                    misses.append(f"{q['text']!r} -> {sorted(target)}")
            cov[form] = {"queries": len(qq), "resolved": hit, "unambiguous": unamb, "misses": misses}
        e = cov["exact_name"]
        figures["t9_dev_coverage"] = cov
        report(e["queries"] > 0 and e["resolved"] == e["queries"],
               "gazetteer resolves every T9 dev exact_name query to its target",
               f"{e['resolved']}/{e['queries']} ({e['resolved'] / max(1, e['queries']):.1%}), unambiguous "
               f"{e['unambiguous']}; misses: {_short(e['misses']) or 'none'}")
        for form in ("id", "alias"):
            c = cov[form]
            info(f"T9 dev {form} queries resolved by the gazetteer",
                 f"{c['resolved']}/{c['queries']}, unambiguous {c['unambiguous']}; misses: {_short(c['misses']) or 'none'}")
    else:
        report(False, "benchmark train/dev files found", f"{bench}")

    # 10. counts and build time
    tm = man["timings"]
    size = (bdir / "attack.sqlite").stat().st_size
    report(bool(tm.get("total_s")) and size > 0, "counts, build time and size reported",
           f"{q1('SELECT COUNT(*) FROM objects')} documents, {q1('SELECT COUNT(*) FROM edges')} edges, "
           f"{q1('SELECT COUNT(*) FROM cve_links')} CVE links, {q1('SELECT COUNT(*) FROM gazetteer')} names; "
           f"build {tm['total_s']} s ({json.dumps(tm)}), {size / 1e6:.1f} MB")
    figures.update({"timings": tm, "bytes": size, "reconciliation": rec, "report": {k: v for k, v in rp.items()
                                                                                    if k != "gazetteer"}})

    # 11. tests
    if not a.skip_tests:
        p = subprocess.run([sys.executable, "-m", "pytest", "verify", "tests", "-q"], cwd=REPO_ROOT,
                           capture_output=True, text=True)
        last = [ln for ln in p.stdout.strip().splitlines() if ln.strip()][-1:] or [""]
        report(p.returncode == 0, "full test suite: python -m pytest verify tests -q", last[0])
    db.close()
    st.close()
    if a.json_out:
        a.json_out.write_text(json.dumps(figures, indent=2, default=str), encoding="utf-8")
    print(f"\n{'ALL PASS' if not _fails else str(_fails) + ' FAILED'}")
    return 1 if _fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
