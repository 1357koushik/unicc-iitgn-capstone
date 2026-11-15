"""Acceptance check for work package C2 (lexical index). PASS / FAIL / PENDING per item; exit 1 on any FAIL.

    python -m threat_retrieval_engine.lexical.check_c2 [--index <build>] [--store <C1 build>]
        [--v2-report results/lexical/reports/v2_lexical-dev.json] [--v1-report results/lexical/reports/v1_lexical-dev.json]
        [--latency-dir results/lexical/latency] [--fuzz 10000] [--skip-rebuild]

Items
  count         FTS5 rows = docs rows = store searchable rows; every searchable CVE has its rowid
  manifest      manifest hash of the index file matches; tokenizer and format match the code
  determinism   a rebuild from the same store gives a byte-identical index (sha256)
  tokenizer     unit round trips (FTS5 re-tokenizes pre-tokenized text identically, quoted tokens match) and, on
                the real index, 1,000 sampled store rows re-tokenized: per-column token counts equal the index's,
                every token is in the vocabulary
  equality      impact-matrix ranking = plain FTS5 bm25() ranking (same order, scores within 1e-5 relative) on
                every train and dev query; with ATT&CK documents also over all kinds on dev
  fuzz          N random and malformed queries: no exception, no FTS5 syntax error, each under 1 s
  recall_gate   per-slice dev Recall@50 of v2_lexical >= v1_lexical (harness reports); lists slices below
  latency_pc    PC p50/p95/p99 (warm and cold) reported for this index
  latency_server  server p95 <= 30 ms for this index (warm, and a fresh process after LexicalIndex.warm(), the
                service start-up path): PASS / FAIL, or PENDING when not yet measured
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from ..text.tokenizer import fts5_tokenize_option, tokenize
from .build import build as build_lexical
from .build import sha256_file
from .fuzz import fuzz_queries, run_fuzz
from .index import LexicalIndex
from .schema import COLUMNS, LEXICAL_FORMAT, cve_rowid
from .sources import CveStoreSource

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_P95_LIMIT_MS = 30.0


class Checks:
    def __init__(self):
        self.rows: list[tuple[str, str, str]] = []

    def add(self, name: str, status: str, detail: str) -> None:
        self.rows.append((name, status, detail))
        print(f"[{status}] {name}: {detail}", flush=True)

    def ok(self, name: str, cond: bool, detail: str) -> None:
        self.add(name, "PASS" if cond else "FAIL", detail)


def check_count(c: Checks, ix: LexicalIndex, store) -> None:
    db = ix._conn()
    n_fts = db.execute("SELECT COUNT(*) FROM lex").fetchone()[0]
    n_docs = ix.count("cve")
    n_store = store.count(searchable=True)
    missing = 0
    have = {r for (r,) in db.execute("SELECT rowid FROM docs WHERE doc_kind = 'cve'")}
    for row in store.iter_searchable(columns=("cve_id",)):
        if cve_rowid(row["cve_id"]) not in have:
            missing += 1
    n_all = ix.count()
    att = [s for s in ix.manifest.get("inputs", []) if s.get("kind") == "attack"]
    n_att, want_att = ix.count("attack"), (att[0].get("documents") if att else 0)
    c.ok("count", n_fts == n_all == len(ix.rowids) and n_docs == n_store and missing == 0 and n_att == want_att,
         f"fts rows {n_fts:,} = docs {n_all:,} = impact {len(ix.rowids):,}; CVE docs {n_docs:,} = store searchable "
         f"{n_store:,}, searchable CVEs without a row {missing}; ATT&CK docs {n_att:,} = C9 active searchable {want_att:,}")


def check_manifest(c: Checks, ix: LexicalIndex) -> None:
    m = ix.manifest
    sha = sha256_file(ix.path)
    good = (m.get("index_sha256") == sha and m.get("format") == LEXICAL_FORMAT
            and m.get("identity_check", {}).get("mismatches") == 0 and m.get("columns") == list(COLUMNS))
    c.ok("manifest", good, f"index sha256 {sha[:16]}..., manifest {str(m.get('index_sha256'))[:16]}..., "
                           f"identity check {m.get('identity_check')}, tokenizer {ix.meta.get('tokenizer')}")


def check_determinism(c: Checks, ix: LexicalIndex, store_path: str | None, skip: bool) -> None:
    if skip:
        c.add("determinism", "FAIL", "skipped by --skip-rebuild (not verified)")
        return
    from .config import RankingConfig
    tmp = Path(tempfile.mkdtemp(prefix="c2-rebuild-", dir=str(ix.build_dir.parent)))
    try:
        ranking = RankingConfig.from_dict(ix.manifest["ranking"])
        tok = ix.tokenizer
        from .sources import open_attack
        extra = [open_attack(s["attack_path"]) for s in ix.manifest["inputs"] if s.get("kind") == "attack"]
        bdir = build_lexical(store_path or ix.manifest["inputs"][0]["store_path"], tmp, tokenizer=tok, extra_sources=extra,
                             ranking=ranking, set_latest=False, progress=lambda m: None)
        sha = sha256_file(bdir / "lexical.sqlite")
        m2 = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
        same = (sha == ix.manifest.get("index_sha256") and m2["documents_sha256"] == ix.manifest["documents_sha256"]
                and m2["impact"]["sha256"] == ix.manifest["impact"]["sha256"])
        c.ok("determinism", same, f"rebuild sha256 {sha[:16]}... vs {ix.manifest.get('index_sha256', '')[:16]}...")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_tokenizer(c: Checks, ix: LexicalIndex, store, n_sample: int = 1000) -> None:
    problems = []
    texts = ["Apache Log4j2 2.0-beta9 through 2.15.0 (CVE-2021-44228) JNDI; log4j-core /etc/passwd cmd.exe",
             "हिन्दी 漏洞 Ünïcödé ＣＶＥ－２０２１－４４２２８ mysql_real_escape_string() 185.123.45.10",
             "\"NEAR(a b)\" col:x * ^y ((( AND OR NOT t1059.001 CWE79"]
    mem = sqlite3.connect(":memory:")
    tok_opt = fts5_tokenize_option().replace('"', '""')
    mem.execute(f'CREATE VIRTUAL TABLE t USING fts5(x, tokenize="{tok_opt}")')
    mem.execute("CREATE VIRTUAL TABLE v USING fts5vocab(t, instance)")
    for i, text in enumerate(texts, 1):
        toks = tokenize(text, ix.tokenizer)
        mem.execute("INSERT INTO t(rowid, x) VALUES (?, ?)", (i, " ".join(toks)))
        got = [r[0] for r in mem.execute("SELECT term FROM v WHERE doc = ? ORDER BY offset", (i,))]
        if got != toks:
            problems.append(f"round trip differs for {text[:30]!r}")
        for term in set(toks):
            if mem.execute("SELECT count(*) FROM t WHERE t MATCH ? AND rowid = ?", ('"' + term + '"', i)).fetchone()[0] != 1:
                problems.append(f"quoted {term!r} does not match")
    # sampled store rows against the real index
    rnd = random.Random(20261115)
    db = ix._conn()
    src = CveStoreSource(store)
    ids = [r for (r,) in db.execute("SELECT doc_id FROM docs WHERE doc_kind = 'cve'")]
    sample = sorted(rnd.sample(ids, min(n_sample, len(ids))))
    vocab_missing = 0
    checked = 0
    for cid in sample:
        row = store.get(cid, columns=("cve_id", "title", "aliases", "vendor_product", "description", "weakness",
                                      "kev_text"))
        cols = {k: row.get(k) or "" for k in COLUMNS if k not in ("ids", "exploit_titles")}
        cols["ids"] = cid
        cols["exploit_titles"] = "; ".join(sorted({a["alias"] for a in store.aliases(cid, kinds=("title",))}))
        counts, terms = [], set()
        for col in COLUMNS:
            toks = tokenize(cols[col], ix.tokenizer)
            counts.append(len(toks))
            terms.update(toks)
        stored = json.loads(db.execute("SELECT column_tokens FROM docs WHERE rowid = ?", (cve_rowid(cid),)).fetchone()[0])
        if stored != counts:
            problems.append(f"{cid}: column token counts {counts} != index {stored}")
        if terms:
            found = {t for t, in db.execute(f"SELECT term FROM vocab WHERE term IN ({','.join('?' * len(terms))})",
                                            sorted(terms))}
            vocab_missing += len(terms - found)
        checked += 1
    del src
    if vocab_missing:
        problems.append(f"{vocab_missing} sampled tokens missing from the vocabulary")
    c.ok("tokenizer", not problems, f"{len(texts)} unit round trips, {checked} sampled store rows re-tokenized; "
                                    + ("; ".join(problems[:5]) if problems else "identical"))


def check_equality(c: Checks, ix: LexicalIndex) -> None:
    """Impact-matrix ranking == plain FTS5 bm25() ranking on every train and dev query (top 100)."""
    from .evaluate import load
    bad, n, worst = [], 0, 0.0
    kinds_list = [("cve",)] + ([None] if "attack" in ix.kind_doc_range else [])
    for split in ("train", "dev"):
        _, qs = load(split)
        for q in qs:
            for kinds in kinds_list:
                if kinds is None and split != "dev":
                    continue
                a = ix.search(q.text, k=100, kinds=kinds).hits
                b = ix.search_fts5(q.text, k=100, kinds=kinds).hits
                n += 1
                rel = max((abs(x - y) / max(abs(y), 1e-12) for (_, x), (_, y) in zip(a, b)), default=0.0)
                worst = max(worst, rel)
                if [d for d, _ in a] != [d for d, _ in b] or rel > 1e-5:
                    bad.append(q.qid)
    c.ok("equality", not bad, f"{n:,} rankings (train + dev{'; dev also over all kinds' if len(kinds_list) > 1 else ''}) "
                              f"compared with plain FTS5 bm25: {len(bad)} differ; largest relative score difference "
                              f"{worst:.2e}" + (f"; first {bad[:5]}" if bad else ""))


def check_fuzz(c: Checks, ix: LexicalIndex, n: int) -> None:
    rep = run_fuzz(ix, fuzz_queries(n), per_query_limit_s=1.0)
    c.ok("fuzz", not rep["errors"] and not rep["slow"],
         f"{rep['queries']:,} queries, errors {len(rep['errors'])}, over 1 s {len(rep['slow'])}, worst {rep['worst_s']} s, "
         f"total {rep['total_s']} s" + (f"; first error {rep['errors'][0]}" if rep["errors"] else ""))


def _report(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def check_recall(c: Checks, ix: LexicalIndex, v2p: Path, v1p: Path) -> None:
    v2, v1 = _report(v2p), _report(v1p)
    if v2 is None or v1 is None:
        c.add("recall_gate", "FAIL", f"missing harness report(s): {v2p if v2 is None else ''} {v1p if v1 is None else ''}")
        return
    info = (v2["variant"].get("server") or {}).get("service_info") or {}
    if info.get("index_sha256") != ix.manifest.get("index_sha256"):
        c.add("recall_gate", "FAIL", f"{v2p} was produced with index {str(info.get('index_sha256'))[:16]}..., not the "
                                     f"checked index {ix.manifest.get('index_sha256', '')[:16]}...")
        return
    if v2["split"] != "dev" or v1["split"] != "dev":
        c.add("recall_gate", "FAIL", "reports must be on the dev split")
        return
    below, rows = [], []
    for sl in sorted(v2["populations"]):
        if not (sl.startswith("T") and len(sl) == 2):
            continue
        a = v2["populations"][sl]["metrics"]["recall@50"]["value"]
        b = (v1["populations"].get(sl) or {}).get("metrics", {}).get("recall@50", {}).get("value")
        if a is None and b is None:
            rows.append(f"{sl} n/a")
            continue
        rows.append(f"{sl} {a:.3f}>={b:.3f}" if a >= b else f"{sl} {a:.3f}<{b:.3f}")
        if a < b:
            below.append(sl)
    c.ok("recall_gate", not below, ("slices below v1: " + ", ".join(below) + "; " if below else "") + ", ".join(rows))


def _latency(dirp: Path, prefix: str, sha: str) -> dict | None:
    best = None
    for p in sorted(dirp.glob(f"{prefix}*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("index", {}).get("index_sha256") == sha:
            best = (p, d)
    return {"path": str(best[0]), **best[1]} if best else None


def check_latency(c: Checks, ix: LexicalIndex, dirp: Path) -> None:
    sha = ix.manifest.get("index_sha256")
    pc = _latency(dirp, "pc-", sha)
    if pc is None:
        c.add("latency_pc", "FAIL", f"no PC latency measurement for this index in {dirp}")
    else:
        w, k = pc["warm"]["median"], pc["cold"]["median"]
        c.add("latency_pc", "PASS", f"warm p50 {w['p50']:.1f} / p95 {w['p95']:.1f} / p99 {w['p99']:.1f} ms; cold p50 "
                                    f"{k['p50']:.1f} / p95 {k['p95']:.1f} / p99 {k['p99']:.1f} ms; after warm() p95 "
                                    f"{pc['cold_after_warmup']['median']['p95']:.1f} ms; impact matrix "
                                    f"{pc['index']['impact_nnz']:,} nnz, {pc['index']['impact_mib']} MiB, load "
                                    f"{pc['index']['impact_load_s']} s ({pc['host']}, "
                                    f"{pc['queries']['n']} dev queries; {Path(pc['path']).name})")
    sv = _latency(dirp, "server-", sha)
    if sv is None:
        c.add("latency_server", "PENDING", "no server measurement for this index yet; run "
                                           "scripts/lexical/server_latency.sh after B6 releases the benchmark lock")
        return
    w, k, c0 = sv["warm"]["median"], sv["cold_after_warmup"]["median"], sv["cold"]["median"]
    c.ok("latency_server", w["p95"] <= SERVER_P95_LIMIT_MS and k["p95"] <= SERVER_P95_LIMIT_MS,
         f"warm p95 {w['p95']:.1f} ms, fresh process after warm() p95 {k['p95']:.1f} ms (limit "
         f"{SERVER_P95_LIMIT_MS:g}); fresh process without warm-up p95 {c0['p95']:.1f} ms (reported); "
         f"load {sv.get('load_average')} ({Path(sv['path']).name})")


def main(argv: list[str] | None = None) -> int:
    from ..store import Store
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--index")
    ap.add_argument("--store")
    ap.add_argument("--v2-report", type=Path, default=REPO_ROOT / "results/lexical/reports/v2_lexical-dev.json")
    ap.add_argument("--v1-report", type=Path, default=REPO_ROOT / "results/lexical/reports/v1_lexical-dev.json")
    ap.add_argument("--latency-dir", type=Path, default=REPO_ROOT / "results/lexical/latency")
    ap.add_argument("--fuzz", type=int, default=10_000)
    ap.add_argument("--skip-rebuild", action="store_true", help="do not rebuild (determinism then reports FAIL)")
    a = ap.parse_args(argv)
    c = Checks()
    ix = LexicalIndex.open(a.index, verify=True)
    store_path = a.store or ix.manifest["inputs"][0]["store_path"]
    with Store.open(store_path) as store:
        check_count(c, ix, store)
        check_manifest(c, ix)
        check_tokenizer(c, ix, store)
    check_equality(c, ix)
    check_fuzz(c, ix, a.fuzz)
    check_recall(c, ix, a.v2_report, a.v1_report)
    check_latency(c, ix, a.latency_dir)
    check_determinism(c, ix, store_path, a.skip_rebuild)
    ix.close()
    fails = [n for n, s, _ in c.rows if s == "FAIL"]
    pend = [n for n, s, _ in c.rows if s == "PENDING"]
    print(f"\ncheck_c2: {'FAIL' if fails else 'PASS'} ({len(c.rows) - len(fails) - len(pend)} pass, {len(fails)} fail"
          f"{', ' + str(len(pend)) + ' pending: ' + ', '.join(pend) if pend else ''})"
          + (f"; failed: {', '.join(fails)}" if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
