"""Acceptance check for work package C3 (dense search). PASS / FAIL / PENDING per item; exit 1 on any FAIL.

    python -m threat_retrieval_engine.dense.check_c3 [--index <build>] [--store <C1 build>] [--attack <C9 build>]
        [--queries <dev+train queries.jsonl>] [--latency-dir results/dense/latency] [--comparison results/dense/comparison]
        [--n-exact 1000] [--fuzz 2000] [--reencode 300]

Items
  manifest      files match the manifest's sha256; format; model pinned in the code (repository, revision, pooling,
                prefixes, weights sha256) or the v1 export described; build ID recorded
  count         rows = documents (one vector per document; for the v1 export with collapse max, rows = sum of the
                documents' v1 rows); every document is a searchable C1 CVE or an active C9 document of the input
                builds; a full encoded build holds every searchable CVE and ATT&CK document (vector count = document
                count); the v1 export reports its coverage (searchable CVEs without a v1 vector)
  norms         every vector finite with unit norm (|n - 1| <= 1e-3)
  exact         N train/dev queries (encoded with the index's model): search(k=100) for CVE and all kinds equals the
                float32 complete sort exactly, and the float64 brute force except where float64 scores differ by less
                than 1e-6 (float32 rounding; counted)
  determinism   the same N queries encoded and searched twice give bit-identical vectors and identical rankings; a
                fresh index open gives the same rankings
  reencode      (encoded builds) a seeded sample of documents re-encoded on this machine from documents.jsonl
                agrees with the stored vectors (cosine >= 0.9999)
  fuzz          malformed text through DenseRetriever (the lexical fuzz corpus, first N) and malformed vectors, k,
                kinds and masks through DenseIndex: no unexpected exception, no hang, each text query under 2 s
  latency_server  dense search p95 <= 60 ms on the server for this index (results/dense/latency/server-search-*.json)
  encode_latency  query-encoding p95 on the server reported against the 250 ms target (a target, not a limit)
  comparison    the model comparison and the C3b decision are recorded with numbers (comparison.json)
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

import numpy as np

from . import models as M
from .index import GROUPS_FILE, DenseIndex, top_k
from .schema import DENSE_FORMAT, DOC_IDS_FILE, VECTORS_FILE

REPO_ROOT = Path(__file__).resolve().parents[2]
SEARCH_P95_LIMIT_MS = 60.0
ENCODE_P95_TARGET_MS = 250.0


class Checks:
    def __init__(self):
        self.rows: list[tuple[str, str, str]] = []

    def add(self, name, status, detail):
        self.rows.append((name, status, detail))
        print(f"[{status}] {name}: {detail}", flush=True)

    def ok(self, name, cond, detail):
        self.add(name, "PASS" if cond else "FAIL", detail)


def check_manifest(c: Checks, ix: DenseIndex) -> None:
    from .index import _sha256
    m = ix.manifest
    problems = []
    for name in [VECTORS_FILE, DOC_IDS_FILE] + ([GROUPS_FILE] if m.get("row_groups") else []):
        if _sha256(ix.build_dir / name) != m["files"].get(name):
            problems.append(f"{name} sha256")
    if m.get("format") != DENSE_FORMAT:
        problems.append("format")
    model = m.get("model") or {}
    spec = M.MODELS.get(model.get("name"))
    if spec is None:
        problems.append(f"unknown model {model.get('name')}")
    else:
        for k in ("repo", "revision", "pooling", "query_prefix", "passage_prefix", "dim", "weights_sha256"):
            if model.get(k) != getattr(spec, k):
                problems.append(f"model {k}")
    if m.get("source") not in ("encoded", "v1_export"):
        problems.append(f"source {m.get('source')}")
    c.ok("manifest", not problems, f"build {ix.build_id}, source {m.get('source')}, model {model.get('name')}@"
                                   f"{str(model.get('revision'))[:12]}, vectors sha256 {m['files'][VECTORS_FILE][:16]}..."
                                   + (f"; problems: {problems}" if problems else ""))


def check_count(c: Checks, ix: DenseIndex, store_path, attack_path) -> None:
    from ..store import Store
    m = ix.manifest
    inputs = m.get("inputs") or {}
    sp = store_path or (inputs.get("store") or {}).get("path")
    problems = []
    with Store.open(sp) as s:
        if s.build_id != (inputs.get("store") or {}).get("build_id"):
            problems.append(f"store {s.build_id} is not the build's {(inputs.get('store') or {}).get('build_id')}")
        searchable = {r["cve_id"] for r in s.iter_searchable(columns=("cve_id",))}
    cves = ix.doc_ids[slice(*ix.kind_ranges.get("cve", (0, 0)))]
    att = ix.doc_ids[slice(*ix.kind_ranges.get("attack", (0, 0)))]
    not_searchable = [d for d in cves if d not in searchable]
    if not_searchable:
        problems.append(f"{len(not_searchable)} CVE documents not searchable in the store, e.g. {not_searchable[:3]}")
    rows = ix.vectors.shape[0]
    want_rows = int(m["rows"]) if m.get("row_groups") else ix.n_docs
    if rows != want_rows or len(set(ix.doc_ids)) != ix.n_docs:
        problems.append(f"rows {rows} vs {want_rows}, distinct doc_ids {len(set(ix.doc_ids))} vs {ix.n_docs}")
    detail = f"{ix.n_docs:,} documents ({len(cves):,} CVE, {len(att):,} ATT&CK), {rows:,} vector rows"
    if m.get("source") == "encoded":
        full = (m.get("selection") or {}).get("rule") == "all searchable documents"
        if "attack" in inputs:
            from ..attack import AttackStore
            a = AttackStore.open(attack_path or inputs["attack"]["path"])
            try:
                active = {r["doc_id"] for r in a.iter_searchable(columns=("doc_id", "state")) if r.get("state") == "active"}
            finally:
                a.close()
            if set(att) - active:
                problems.append(f"{len(set(att) - active)} ATT&CK documents not active+searchable")
        else:
            active = set()
        if full:
            if set(cves) != searchable or (active and set(att) != active):
                problems.append(f"full build: CVE {len(cves):,} vs store {len(searchable):,}, ATT&CK {len(att):,} vs "
                                f"{len(active):,}")
            detail += f"; full build: vector count = document count = store searchable {len(searchable):,} + ATT&CK " \
                      f"{len(active):,}"
        else:
            detail += f"; selection: {(m.get('selection') or {}).get('rule')}"
    else:
        cov = m.get("coverage") or {}
        detail += (f"; v1 export (collapse {m.get('collapse')}): {cov.get('cves'):,} of {len(searchable):,} searchable CVEs "
                   f"have a v1 vector, {len(searchable) - len(cves):,} have none (not a full build: vector count < "
                   f"searchable documents; v1 has no ATT&CK vectors); {cov.get('cves_with_several_rows'):,} CVEs with "
                   f"several v1 rows; {sum((cov.get('dropped_rows') or {}).values()):,} v1 rows dropped "
                   f"({cov.get('dropped_rows')})")
        if (m.get("selection") or {}).get("rule", "").startswith("all searchable") and \
                len(searchable) - len(cves) != cov.get("store_searchable_without_v1_vector"):
            problems.append("coverage in the manifest differs from the store")
    c.ok("count", not problems, detail + (f"; problems: {problems}" if problems else ""))


def check_norms(c: Checks, ix: DenseIndex) -> None:
    try:
        worst = ix.check_norms()
        c.ok("norms", True, f"{ix.vectors.shape[0]:,} vectors finite, max |norm - 1| = {worst:.2e}")
    except Exception as exc:
        c.ok("norms", False, str(exc))


def load_queries(path: Path, n: int, seed: int = 20261117) -> list[str]:
    qs = []
    for line in open(path, encoding="utf-8"):
        q = json.loads(line)
        if q.get("split") == "test":
            raise SystemExit("refusing a queries file with test-split queries")
        if q.get("split") in ("train", "dev"):
            qs.append(q["text"])
    rnd = random.Random(seed)
    return rnd.sample(qs, min(n, len(qs)))


def check_exact_and_determinism(c: Checks, ix: DenseIndex, retriever, texts: list[str]) -> list[np.ndarray]:
    t0 = time.time()
    vecs = [retriever.encoder.encode_ids(retriever.encoder.tokenizer(
        [retriever.model_input(t)], truncation=True, max_length=retriever.query_max_tokens, padding=False,
        return_attention_mask=False, return_token_type_ids=False)["input_ids"]) [0] for t in texts]
    enc_s = time.time() - t0
    bad32, bad64, near, n = [], [], 0, 0
    kinds_list = [("cve",)] + ([None] if "attack" in ix.kind_ranges else [])
    first = {}
    for i, v in enumerate(vecs):
        for kinds in kinds_list:
            hits = ix.search(v, k=100, kinds=kinds)
            first[(i, kinds)] = hits
            s, ranges = ix.scores(v, kinds)
            pos = np.concatenate([np.arange(a, b) for a, b in ranges])
            full32 = np.lexsort((np.arange(len(s)), -s.astype(np.float64)))[:100]
            if [d for d, _ in hits] != [ix.doc_ids[int(pos[j])] for j in full32]:
                bad32.append(i)
            ref = ix.brute_force(v, k=100, kinds=kinds)
            if [d for d, _ in hits] != [d for d, _ in ref]:
                # differences allowed only between documents whose float64 scores are within float32 rounding
                ref_s = dict(ref)
                a_ids = [d for d, _ in hits]
                b_ids = [d for d, _ in ref]
                diff = [j for j, (x, y) in enumerate(zip(a_ids, b_ids)) if x != y]
                ok = True
                v64 = v.astype(np.float64)
                for j in diff:
                    x, y = a_ids[j], b_ids[j]
                    sx = float(ix.vectors[ix.position(x)].astype(np.float64) @ v64) if ix.groups is None else dict(hits)[x]
                    sy = ref_s[y]
                    if abs(sx - sy) > 1e-6:
                        ok = False
                if ok:
                    near += 1
                else:
                    bad64.append(i)
            n += 1
    c.ok("exact", not bad32 and not bad64,
         f"{len(texts):,} train/dev queries, {n:,} rankings (top 100; CVE kind" + (" and all kinds" if len(kinds_list) > 1
         else "") + f"): {len(bad32)} differ from the complete float32 sort, {len(bad64)} differ from the float64 brute "
         f"force beyond float32 rounding, {near} differ only among documents within 1e-6 (float32 rounding); query "
         f"encoding {enc_s:.0f} s")
    # determinism: encode and search again; and from a freshly opened index
    again = [retriever.encoder.encode_ids(retriever.encoder.tokenizer(
        [retriever.model_input(t)], truncation=True, max_length=retriever.query_max_tokens, padding=False,
        return_attention_mask=False, return_token_type_ids=False)["input_ids"])[0] for t in texts]
    vec_same = all(np.array_equal(a, b) for a, b in zip(vecs, again))
    fresh = DenseIndex.open(ix.build_dir)
    rank_same = all(ix.search(v, k=100, kinds=k) == first[(i, k)] for i, v in enumerate(again) for k in kinds_list)
    fresh_same = all(fresh.search(v, k=100, kinds=k) == first[(i, k)] for i, v in enumerate(vecs) for k in kinds_list)
    c.ok("determinism", vec_same and rank_same and fresh_same,
         f"query vectors bit-identical on re-encoding: {vec_same}; rankings identical on repeat: {rank_same}; identical "
         f"from a freshly opened index: {fresh_same}")
    return vecs


def check_reencode(c: Checks, ix: DenseIndex, n: int, model_root) -> None:
    m = ix.manifest
    if m.get("source") != "encoded":
        c.add("reencode", "PASS", "not applicable: v1 export (vectors computed by v1; their source sha256 "
                                  f"{(m.get('inputs') or {}).get('qdrant_storage_sha256', '')[:16]}... is recorded)")
        return
    from .encoder import Encoder
    from .sources import DocumentSet
    ds = DocumentSet.read(ix.build_dir / "documents.jsonl")
    if ds.doc_ids != ix.doc_ids or ds.sha256() != m["inputs"]["documents_sha256"]:
        c.ok("reencode", False, "documents.jsonl does not match the index rows or the manifest")
        return
    rnd = random.Random(20261117)
    idx = sorted(rnd.sample(range(len(ds)), min(n, len(ds))))
    enc = Encoder.load(m["model"]["name"], model_root=model_root)
    v = enc.encode_documents([ds.texts[i] for i in idx], max_tokens=int(m["model"]["document_max_tokens"]))
    cos = (v * ix.vectors[idx]).sum(axis=1)
    c.ok("reencode", float(cos.min()) >= 0.9999,
         f"{len(idx)} sampled documents re-encoded here: cosine min {cos.min():.7f}, mean {cos.mean():.7f}, max |diff| "
         f"{float(np.abs(v - ix.vectors[idx]).max()):.2e} (stored vectors encoded on {m['encode'].get('hosts')})")


def check_fuzz(c: Checks, ix: DenseIndex, retriever, n_text: int) -> None:
    from ..lexical.fuzz import fuzz_queries
    errors, slow, worst = [], [], 0.0
    for i, q in enumerate(fuzz_queries(n_text)):
        t0 = time.perf_counter()
        try:
            retriever.search(q, k=100, kinds=None)
        except Exception as exc:
            errors.append(f"{i}: {type(exc).__name__}: {exc}"[:200])
        dt = time.perf_counter() - t0
        worst = max(worst, dt)
        if dt > 2.0:
            slow.append(i)
    # malformed API input must raise ValueError/TypeError, never anything else
    rnd = np.random.default_rng(7)
    unexpected = []
    bad_inputs = [np.zeros(ix.dim + 1, np.float32), np.full(ix.dim, np.nan, np.float32), np.ones((1, ix.dim)),
                  np.array(["x"] * ix.dim), np.full(ix.dim, np.inf), [], None]
    for j in range(1000):
        x = bad_inputs[j % len(bad_inputs)]
        try:
            ix.search(x, k=int(rnd.integers(1, 50)))
            unexpected.append(f"accepted bad vector {j}")
        except (ValueError, TypeError):
            pass
        except Exception as exc:
            unexpected.append(f"{type(exc).__name__}: {exc}"[:120])
    good = np.ones(ix.dim, np.float32) / np.sqrt(ix.dim)
    for k in (0, -3, 2.5, True, "10", None):
        try:
            ix.search(good, k=k)
            unexpected.append(f"accepted k={k!r}")
        except (ValueError, TypeError):
            pass
    for kinds in (("x",), (), "nope"):
        try:
            ix.search(good, kinds=kinds)
            unexpected.append(f"accepted kinds={kinds!r}")
        except (ValueError, TypeError):
            pass
    for mask in (np.ones(3, bool), np.ones(ix.n_docs, int)):
        try:
            ix.search(good, mask=mask)
            unexpected.append("accepted a bad mask")
        except (ValueError, TypeError):
            pass
    c.ok("fuzz", not errors and not slow and not unexpected,
         f"{n_text:,} malformed text queries: errors {len(errors)}, over 2 s {len(slow)}, worst {worst:.2f} s; "
         f"1,000+ malformed vectors/k/kinds/masks: {len(unexpected)} accepted or wrong exception"
         + (f"; first {(errors + unexpected)[:2]}" if errors or unexpected else ""))


def _latest(dirp: Path, prefix: str, key: str, value: str) -> tuple[Path, dict] | None:
    best = None
    for p in sorted(dirp.glob(f"{prefix}*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if (d.get("index") or {}).get(key) == value or d.get(key) == value:
            best = (p, d)
    return best


def check_latency(c: Checks, ix: DenseIndex, dirp: Path) -> None:
    sha = ix.manifest["files"][VECTORS_FILE]
    sv = _latest(dirp, "server-search-", "vectors_sha256", sha)
    if sv is None:
        c.add("latency_server", "PENDING", f"no server search measurement for this index in {dirp}")
    else:
        p, d = sv
        ch = d["chosen"]
        c.ok("latency_server", ch["cve"]["p95"] <= SEARCH_P95_LIMIT_MS and ch["all"]["p95"] <= SEARCH_P95_LIMIT_MS,
             f"BLAS threads {d['blas_threads_chosen']} (fixed by sweep): CVE kind p50 {ch['cve']['p50']:.1f} / p95 "
             f"{ch['cve']['p95']:.1f} / p99 {ch['cve']['p99']:.1f} ms; all kinds p95 {ch['all']['p95']:.1f} ms (limit "
             f"{SEARCH_P95_LIMIT_MS:g}); index open {d['open_fresh_process']['median_ms'] / 1000:.1f} s; "
             f"{d['queries']['n']} dev queries x {d['repeat']}, load {d['load_average']} ({p.name})")
    model = (ix.manifest.get("model") or {}).get("name")
    ev = None
    for p in sorted(dirp.glob("server-encode-*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if model in d.get("models", {}) and "all_queries_at_chosen" in d["models"][model]:
            ev = (p, d)
    if ev is None:
        c.add("encode_latency", "PENDING", f"no server encoding measurement for {model}")
    else:
        p, d = ev
        e = d["models"][model]
        a = e["all_queries_at_chosen"]["median"]
        c.add("encode_latency", "PASS" if a["p95"] <= ENCODE_P95_TARGET_MS else "TARGET-MISSED",
              f"{model}, {e['torch_threads_chosen']} torch threads (fixed by sweep), batch 1, cap {d['max_tokens']} "
              f"tokens: p50 {a['p50']:.0f} / p95 {a['p95']:.0f} / p99 {a['p99']:.0f} ms over {d['queries']['n']} dev "
              f"queries x {d['repeat']} (target p95 {ENCODE_P95_TARGET_MS:g} ms; a target, not a limit) ({p.name})")


def check_comparison(c: Checks, path: Path) -> None:
    p = path / "comparison.json"
    if not p.is_file():
        c.add("comparison", "FAIL", f"{p} missing")
        return
    d = json.loads(p.read_text(encoding="utf-8"))
    dec, re_ = d.get("decision"), d.get("reembed")
    if not dec or not re_:
        c.add("comparison", "FAIL", "comparison.json has no decision")
        return
    w = dec["winner"]
    mm = d["dev"][w]["macro"]
    c.ok("comparison", True, f"winner {dec['winner_model']} (dev macro Recall@50 {mm['recall@50']['value']:.3f}, "
                             f"nDCG@10 {mm['ndcg@10']['value']:.3f}); C3b needed: {re_['c3b_needed']} (vs "
                             f"{re_['stronger_v1_baseline']}: better on {re_['significantly_better_on']}, worse on "
                             f"{re_['significantly_worse_on']})")


def main(argv: list[str] | None = None) -> int:
    from .retriever import DenseRetriever
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--index")
    ap.add_argument("--store")
    ap.add_argument("--attack")
    ap.add_argument("--queries", type=Path, default=REPO_ROOT / "data/benchmark/v2.0/queries.jsonl")
    ap.add_argument("--latency-dir", type=Path, default=REPO_ROOT / "results/dense/latency")
    ap.add_argument("--comparison", type=Path, default=REPO_ROOT / "results/dense/comparison")
    ap.add_argument("--n-exact", type=int, default=1000)
    ap.add_argument("--fuzz", type=int, default=2000)
    ap.add_argument("--reencode", type=int, default=300)
    ap.add_argument("--model-root")
    ap.add_argument("--torch-threads", type=int)
    a = ap.parse_args(argv)
    c = Checks()
    ix = DenseIndex.open(a.index)
    check_manifest(c, ix)
    check_count(c, ix, a.store, a.attack)
    check_norms(c, ix)
    r = DenseRetriever(ix, torch_threads=a.torch_threads, model_root=a.model_root)
    check_exact_and_determinism(c, ix, r, load_queries(a.queries, a.n_exact))
    check_reencode(c, ix, a.reencode, a.model_root)
    check_fuzz(c, ix, r, a.fuzz)
    check_latency(c, ix, a.latency_dir)
    check_comparison(c, a.comparison)
    fails = [n for n, s, _ in c.rows if s == "FAIL"]
    pend = [n for n, s, _ in c.rows if s == "PENDING"]
    print(f"\ncheck_c3: {'FAIL' if fails else 'PASS'} ({len(c.rows) - len(fails) - len(pend)} pass/reported, "
          f"{len(fails)} fail" + (f", {len(pend)} pending: {', '.join(pend)}" if pend else "") + ")"
          + (f"; failed: {', '.join(fails)}" if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
