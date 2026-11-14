"""B2 acceptance check: prints PASS/FAIL per item; exit 1 if any FAIL.

    python benchmarks_v2/build/check_b2.py [--out <data/benchmark>] [--version v2.0]
           [--skip-rebuild] [--skip-repo-tests]

Items: build present; manifest and file hashes; format of every field (docs/benchmark_format.md);
every slice present with counts and every shortfall explained; overlap rule re-computed independently;
leakage tests; byte-identical second build; sealed protection; dataset card matches the build;
standard-library-only builder; repository test suite.
Never prints sealed query text or per-query results.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks_v2.build import sealed  # noqa: E402
from benchmarks_v2.build.common import (ATTACK_DOC_RE, CVE_ID_RE, OVERLAP_THRESHOLD, REPO_ROOT, SLICES,  # noqa: E402
                                        SPLIT_RATIOS, TARGET_SIZES, default_benchmark_dir, default_feeds_dir,
                                        sha256_file)

fails = 0
QUERY_KEYS = {"qid", "slice", "split", "text", "answerable", "temporal_holdout", "source", "meta"}
QREL_KEYS = {"qid", "doc_id", "grade", "origin"}
ORIGINS = {"known_item", "equivalence", "judged", "authoring"}
OVERLAP_EXEMPT = {"T1", "T7", "T9"}
CARD = REPO_ROOT / "docs" / "benchmark_dataset_card.md"


def report(ok: bool, label: str, detail: str = "") -> bool:
    global fails
    fails += (not ok)
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""), flush=True)
    return ok


def jl(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def validate_format(queries: list[dict], qrels: list[dict], eq: list[dict], where: str) -> list[str]:
    errs = []
    qids = {}
    for q in queries:
        tag = q.get("qid", "?")
        if set(q) != QUERY_KEYS:
            errs.append(f"{where} {tag}: keys {sorted(set(q) ^ QUERY_KEYS)}")
            continue
        if not isinstance(q["qid"], str) or not re.fullmatch(r"T\d-\d+", q["qid"]) or q["qid"].split("-")[0] != q["slice"]:
            errs.append(f"{where} {tag}: qid form")
        if q["slice"] not in SLICES:
            errs.append(f"{where} {tag}: slice")
        if q["split"] not in ("train", "dev", "test") or SPLIT_RATIOS.get(q["slice"], {}).get(q["split"], 0) <= 0:
            errs.append(f"{where} {tag}: split {q['split']} not allowed for slice")
        if not isinstance(q["text"], str) or not q["text"].strip():
            errs.append(f"{where} {tag}: text")
        if not isinstance(q["answerable"], bool) or q["answerable"] != (q["slice"] != "T7"):
            errs.append(f"{where} {tag}: answerable")
        if not isinstance(q["temporal_holdout"], bool):
            errs.append(f"{where} {tag}: temporal_holdout")
        s = q["source"]
        if not isinstance(s, dict) or not isinstance(s.get("name"), str) or not s["name"]:
            errs.append(f"{where} {tag}: source.name")
        elif s["name"] != "generated" and not (isinstance(s.get("id"), str) and s["id"] and isinstance(s.get("licence"), str) and s["licence"]):
            errs.append(f"{where} {tag}: source id/licence")
        if not isinstance(q["meta"], dict):
            errs.append(f"{where} {tag}: meta")
        if q["slice"] == "T6" and (not q["meta"].get("parent_qid") or
                                   q["meta"].get("noise_type") not in ("typo", "spacing", "abbreviation", "log_fragment")):
            errs.append(f"{where} {tag}: T6 meta.parent_qid / meta.noise_type")
        if q["slice"] == "T9" and q["meta"].get("query_form") not in ("id", "exact_name", "natural"):
            errs.append(f"{where} {tag}: T9 meta.query_form")
        if q["qid"] in qids:
            errs.append(f"{where} {tag}: duplicate qid")
        qids[q["qid"]] = q
    seen = set()
    g2 = defaultdict(int)
    for r in qrels:
        tag = r.get("qid", "?")
        judged = r.get("origin") == "judged"
        keys = QREL_KEYS | ({"judge"} if judged else set())
        if set(r) != keys:
            errs.append(f"{where} qrel {tag}: keys {sorted(set(r) ^ keys)}")
            continue
        if r["qid"] not in qids:
            errs.append(f"{where} qrel {tag}: unknown qid")
        if not isinstance(r["doc_id"], str) or not (CVE_ID_RE.match(r["doc_id"]) or ATTACK_DOC_RE.match(r["doc_id"])):
            errs.append(f"{where} qrel {tag}: doc_id form")
        if r["grade"] not in (0, 1, 2) or isinstance(r["grade"], bool):
            errs.append(f"{where} qrel {tag}: grade")
        if r["origin"] not in ORIGINS:
            errs.append(f"{where} qrel {tag}: origin")
        if judged and not (isinstance(r["judge"], dict) and set(r["judge"]) == {"round", "first", "second", "adjudicated"}):
            errs.append(f"{where} qrel {tag}: judge")
        k = (r["qid"], r["doc_id"])
        if k in seen:
            errs.append(f"{where} qrel {tag}: duplicate pair")
        seen.add(k)
        if r["grade"] == 2:
            g2[r["qid"]] += 1
    for qid, q in qids.items():
        if q["answerable"] and not g2.get(qid):
            errs.append(f"{where} {qid}: answerable without grade-2 qrel")
        if not q["answerable"] and any(r["qid"] == qid for r in qrels):
            errs.append(f"{where} {qid}: unanswerable with qrels")
    members = set()
    for s in eq:
        if set(s) != {"set_id", "members", "reason"}:
            errs.append(f"equivalence {s.get('set_id')}: keys")
            continue
        m = s["members"]
        if not (isinstance(m, list) and len(m) >= 2 and m == sorted(set(m)) and all(CVE_ID_RE.match(x) for x in m)):
            errs.append(f"equivalence {s['set_id']}: members")
        if members & set(m):
            errs.append(f"equivalence {s['set_id']}: overlaps another set")
        members |= set(m)
        if not isinstance(s["reason"], str) or not s["reason"]:
            errs.append(f"equivalence {s['set_id']}: reason")
    return errs


def check_overlap(u, all_q: list[dict], all_qrels: list[dict]) -> tuple[bool, str]:
    from benchmarks_v2.build.text import overlap, token_set
    qtext = {q["qid"]: (q["slice"], q["text"]) for q in all_q}
    worst = defaultdict(float)
    bad = 0
    n = 0
    cache = {}
    for r in all_qrels:
        sl, text = qtext[r["qid"]]
        if sl in OVERLAP_EXEMPT or r["grade"] != 2 or not r["doc_id"].startswith("CVE-"):
            continue
        toks = cache.get(r["doc_id"])
        if toks is None:
            toks = cache[r["doc_id"]] = token_set(u.corpus_text(r["doc_id"]))
        ov = overlap(text, toks)
        n += 1
        worst[sl] = max(worst[sl], ov)
        if ov > OVERLAP_THRESHOLD + 1e-9:
            bad += 1
    detail = f"{n} target pairs re-scored; max per slice " + ", ".join(f"{k}={v:.2f}" for k, v in sorted(worst.items()))
    return bad == 0, detail + (f"; {bad} pairs above 0.6" if bad else "")


def check_products(u, all_q: list[dict], all_qrels: list[dict]) -> tuple[bool, str, bool, str]:
    """T5/T8: (1) the product or vendor named in the query occurs in every grade-2 target's description,
    CVE List title or CNA affected vendor/product, and is part of the query text; (2) no underscores."""
    from benchmarks_v2.build.slice_products import find_span
    words = lambda s: re.findall(r"[a-z0-9]+", (s or "").lower())  # noqa: E731
    g2 = defaultdict(list)
    for r in all_qrels:
        if r["grade"] == 2:
            g2[r["qid"]].append(r["doc_id"])
    bad, n, desc_only_miss, under = 0, 0, 0, []
    per = defaultdict(lambda: [0, 0])
    for q in all_q:
        if q["slice"] not in ("T5", "T8"):
            continue
        if "_" in q["text"]:
            under.append(q["qid"])
        prod, vend = q["meta"].get("product_label"), q["meta"].get("vendor_label")
        names = [x for x in (prod, vend) if x]
        in_text = any(find_span(words(x), q["text"]) for x in names)
        for d in g2[q["qid"]]:
            n += 1
            r = u.nvd.get(d) or {"desc": u.description(d), "aff": []}
            cl = u.cvelist(d)
            texts = [r["desc"]] + [f"{a['v']} {a['p']}" for a in r.get("aff", [])] + ([cl["title"]] if cl and cl.get("title") else [])
            ok = in_text and any(find_span(words(x), t) for x in names for t in texts)
            if not ok:
                bad += 1
            per[q["slice"]][0] += 1
            if not any(find_span(words(x), r["desc"]) for x in names):
                per[q["slice"]][1] += 1
                desc_only_miss += 1
    info = "; ".join(f"{k}: {v[1]} of {v[0]} target pairs name the product only in the CNA affected block or title"
                     for k, v in sorted(per.items()))
    return bad == 0, f"{n} grade-2 pairs checked, {bad} inconsistent; {info}", not under, \
        (f"{len(under)} T5/T8 queries contain '_'" if under else "no underscores in T5/T8 query text")


def stdlib_only() -> tuple[bool, str]:
    std = set(sys.stdlib_module_names) | {"benchmarks_v2", "__future__"}
    bad = []
    for p in sorted((REPO_ROOT / "benchmarks_v2" / "build").glob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for nm in names:
                if nm.split(".")[0] not in std:
                    bad.append(f"{p.name}:{nm}")
    return not bad, ", ".join(bad) or "standard library only"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=default_benchmark_dir())
    ap.add_argument("--version", default="v2.0")
    ap.add_argument("--skip-rebuild", action="store_true")
    ap.add_argument("--skip-repo-tests", action="store_true")
    a = ap.parse_args()
    b = a.out / a.version
    if not report((b / "manifest.json").is_file(), "build present", str(b)):
        print("\n1 FAILED")
        return 1
    m = json.loads((b / "manifest.json").read_text(encoding="utf-8"))
    need = ["version", "build_date", "builder", "inputs", "files", "counts", "seed"]
    report(all(k in m for k in need) and m["builder"].get("commit") and all(i.get("sha256") or i.get("commit")
                                                                              for i in m["inputs"]),
           "manifest has version, build date, builder commit, input hashes, file hashes, counts",
           f"commit {m['builder'].get('commit', '')[:12]}, {len(m['inputs'])} inputs")
    report(all(set(f) == {"sha256", "count"} for f in m["files"].values()),
           "manifest files map path -> {sha256, count}", ", ".join(sorted(m["files"])))
    bad_hash = [rel for rel, f in m["files"].items() if sha256_file(b / rel) != f["sha256"]]
    report(not bad_hash, "every file's sha256 matches the manifest", ", ".join(bad_hash) or f"{len(m['files'])} files")

    oq, oqr, eq = jl(b / "queries.jsonl"), jl(b / "qrels.jsonl"), jl(b / "equivalence.jsonl")
    sq, sqr = sealed.audit_sealed(b, "b2_acceptance")
    errs = validate_format(oq, oqr, eq, "open") + validate_format(sq, sqr, [], "sealed")
    report(not errs, "format conforms to docs/benchmark_format.md (every field validated)",
           f"{len(oq) + len(sq)} queries, {len(oqr) + len(sqr)} qrels, {len(eq)} equivalence sets"
           + (f"; {len(errs)} errors, first: {errs[:3]}" if errs else ""))
    try:
        from benchmarks_v2.eval import schema as b4
    except ImportError:
        b4 = None
    if b4 is None:
        report(False, "B4 harness loader accepts the build", "benchmarks_v2.eval not present on this branch")
    else:
        try:
            saved = os.environ.pop(sealed.ENV, None)
            n_open = sum(len(b4.load_dataset(b, split=sp).select(split=sp)) for sp in ("train", "dev"))
            sq4 = b4.load_queries(b / sealed.SEALED_DIR / "queries.jsonl")   # schema parse only, no metrics
            b4.load_qrels(b / sealed.SEALED_DIR / "qrels.jsonl", {x.qid: x for x in sq4})
            if saved is not None:
                os.environ[sealed.ENV] = saved
            report(n_open == len(oq) and len(sq4) == len(sq), "B4 harness loader accepts the build (manifest verified)",
                   f"{n_open} train+dev queries loaded, {len(sq4)} sealed rows schema-parsed")
        except Exception as exc:  # noqa: BLE001
            report(False, "B4 harness loader accepts the build", f"{type(exc).__name__}: {str(exc)[:200]}")
    all_q, all_qr = oq + sq, oqr + sqr
    counts = defaultdict(lambda: defaultdict(int))
    for q in all_q:
        counts[q["slice"]][q["split"]] += 1
    rep = json.loads((b / "build_report.json").read_text(encoding="utf-8"))
    for sl in SLICES:
        n = sum(counts[sl].values())
        c = counts[sl]
        detail = f"train={c['train']} dev={c['dev']} test={c['test']} total={n}/{TARGET_SIZES[sl]}"
        entry = rep["slices"].get(sl, {})
        explained = n >= TARGET_SIZES[sl] or bool(entry.get("shortfall_reason"))
        if n < TARGET_SIZES[sl]:
            detail += f"; shortfall {TARGET_SIZES[sl] - n} explained in build_report.json"
        report(n > 0 and explained and {k: v for k, v in c.items() if v} == {k: v for k, v in entry.get("by_split", {}).items() if v},
               f"slice {sl} present, counts match report, shortfall explained", detail)
    from benchmarks_v2.build.universe import load_universe
    u = load_universe(default_feeds_dir(), workers=6)
    ok, detail = check_overlap(u, all_q, all_qr)
    report(ok, "overlap rule holds (independent re-computation, <= 60% per target pair)", detail)
    ok1, d1, ok2, d2 = check_products(u, all_q, all_qr)
    report(ok1, "T5/T8 product consistency (query product/vendor named in every target's text)", d1)
    report(ok2, "T5/T8 query text reads like analyst text (no CPE slugs with underscores)", d2)
    for sl in SLICES:
        o = rep["slices"][sl]["overlap"]
        if not o["exempt"]:
            bf, af = o["before_filter"], o["after_filter"]
            report(af["max"] is None or af["max"] <= OVERLAP_THRESHOLD, f"overlap distribution published for {sl}",
                   f"before p50={bf['p50']} >0.6={bf['share_gt_0.6']} n={bf['n']}; after p50={af['p50']} max={af['max']} n={af['n']}")

    env = dict(os.environ, TRE_BENCHMARK_DIR=str(b))
    env.pop(sealed.ENV, None)
    p = subprocess.run([sys.executable, "-m", "pytest", "tests/test_benchmark_leakage.py", "-q", "-rs"], cwd=REPO_ROOT,
                       capture_output=True, text=True, env=env)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    report(p.returncode == 0 and "skipped" not in last, "leakage tests pass against the built data", last)

    if a.skip_rebuild:
        report(False, "byte-identical second build", "skipped (--skip-rebuild)")
    else:
        with tempfile.TemporaryDirectory(prefix="b2_rebuild_") as td:
            cmd = [sys.executable, str(REPO_ROOT / "benchmarks_v2" / "build" / "build_collection.py"), "--version", a.version,
                   "--out", td, "--seed", str(m["seed"]), "--build-date", m["build_date"],
                   "--t0-narratives", str(a.out / "inputs" / "t0_narratives")]
            r = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
            nb = Path(td) / a.version
            diffs = []
            if r.returncode != 0:
                diffs.append("rebuild failed: " + (r.stderr.strip().splitlines() or [""])[-1])
            else:
                fa = sorted(x.relative_to(b).as_posix() for x in b.rglob("*") if x.is_file())
                fb = sorted(x.relative_to(nb).as_posix() for x in nb.rglob("*") if x.is_file())
                if fa != fb:
                    diffs.append("file lists differ")
                diffs += [rel for rel in fa if rel in fb and sha256_file(b / rel) != sha256_file(nb / rel)]
            sealed.unprotect_tree(Path(td))
            report(not diffs, "byte-identical second build (same inputs and seed)",
                   ", ".join(diffs) or f"{len(m['files']) + 1} files identical")

    # sealed protection
    test_ids = {q["qid"] for q in sq}
    ok = all(q["split"] == "test" for q in sq) and not any(q["split"] == "test" for q in oq)
    leaks = 0
    for x in b.rglob("*"):
        if x.is_file() and sealed.SEALED_DIR not in x.relative_to(b).parts and x.suffix in (".json", ".jsonl"):
            t = x.read_text(encoding="utf-8")
            leaks += sum(1 for qid in test_ids if f'"{qid}"' in t)
    ro = all(sealed.is_read_only(x) for x in (b / sealed.SEALED_DIR).iterdir())
    os.environ.pop(sealed.ENV, None)
    try:
        sealed.open_sealed(b)
        guard = False
    except sealed.SealedAccessError:
        guard = True
    gi = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    ignored = bool(re.search(r"^data/benchmark/\s*$", gi, re.M))
    tracked = subprocess.run(["git", "ls-files", "data/benchmark"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip()
    report(ok and leaks == 0 and ro and guard and ignored and not tracked, "sealed protection in place",
           f"test split only under sealed/ ({len(sq)} queries), {leaks} test qids outside, read-only={ro}, "
           f"guard refuses without {sealed.ENV}={sealed.VALUE}: {guard}, data/benchmark/ gitignored={ignored}, tracked files={bool(tracked)}")

    # dataset card
    if CARD.is_file():
        card = CARD.read_text(encoding="utf-8")
        missing = [rel for rel, f in m["files"].items() if rel != "build_report.json" and f["sha256"] not in card]
        cnt_ok = all(f"| {sl} |" in card for sl in SLICES)
        report(not missing and cnt_ok and m["build_date"] in card, "dataset card matches the build (hashes, slices)",
               ", ".join(missing) or str(CARD.relative_to(REPO_ROOT)))
    else:
        report(False, "dataset card present", str(CARD))

    ok, detail = stdlib_only()
    report(ok, "builder uses the standard library only", detail)
    tracked = set(subprocess.run(["git", "ls-files", "benchmarks_v2", "tests"], cwd=REPO_ROOT, capture_output=True,
                                 text=True).stdout.split())
    need_files = [p.relative_to(REPO_ROOT).as_posix() for p in sorted((REPO_ROOT / "benchmarks_v2" / "build").glob("*.py"))]
    need_files += ["tests/test_benchmark_leakage.py", "tests/test_benchmark_build.py"]
    untracked = [f for f in need_files if f not in tracked]
    report(not untracked, "builder, tests and card are committed (not git-ignored)",
           ", ".join(untracked) or f"{len(need_files)} files tracked")
    if not a.skip_repo_tests:
        p = subprocess.run([sys.executable, "-m", "pytest", "verify", "tests", "-q"], cwd=REPO_ROOT,
                           capture_output=True, text=True, env={k: v for k, v in os.environ.items()
                                                                if k not in ("TRE_BENCHMARK_DIR", sealed.ENV)})
        last = (p.stdout.strip().splitlines() or [""])[-1]
        report(p.returncode == 0, "python -m pytest verify tests -q", last)
    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
