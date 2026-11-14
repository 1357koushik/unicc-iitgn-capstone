"""Build the retrieval benchmark collection (work package B2, plan sections 6.1-6.4).

    python benchmarks_v2/build/build_collection.py --version v2.0 --out "<repo>/data/benchmark"

Writes <out>/<version>/{queries.jsonl, qrels.jsonl, equivalence.jsonl, manifest.json, build_report.json,
sealed/{queries.jsonl, qrels.jsonl, README.txt}} per docs/benchmark_format.md. Same inputs and seed give
byte-identical files. Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import shutil
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "benchmarks_v2.build"

from benchmarks_v2.build import noise, sealed, slice_products, slice_t0, slice_t2, slice_t9, slices_ids, slices_rules  # noqa: E402
from benchmarks_v2.build.attack import load_attack  # noqa: E402
from benchmarks_v2.build.common import (BUILDER_VERSION, DEFAULT_SEED, REPO_ROOT, SLICES, SPLITS,  # noqa: E402
                                        TARGET_SIZES, default_benchmark_dir, default_feeds_dir,
                                        default_sources_dir, git_head, sha256_file, write_json, write_jsonl)
from benchmarks_v2.build.equivalence import EquivalenceMap, build_equivalence  # noqa: E402
from benchmarks_v2.build.gate import Gate  # noqa: E402
from benchmarks_v2.build.leakage import TextIndex, attack_sentence_refs, expansion_refs  # noqa: E402
from benchmarks_v2.build.model import assign_splits, histogram, summarize, temporal_flag  # noqa: E402
from benchmarks_v2.build.sources import Sources  # noqa: E402
from benchmarks_v2.build.universe import cvelist_version, env_workers, load_universe  # noqa: E402

SHORTFALL_REASONS = {
    "T0": "T0 narratives are written by package B2a (not yet delivered); only Team 3's own cases are in this "
          "build. Re-run the build after B2a writes <benchmark>/inputs/t0_narratives/*.jsonl.",
    "T2": "names are kept only when corroborated by the CVE's own NVD/CVE List text or references or by a "
          "query-side source; uncorroborated names and template variants that exceed the 60% overlap rule or "
          "collide with an expansion-source record are dropped (quality over count).",
    "T6": "T6 is derived from dev/test T0, T2 and T3 parents; T0 is small until B2a lands.",
}


def builder_commit() -> str | None:
    """Last commit that changed the builder (stable across documentation-only commits); HEAD as fallback."""
    import subprocess
    try:
        r = subprocess.run(["git", "log", "-1", "--format=%H", "--", "benchmarks_v2/build"], cwd=REPO_ROOT,
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return git_head(REPO_ROOT)


def code_digest() -> str:
    h = hashlib.sha256()
    for p in sorted((REPO_ROOT / "benchmarks_v2" / "build").glob("*.py")):
        h.update(p.name.encode() + b"\0" + p.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def default_build_date(srcs: Sources, feeds: Path) -> dt.date:
    dates = []
    for n in srcs.available():
        s = srcs._load(n)
        if s is not None:
            try:
                dates.append(dt.date.fromisoformat(s.date))
            except ValueError:
                pass
    for pat in ("cisa_kev-*.csv", "epss_scores-*.csv"):
        for p in feeds.glob(pat):
            try:
                dates.append(dt.date.fromisoformat(p.stem.split("-", 1)[1][:10]))
            except ValueError:
                pass
    return max(dates) if dates else dt.date(2026, 1, 1)


def log(msg: str, t0: float) -> None:
    print(f"[{time.time() - t0:7.1f}s] {msg}", flush=True)


def build(args) -> Path:
    t0 = time.time()
    seed = args.seed
    srcs = Sources(args.sources)
    feeds = Path(args.feeds)
    build_date = dt.date.fromisoformat(args.build_date) if args.build_date else default_build_date(srcs, feeds)
    log(f"build date {build_date}, seed {seed}", t0)
    u = load_universe(feeds, want_refs=slice_t2.want_ref_ids(), workers=args.workers)
    log(f"universe: {len(u.nvd)} NVD, {len(u.kev)} KEV, {len(u.epss)} EPSS", t0)
    kb = load_attack(srcs)
    log(f"ATT&CK: {len(kb.objects)} active objects, {len(kb.rels)} relationships", t0)
    eq_sets, eq_stats = build_equivalence(u)
    eqmap = EquivalenceMap(eq_sets, u)
    log(f"equivalence sets: {len(eq_sets)}", t0)
    exp_refs, exp_used = expansion_refs(srcs)
    expansion = TextIndex(exp_refs)
    att_idx = TextIndex(attack_sentence_refs(kb)) if kb.available else None
    log(f"expansion index: {len(expansion)} texts; ATT&CK sentences: {len(att_idx) if att_idx else 0}", t0)
    gate = Gate(u, eqmap, expansion, att_idx)
    stats: dict = {}
    items = []

    t0_items, stats["T0_team3"] = slice_t0.build_team3(u, kb, gate, Path(args.team3_file))
    b2a_items, stats["T0_b2a"], b2a_inputs = slice_t0.build_b2a(u, kb, srcs, gate, args.t0_narratives)
    items += t0_items + b2a_items
    log(f"T0: {len(t0_items)} Team 3 + {len(b2a_items)} B2a", t0)
    for name, fn in (
        ("T1", lambda: slices_ids.build_t1(u, gate, seed)),
        ("T2", lambda: slice_t2.build_t2(u, srcs, gate, seed, TARGET_SIZES["T2"])),
        ("T3", lambda: slices_rules.build_t3(srcs, gate, seed, TARGET_SIZES["T3"])),
        ("T4", lambda: slices_rules.build_t4(srcs, gate, seed, TARGET_SIZES["T4"])),
    ):
        got, stats[name] = fn()
        items += got
        log(f"{name}: {len(got)}", t0)
    pidx = slice_products.ProductIndex(u)
    for name, fn in (
        ("T5", lambda: slice_products.build_t5(u, pidx, gate, seed, TARGET_SIZES["T5"])),
        ("T8", lambda: slice_products.build_t8(u, pidx, gate, seed, TARGET_SIZES["T8"])),
        ("T9", lambda: slice_t9.build_t9(kb, gate, seed, TARGET_SIZES["T9"])),
        ("T7", lambda: slices_ids.build_t7(u, kb, gate, seed)),
    ):
        got, stats[name] = fn()
        items += got
        log(f"{name}: {len(got)}", t0)

    for it in items:
        it.temporal_holdout = temporal_flag(it, u, build_date)
    split_stats = assign_splits(items, eqmap, seed)
    counters = {s: 0 for s in SLICES}
    for it in items:
        counters[it.slice] += 1
        it.qid = f"{it.slice}-{counters[it.slice]:04d}"
    parents = [i for i in items if i.slice in ("T0", "T2", "T3")]
    t6, stats["T6"] = noise.build_t6(parents, gate, seed, TARGET_SIZES["T6"])
    for it in t6:
        counters["T6"] += 1
        it.qid = f"T6-{counters['T6']:04d}"
    items += t6
    log(f"T6: {len(t6)}", t0)
    items.sort(key=lambda i: (SLICES.index(i.slice), i.qid))
    # Consistency: re-run grouping over everything (T6 included) and confirm no split moved.
    before = {i.qid: i.split for i in items}
    check = assign_splits_check(items, eqmap)
    if check:
        raise RuntimeError(f"split grouping violated for {len(check)} groups")

    # ------------------------------------------------------------------ write
    out_root = Path(args.out)
    final = out_root / args.version
    tmp = out_root / f".{args.version}.building"
    if tmp.exists():
        sealed.unprotect_tree(tmp)
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    open_q = [i for i in items if i.split != "test"]
    test_q = [i for i in items if i.split == "test"]
    files = {}

    def w(rel: str, rows: list[dict]) -> None:
        n = write_jsonl(tmp / rel, rows)
        files[rel] = {"count": n}

    w("queries.jsonl", [i.to_query() for i in open_q])
    w("qrels.jsonl", [r for i in open_q for r in i.to_qrels()])
    w("equivalence.jsonl", eq_sets)
    w(f"{sealed.SEALED_DIR}/queries.jsonl", [i.to_query() for i in test_q])
    w(f"{sealed.SEALED_DIR}/qrels.jsonl", [r for i in test_q for r in i.to_qrels()])
    (tmp / sealed.SEALED_DIR / "README.txt").write_bytes(sealed.README.encode("utf-8"))
    files[f"{sealed.SEALED_DIR}/README.txt"] = {"count": None}

    counts = summarize(items)
    report = make_report(items, stats, gate, eq_stats, split_stats, counts, build_date)
    write_json(tmp / "build_report.json", report)
    files["build_report.json"] = {"count": None}
    for rel in files:
        p = tmp / rel
        files[rel]["sha256"] = sha256_file(p)

    inputs = list(u.inputs)
    reads = sorted(u.cvelist_reads.items())
    inputs.append({"name": "cvelistV5", "commit": cvelist_version(feeds), "files_read": len(reads),
                   "files_read_sha256": hashlib.sha256("".join(f"{a} {b}\n" for a, b in reads).encode()).hexdigest()})
    for n in sorted(srcs.used):
        inputs.append(srcs.used[n].input_entry())
    t3f = Path(args.team3_file)
    if t3f.is_file():
        inputs.append({"name": "team3/benchmark_data.py", "sha256": sha256_file(t3f)})
    inputs += b2a_inputs
    manifest = {
        "version": args.version, "build_date": build_date.isoformat(), "seed": seed,
        "format": "docs/benchmark_format.md",
        "builder": {"version": BUILDER_VERSION, "commit": builder_commit(), "code_sha256": code_digest(),
                    "entry_point": "benchmarks_v2/build/build_collection.py"},
        "inputs": inputs,
        "files": files,
        "counts": counts,
        "totals": {"queries": len(items), "qrels": sum(len(i.qrels) for i in items), "equivalence_sets": len(eq_sets)},
        "sealed": {"dir": sealed.SEALED_DIR, "env": f"{sealed.ENV}={sealed.VALUE}",
                   "test_queries": len(test_q)},
    }
    write_json(tmp / "manifest.json", manifest)
    sealed.protect(tmp)
    if final.exists():
        sealed.unprotect_tree(final)
        shutil.rmtree(final)
    tmp.rename(final)
    sealed.protect(final)
    log(f"wrote {final} ({len(items)} queries, {len(test_q)} sealed)", t0)
    for sl in SLICES:
        c = counts.get(sl, {s: 0 for s in SPLITS})
        print(f"  {sl}: " + "  ".join(f"{s}={c[s]}" for s in SPLITS) + f"  total={sum(c.values())}/{TARGET_SIZES[sl]}")
    _ = before
    return final


def assign_splits_check(items, eqmap) -> list:
    """Return groups whose members disagree on split (must be empty)."""
    from benchmarks_v2.build.model import group_keys
    owner: dict[str, str] = {}
    bad = []
    # union-find over keys
    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for it in items:
        ks = [f"q:{it.qid}", f"parent:{it.qid}"] + sorted(group_keys(it, eqmap))
        for k in ks[1:]:
            ra, rb = find(ks[0]), find(k)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
    for it in items:
        root = find(f"q:{it.qid}")
        if root in owner and owner[root] != it.split:
            bad.append(root)
        owner.setdefault(root, it.split)
    return sorted(set(bad))


def make_report(items, stats, gate, eq_stats, split_stats, counts, build_date) -> dict:
    per_slice = {}
    for sl in SLICES:
        its = [i for i in items if i.slice == sl]
        n = len(its)
        entry = {"target": TARGET_SIZES[sl], "actual": n, "by_split": counts.get(sl, {s: 0 for s in SPLITS}),
                 "temporal_holdout": sum(1 for i in its if i.temporal_holdout),
                 "qrels": sum(len(i.qrels) for i in its),
                 "grade2_qrels": sum(1 for i in its for q in i.qrels if q["grade"] == 2)}
        if n < TARGET_SIZES[sl]:
            entry["shortfall"] = TARGET_SIZES[sl] - n
            entry["shortfall_reason"] = SHORTFALL_REASONS.get(sl) or _auto_reason(sl, stats, gate)
        ex = sl in ("T1", "T7", "T9")
        entry["overlap"] = {"exempt": ex,
                            "rule": "drop (query,target) when >60% of query content tokens occur in the target's corpus text"}
        if not ex:
            entry["overlap"]["before_filter"] = histogram(gate.overlap.before.get(sl, []))
            entry["overlap"]["after_filter"] = histogram([i.max_overlap or 0.0 for i in its])
            entry["overlap"]["pairs_dropped"] = gate.overlap.dropped_pairs.get(sl, 0)
            entry["overlap"]["queries_dropped"] = gate.overlap.dropped_queries.get(sl, 0)
        entry["gate"] = {"examined": gate.examined.get(sl, 0), "rejected": dict(sorted(gate.rejects.get(sl, {}).items()))}
        per_slice[sl] = entry
    return {"build_date": build_date.isoformat(), "slices": per_slice, "slice_stats": stats,
            "equivalence": eq_stats, "splits": split_stats}


def _auto_reason(sl, stats, gate) -> str:
    rej = dict(gate.rejects.get(sl, {}))
    return f"candidate pool exhausted under the quality filters; gate rejections {rej}; builder stats {stats.get(sl)}"


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default="v2.0")
    ap.add_argument("--out", type=Path, default=default_benchmark_dir())
    ap.add_argument("--sources", type=Path, default=default_sources_dir())
    ap.add_argument("--feeds", type=Path, default=default_feeds_dir())
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--build-date", default=None, help="YYYY-MM-DD; default: newest input snapshot date")
    ap.add_argument("--t0-narratives", type=Path, default=None,
                    help="B2a narrative directory; default <out>/inputs/t0_narratives")
    ap.add_argument("--team3-file", type=Path, default=slice_t0.TEAM3_FILE)
    ap.add_argument("--workers", type=int, default=env_workers())
    a = ap.parse_args(argv)
    if a.t0_narratives is None:
        a.t0_narratives = Path(a.out) / "inputs" / "t0_narratives"
    return a


def main(argv=None) -> int:
    build(parse_args(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
