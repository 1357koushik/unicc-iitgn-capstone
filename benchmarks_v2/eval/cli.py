"""Command line: ``python -m benchmarks_v2.eval <command>``.

  validate  check a dataset directory (or explicit files) against the data contract
  run       send queries to a registered variant and append to a resumable run file
  score     score a run (optionally against comparison runs) and write JSON + Markdown reports
  pool      export (qid, doc_id) pairs in the top 10 of runs that still need a judgement (for B3)
  report    re-render the Markdown of a report JSON
  gates     evaluate the release gates (gates.yaml) on a report JSON; exit 1 if any gate fails

Exit codes: 0 success, 1 gates failed, 2 invalid input, 3 run stopped (service unreachable or response
mapping error; resumable), 4 refused because the sealed test split was requested.

Only ``validate``, ``run`` and the modules they import are needed on the server (standard library + PyYAML);
everything else imports NumPy lazily.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import sealed
from .schema import SLICES, ValidationError

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS = REPO_ROOT / "results" / "eval"


class UsageError(ValueError):
    pass


def default_dataset() -> Path | None:
    env = os.environ.get("TRE_BENCHMARK_DIR")
    if env:
        return Path(env)
    base = REPO_ROOT / "data" / "benchmark"
    if base.is_dir():
        versions = sorted(p for p in base.iterdir() if (p / "queries.jsonl").exists())
        if versions:
            return versions[-1]
    return None


def parse_slices(s: str | None) -> list[str] | None:
    if not s:
        return None
    out = [x.strip() for x in s.split(",") if x.strip()]
    bad = [x for x in out if x not in SLICES]
    if bad:
        raise UsageError(f"unknown slice(s) {bad}; use T0..T9")
    return out


def add_data_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dataset", type=Path, help="benchmark version directory (default: $TRE_BENCHMARK_DIR or the "
                                                "latest data/benchmark/<version>)")
    p.add_argument("--queries", type=Path, help="explicit queries.jsonl (instead of --dataset)")
    p.add_argument("--qrels", type=Path, help="explicit qrels.jsonl")
    p.add_argument("--equivalence", type=Path, help="explicit equivalence.jsonl")
    p.add_argument("--split", choices=["train", "dev", "test"])
    p.add_argument("--slices", help="comma-separated slices, e.g. T1,T3")


def load_data(args, split):
    from .schema import load_dataset
    if args.queries is not None:
        if args.qrels is None:
            raise UsageError("--queries needs --qrels for this command")
        return load_dataset(None, split, queries_path=args.queries, qrels_path=args.qrels,
                            equivalence_path=args.equivalence)
    root = args.dataset or default_dataset()
    if root is None:
        raise UsageError("no dataset; pass --dataset data/benchmark/<version> or explicit files")
    return load_dataset(root, split, qrels_path=args.qrels, equivalence_path=args.equivalence)


# --------------------------------------------------------------------------------------------- commands
def cmd_validate(args) -> int:
    sealed.check_split(args.split, "validating the test split")
    ds = load_data(args, args.split)
    qs = ds.select(args.split, parse_slices(args.slices))
    by = {}
    for q in qs:
        by.setdefault((q.slice, q.split), 0)
        by[(q.slice, q.split)] += 1
    print(f"OK: {len(qs)} queries, {sum(len(v) for v in ds.qrels.values())} judgements, "
          f"{len(ds.equivalence.members)} equivalence units")
    for (sl, sp), n in sorted(by.items()):
        print(f"  {sl} {sp}: {n}")
    for w in ds.info["warnings"]:
        print(f"  warning: {w}")
    return 0


def cmd_run(args) -> int:
    from .adapters import make_adapter
    from .registry import get_variant
    from .runner import run_variant
    from .schema import load_queries
    sealed.check_split(args.split, "running the test split")
    slices = parse_slices(args.slices)
    if args.queries is not None:
        qs = load_queries(args.queries)
        sealed.check_query_splits({q.split for q in qs}, f"running {args.queries} (has test-split queries)")
        qs = [q for q in qs if (args.split is None or q.split == args.split) and (slices is None or q.slice in slices)]
        split_name = args.split or "-".join(sorted({q.split for q in qs})) or "none"
    else:
        if args.split is None:
            raise UsageError("run needs --split (or an explicit --queries file)")
        root = args.dataset or default_dataset()
        if root is None:
            raise UsageError("no dataset; pass --dataset or --queries")
        base = Path(root) / ("sealed" if args.split == "test" else "")
        qs = [q for q in load_queries(base / "queries.jsonl")
              if q.split == args.split and (slices is None or q.slice in slices)]
        split_name = args.split
    if not qs:
        raise UsageError("no queries selected")
    cfg = get_variant(args.variant, args.registry)
    adapter = make_adapter(args.variant, cfg, base_url=args.base_url, timeout_s=args.timeout, runfile=args.runfile)
    out = args.out or (DEFAULT_RESULTS / "runs" / f"{args.variant}-{split_name}.jsonl")
    print(f"[run] variant {args.variant} ({cfg['adapter']}), {len(qs)} queries, out {out}", flush=True)
    session = run_variant(args.variant, adapter, qs, Path(out), concurrency=args.concurrency,
                          max_queries=args.max_queries, harness_commit=args.harness_commit,
                          progress=lambda m: print(m, flush=True), pause_after_error_s=args.pause_after_error)
    print(f"[run] {session['status']}: sent {session['sent']}, errors {session['errors']}, "
          f"{session['already_done'] + session['sent']}/{len(qs)} done", flush=True)
    return 0


def settings_from_args(args):
    from .metrics import Settings
    s = Settings()
    s.bootstrap = args.bootstrap
    s.seed = args.seed
    s.min_grade = args.min_grade
    s.ece_bins = args.ece_bins
    s.calib_depth = args.calib_depth
    s.ni_margin = args.noninferiority_margin
    s.ni_alpha = args.ni_alpha
    s.ni_metrics = tuple(x.strip() for x in args.ni_metrics.split(",") if x.strip())
    s.false_accept_min_tier = args.false_accept_min_tier
    return s


def infer_split(ds, run) -> str:
    splits = {ds.queries[q].split for q in run.records if q in ds.queries}
    unknown = [q for q in run.records if q not in ds.queries]
    if unknown:
        sealed.require_open(f"scoring {run.path}: {len(unknown)} qids are not in the open dataset "
                            "(test split?)")
        return "test"
    if len(splits) != 1:
        raise UsageError(f"run covers splits {sorted(splits)}; pass --split")
    return splits.pop()


def cmd_score(args) -> int:
    from .gates import evaluate_gates, load_gates
    from .report import build_report, default_paths, write_report
    from .schema import load_run
    from .scoring import score
    sealed.check_split(args.split, "scoring the test split")
    run = load_run(args.run)
    others = [load_run(p) for p in (args.compare or [])]
    split = args.split
    ds = load_data(args, split)
    if split is None:
        split = infer_split(ds, run)
        if split == "test":
            ds = load_data(args, "test")
    slices = parse_slices(args.slices)
    queries = ds.select(split, slices)
    if not queries:
        raise UsageError("no queries selected")
    s = settings_from_args(args)
    gcfg = load_gates(args.gates) if not args.no_gates else None
    analysis = score(ds, run, queries, s, pop_defs=(gcfg or {}).get("populations"),
                     parent_defs=(gcfg or {}).get("parent_pairs"), compare_runs=others,
                     allow_incomplete=args.allow_incomplete)
    unj = analysis["populations"]["overall"]["unjudged"]["unjudged_positions"]
    flags = {"allow_unjudged": args.allow_unjudged, "unjudged_positions": unj,
             "judgement_complete": unj == 0, "incomplete": bool(analysis["missing_qids"]),
             "allow_incomplete": args.allow_incomplete}
    rep = build_report(analysis, ds_info=ds.info, run=run, split=split, slices=slices, settings=s.as_dict(),
                       flags=flags)
    if gcfg is not None:
        rep["gates"] = evaluate_gates(rep, gcfg, allow_unjudged=args.allow_unjudged)
    jp, mp = (args.json_out, args.md_out) if args.json_out else default_paths(args.out_dir, run.variant, split)
    if mp is None:
        mp = Path(str(jp)).with_suffix(".md")
    Path(jp).parent.mkdir(parents=True, exist_ok=True)
    write_report(rep, Path(jp), Path(mp))
    ov = rep["populations"]["overall"]["metrics"]
    print(f"wrote {jp}\nwrote {mp}")
    print(f"overall: S@1 {ov['success@1']['value']}, nDCG@10 {ov['ndcg@10']['value']}, unjudged top-10 docs {unj}"
          + (" (allowed, report marked provisional)" if unj and args.allow_unjudged else ""))
    if rep.get("gates"):
        print(f"gates: {rep['gates']['overall']} {rep['gates']['counts']}")
    return 0


def cmd_pool(args) -> int:
    from .pool import export_pool
    from .schema import load_run
    sealed.check_split(args.split, "pooling the test split")
    runs = [load_run(p) for p in args.runs]
    ds = load_data(args, args.split)
    split = args.split
    if split is None:
        splits = {infer_split(ds, r) for r in runs}
        if len(splits) != 1:
            raise UsageError(f"runs cover different splits {sorted(splits)}")
        split = splits.pop()
        if split == "test":
            ds = load_data(args, "test")
    rows = export_pool(ds, runs, args.out, depth=args.depth)
    print(f"wrote {args.out}: {len(rows)} (qid, doc_id) pairs to judge from {len(runs)} run(s), depth {args.depth}")
    return 0


def _load_report(path: Path) -> dict:
    rep = json.loads(Path(path).read_text(encoding="utf-8"))
    sealed.check_split(rep.get("split"), f"reading report {path}")
    return rep


def cmd_report(args) -> int:
    from .report import render_markdown
    rep = _load_report(args.json)
    md = render_markdown(rep)
    out = args.md_out or Path(str(args.json)).with_suffix(".md")
    Path(out).write_text(md, encoding="utf-8")
    print(f"wrote {out}")
    if args.print:
        print(md)
    return 0


def cmd_gates(args) -> int:
    from .gates import evaluate_gates, gate_table_lines, load_gates
    rep = _load_report(args.report)
    g = evaluate_gates(rep, load_gates(args.gates), allow_unjudged=args.allow_unjudged)
    print(f"Release gates for {rep['variant']['name']} on {rep['split']}: {g['overall']}"
          + (" (PROVISIONAL: unjudged documents waived)" if g["provisional"] else ""))
    print("\n".join(gate_table_lines(g)))
    if args.out:
        Path(args.out).write_text(json.dumps(g, indent=1), encoding="utf-8")
    return 0 if g["overall"] == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m benchmarks_v2.eval", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("validate", help="validate benchmark data")
    add_data_args(p)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("run", help="run a variant over queries (resumable)")
    p.add_argument("--variant", required=True)
    p.add_argument("--registry", type=Path, help="variants.yaml (default: the one next to this module)")
    p.add_argument("--dataset", type=Path)
    p.add_argument("--queries", type=Path, help="explicit queries.jsonl (e.g. on the server)")
    p.add_argument("--split", choices=["train", "dev", "test"])
    p.add_argument("--slices")
    p.add_argument("--out", type=Path, help="run file (appended; default results/eval/runs/<variant>-<split>.jsonl)")
    p.add_argument("--base-url", help="override the variant's base_url")
    p.add_argument("--timeout", type=float, help="override the variant's timeout_s")
    p.add_argument("--runfile", help="override the runfile adapter's path")
    p.add_argument("--concurrency", type=int, default=1)
    p.add_argument("--pause-after-error", type=float, default=0.0,
                   help="seconds to wait after a recorded error before the next query (sequential runs only)")
    p.add_argument("--max-queries", type=int, help="send at most this many new queries in this session")
    p.add_argument("--harness-commit", help="commit recorded in the run metadata (default $TRE_HARNESS_COMMIT)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("score", help="score a run and write reports")
    p.add_argument("--run", required=True, type=Path)
    p.add_argument("--compare", nargs="*", type=Path, help="reference run(s) for paired comparisons (this - reference)")
    add_data_args(p)
    p.add_argument("--noninferiority-margin", type=float, default=0.01)
    p.add_argument("--ni-alpha", type=float, default=0.025, help="one-sided alpha of the non-inferiority test")
    p.add_argument("--ni-metrics", default="ndcg@10,success@1")
    p.add_argument("--bootstrap", type=int, default=10_000)
    p.add_argument("--seed", type=int, default=20261114)
    p.add_argument("--min-grade", type=int, default=2, choices=[1, 2])
    p.add_argument("--ece-bins", type=int, default=10)
    p.add_argument("--calib-depth", type=int, default=10)
    p.add_argument("--false-accept-min-tier", default="PARTIAL", choices=["WEAK", "PARTIAL", "STRONG", "EXACT"])
    p.add_argument("--allow-unjudged", action="store_true", help="do not fail gates on unjudged top-10 documents; "
                                                                "the report is marked provisional")
    p.add_argument("--allow-incomplete", action="store_true", help="score a run that lacks some selected queries")
    p.add_argument("--gates", type=Path, help="gates.yaml (default: the one next to this module)")
    p.add_argument("--no-gates", action="store_true")
    p.add_argument("--out-dir", type=Path, default=DEFAULT_RESULTS)
    p.add_argument("--json-out", type=Path)
    p.add_argument("--md-out", type=Path)
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("pool", help="export pairs that need judgement")
    p.add_argument("--runs", nargs="+", required=True, type=Path)
    add_data_args(p)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--depth", type=int, default=10)
    p.set_defaults(func=cmd_pool)

    p = sub.add_parser("report", help="re-render a report's Markdown")
    p.add_argument("--json", required=True, type=Path)
    p.add_argument("--md-out", type=Path)
    p.add_argument("--print", action="store_true")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("gates", help="evaluate release gates on a report")
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--gates", type=Path)
    p.add_argument("--allow-unjudged", action="store_true")
    p.add_argument("--out", type=Path)
    p.set_defaults(func=cmd_gates)
    return ap


def main(argv: list[str] | None = None) -> int:
    from .adapters import MappingError, TransportError
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except sealed.SealedError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    except (ValidationError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (TransportError, MappingError) as exc:
        print(f"run stopped (resumable): {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
