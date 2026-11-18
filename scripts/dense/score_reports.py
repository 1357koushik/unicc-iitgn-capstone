"""Score C3 run files with the B4 harness (``benchmarks_v2.eval score``) into results/dense/reports.

    python scripts/dense/score_reports.py <variant> <split> [--compare <variant> ...] [--slices T0,..]
        [--ni-metrics recall@50,ndcg@10] [--name <report name>] [--subdir vsbest]

Run files are read from results/dense/runs/<variant>-<split>.jsonl (copied from the server), except the
frozen v1 runs, which are read from results/eval/runs (B6). Reports are provisional until judging round 1
(--allow-unjudged), like every report before B3.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
DATA = Path(__import__("os").environ.get("TRE_BENCHMARK_DIR", ROOT / "data" / "benchmark" / "v2.0"))


def run_path(variant: str, split: str) -> Path:
    for d in (ROOT / "results/dense/runs", ROOT / "results/eval/runs"):
        p = d / f"{variant}-{split}.jsonl"
        if p.is_file():
            return p
    raise SystemExit(f"no run file for {variant} {split}")


def main(argv=None) -> int:
    from benchmarks_v2.eval.cli import main as harness
    ap = argparse.ArgumentParser()
    ap.add_argument("variant")
    ap.add_argument("split", choices=["train", "dev"])
    ap.add_argument("--compare", nargs="*", default=[])
    ap.add_argument("--slices")
    ap.add_argument("--ni-metrics", default="recall@50,ndcg@10")
    ap.add_argument("--name")
    ap.add_argument("--subdir", default="")
    a = ap.parse_args(argv)
    out = ROOT / "results/dense/reports" / a.subdir
    out.mkdir(parents=True, exist_ok=True)
    name = a.name or f"{a.variant}-{a.split}"
    args = ["score", "--run", str(run_path(a.variant, a.split)), "--dataset", str(DATA), "--split", a.split,
            "--allow-unjudged", "--ni-metrics", a.ni_metrics, "--json-out", str(out / f"{name}.json"),
            "--md-out", str(out / f"{name}.md")]
    if a.compare:
        args += ["--compare", *[str(run_path(v, a.split)) for v in a.compare]]
    if a.slices:
        args += ["--slices", a.slices]
    return harness(args)


if __name__ == "__main__":
    sys.exit(main())
