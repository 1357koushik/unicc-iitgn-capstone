"""Per-slice tables from C3 harness reports (results/dense/reports): metric with 95% bootstrap interval for each
variant, and the paired difference of the first variant against the others named in its report.

    python scripts/dense/summarize.py --split dev --variants v2_fused,v2_lexical,v2_dense,v1_hybrid \\
        --title "Fusion" --out results/dense/fusion-dev.md
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
METRICS = ("recall@50", "ndcg@10", "recall@100", "success@1")


def load(variant: str, split: str) -> dict:
    for d in (ROOT / "results/dense/reports", ROOT / "results/eval"):
        p = d / f"{variant}-{split}.json"
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    for p in sorted((ROOT / "results/eval").glob(f"{variant}-{split}-*.json")):
        return json.loads(p.read_text(encoding="utf-8"))
    raise SystemExit(f"no report for {variant} {split}")


def cell(m) -> str:
    if not m or m.get("value") is None:
        return "–"
    ci = m.get("ci")
    return f"{m['value']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else f"{m['value']:.3f}"


def dcell(c) -> str:
    if not c or c.get("diff") is None:
        return "–"
    lo, hi = c["ci"]
    star = "*" if lo > 0 or hi < 0 else ""
    return f"{c['diff']:+.3f} [{lo:+.3f}, {hi:+.3f}]{star}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", required=True)
    ap.add_argument("--variants", required=True)
    ap.add_argument("--metrics", default="recall@50,ndcg@10")
    ap.add_argument("--title", default="")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    vs = a.variants.split(",")
    reps = {v: load(v, a.split) for v in vs}
    first = reps[vs[0]]
    slices = [s for s in sorted(first["populations"]) if len(s) == 2 and first["populations"][s].get("n_answerable")]
    L = [f"# {a.title} ({a.split})", "",
         f"Harness reports (benchmark {first['dataset'].get('version')}, provisional: judging round 1 pending). "
         "Values with 95% bootstrap intervals; differences are paired bootstrap, `*` = interval excludes 0.", ""]
    for m in a.metrics.split(","):
        L += [f"## {m}", "", "| variant | " + " | ".join(slices) + " | macro |", "|---" * (len(slices) + 2) + "|"]
        for v in vs:
            r = reps[v]
            L.append(f"| {v} | " + " | ".join(cell(r["populations"].get(s, {}).get("metrics", {}).get(m))
                                               for s in slices) + f" | {cell(r['macro'].get(m))} |")
        for c in first.get("comparisons", []):
            L.append(f"| {c['direction']} | " + " | ".join(dcell(c["populations"].get(s, {}).get(m)) for s in slices)
                     + f" | {dcell(c['macro'].get(m))} |")
        L.append("")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
