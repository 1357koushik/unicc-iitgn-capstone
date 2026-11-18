"""Model comparison table and decisions from B4 harness reports (plan 4.5 items 2-3).

    python -m threat_retrieval_engine.dense.compare --reports results/dense/reports --out results/dense/comparison

Reads the harness report JSONs ``<variant>-<split>.json`` of the comparison variants (``cmp_<model>``,
``cmp_v1``, ``cmp_v1_v1query``) and the paired-comparison reports written by
``scripts/dense/score_compare.sh``:

* ``vsbest/<variant>-dev.json``: each model's dev run scored against the best model's (``--compare``), with the
  non-inferiority test (margin 1 point, one-sided alpha 0.025) on Recall@50 and nDCG@10;
* ``vsv1/<winner>-<split>.json``: the winner against each v1 baseline (all answerable slices and, as
  ``...-cveonly``, without T9, which v1 cannot answer because it has no ATT&CK vectors).

Rules (decided before the numbers were read):

1. Best model: the highest dev macro (Recall@50 + nDCG@10) / 2.
2. Winner: among the models non-inferior to the best on both dev macro metrics (paired stratified bootstrap,
   margin 0.01), the one with the lowest measured query-encoding p50 on the server (encode latency breaks ties
   only; plan 0 rule 1). If no other model is non-inferior, the best model wins.
3. Full re-embed (C3b) is needed when the winner is significantly better than the stronger v1 baseline on dev:
   the 95% interval of the paired macro difference is above zero for Recall@50 or nDCG@10, and neither metric is
   significantly worse.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import COMPARED

METRICS = ("recall@50", "ndcg@10")
EXTRA = ("recall@100", "recall@10", "success@1", "mrr@10")
VARIANTS = tuple(f"cmp_{m}" for m in COMPARED) + ("cmp_v1", "cmp_v1_v1query")


def _load(p: Path) -> dict | None:
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def _cell(m: dict | None) -> dict | None:
    if not m or m.get("value") is None:
        return None
    return {"value": m["value"], "ci": m.get("ci"), "n": m.get("n")}


def table(reports: Path, split: str) -> dict:
    out = {}
    for v in VARIANTS:
        r = _load(reports / f"{v}-{split}.json")
        if r is None:
            continue
        if r["split"] != split:
            raise ValueError(f"{v}-{split}.json is for split {r['split']}")
        row = {"slices": {}, "macro": {}, "n_evaluated": r["n_evaluated"],
               "unjudged_top10": r["populations"]["overall"]["unjudged"]["unjudged_positions"],
               "service_info": (r["variant"].get("server") or {}).get("service_info"),
               "latency_ms": r["populations"]["overall"].get("latency_ms")}
        for sl, pop in sorted(r["populations"].items()):
            if not (sl.startswith("T") and len(sl) == 2) or pop.get("n_answerable", 0) == 0:
                continue
            row["slices"][sl] = {m: _cell(pop["metrics"].get(m)) for m in METRICS + EXTRA}
        row["macro"] = {m: _cell(r["macro"].get(m)) for m in METRICS + EXTRA}
        out[v] = row
    return out


def macro_mean(row: dict) -> float:
    return (row["macro"]["recall@50"]["value"] + row["macro"]["ndcg@10"]["value"]) / 2


def decide(dev: dict, reports: Path, encode_latency: dict[str, float]) -> dict:
    models = [f"cmp_{m}" for m in COMPARED if f"cmp_{m}" in dev]
    if len(models) != len(COMPARED):
        raise ValueError(f"dev reports missing for {sorted(set(f'cmp_{m}' for m in COMPARED) - set(models))}")
    ranked = sorted(models, key=lambda v: -macro_mean(dev[v]))
    best = ranked[0]
    ni = {}
    for v in models:
        if v == best:
            continue
        r = _load(reports / "vsbest" / f"{v}-dev.json")
        if r is None:
            raise ValueError(f"missing paired comparison {v} vs {best}")
        cmp = r["comparisons"][0]
        if cmp["reference_variant"] != best or r["variant"]["name"] != v or r["split"] != "dev":
            raise ValueError(f"{v}: comparison is {cmp['direction']} on {r['split']}, expected {v} - {best} on dev")
        ni[v] = {m: cmp["macro"][m] for m in METRICS}
    tied = [best] + [v for v in models if v != best and all((ni[v][m].get("noninferiority") or {}).get("noninferior")
                                                         for m in METRICS)]
    lat = {v: encode_latency.get(v.removeprefix("cmp_")) for v in tied}
    if len(tied) > 1 and any(x is None for x in lat.values()):
        raise ValueError(f"encode latency missing for tied models {lat}")
    winner = min(tied, key=lambda v: (lat[v] if len(tied) > 1 else 0.0, ranked.index(v)))
    return {"ranking_by_dev_macro_mean": [{"variant": v, "macro_mean": macro_mean(dev[v]),
                                           "recall@50": dev[v]["macro"]["recall@50"]["value"],
                                           "ndcg@10": dev[v]["macro"]["ndcg@10"]["value"]} for v in ranked],
            "best": best, "vs_best": ni, "non_inferior_to_best": tied, "encode_latency_p50_ms": lat,
            "winner": winner, "winner_model": winner.removeprefix("cmp_")}


def reembed_decision(winner: str, reports: Path) -> dict:
    out = {}
    for base in ("cmp_v1", "cmp_v1_v1query"):
        for tag in ("", "-cveonly"):
            r = _load(reports / "vsv1" / f"{winner}-vs-{base}{tag}-dev.json")
            if r is None:
                raise ValueError(f"missing vsv1/{winner}-vs-{base}{tag}-dev.json")
            c = r["comparisons"][0]
            if c["reference_variant"] != base or r["variant"]["name"] != winner or r["split"] != "dev":
                raise ValueError(f"vsv1/{winner}-vs-{base}{tag}: comparison is {c['direction']} on {r['split']}")
            out[f"{base}{tag}"] = {"macro": {m: c["macro"][m] for m in METRICS + EXTRA if m in c["macro"]},
                                   "slices": {sl: {m: c["populations"][sl][m] for m in METRICS}
                                              for sl in sorted(c["populations"]) if sl.startswith("T") and len(sl) == 2
                                              and all(c["populations"][sl].get(m) for m in METRICS)}}
    # the stronger baseline: higher dev macro mean of the two baselines (from the full-slice comparison means)
    def base_mean(b):
        mm = out[b]["macro"]
        return (mm["recall@50"]["mean_b"] + mm["ndcg@10"]["mean_b"]) / 2
    stronger = max(("cmp_v1", "cmp_v1_v1query"), key=base_mean)
    mm = out[stronger]["macro"]
    better = [m for m in METRICS if mm[m]["ci"][0] > 0]
    worse = [m for m in METRICS if mm[m]["ci"][1] < 0]
    return {"stronger_v1_baseline": stronger, "significantly_better_on": better, "significantly_worse_on": worse,
            "c3b_needed": bool(better) and not worse, "comparisons": out}


def render(dev: dict, train: dict, dec: dict | None, re: dict | None) -> str:
    def f(c):
        if not c:
            return "n/a"
        lo, hi = (c.get("ci") or [None, None])
        return f"{c['value']:.3f} [{lo:.3f}, {hi:.3f}]" if lo is not None else f"{c['value']:.3f}"
    lines = ["# C3 embedding-model comparison (reduced corpus)", ""]
    for split, tab in (("dev", dev), ("train", train)):
        if not tab:
            continue
        slices = sorted({s for r in tab.values() for s in r["slices"]})
        for m in METRICS:
            lines += [f"## {split}: {m} (95% bootstrap interval)", "",
                      "| variant | " + " | ".join(slices) + " | macro |", "|---" * (len(slices) + 2) + "|"]
            for v, r in tab.items():
                lines.append(f"| {v} | " + " | ".join(f((r['slices'].get(s) or {}).get(m)) for s in slices)
                             + f" | {f(r['macro'][m])} |")
            lines.append("")
    if dec:
        lines += ["## Decision", "", f"Best by dev macro mean of Recall@50 and nDCG@10: `{dec['best']}`; non-inferior "
                  f"to it (margin 0.01, both metrics): {', '.join(dec['non_inferior_to_best'])}; winner "
                  f"`{dec['winner']}`.", ""]
    if re:
        lines += [f"C3b (full re-embed) needed: **{re['c3b_needed']}** (stronger v1 baseline `{re['stronger_v1_baseline']}`; "
                  f"significantly better on {re['significantly_better_on'] or 'none'}, worse on "
                  f"{re['significantly_worse_on'] or 'none'}).", ""]
        for b, c in re["comparisons"].items():
            lines.append(f"- vs `{b}`: " + "; ".join(
                f"{m} {c['macro'][m]['diff']:+.3f} [{c['macro'][m]['ci'][0]:+.3f}, {c['macro'][m]['ci'][1]:+.3f}]"
                for m in METRICS))
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reports", type=Path, required=True)
    ap.add_argument("--latency", type=Path, help="encode latency JSON {model: p50_ms} measured on the server")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    dev, train = table(a.reports, "dev"), table(a.reports, "train")
    lat = json.loads(a.latency.read_text(encoding="utf-8")) if a.latency and a.latency.is_file() else {}
    dec = re = None
    if all(f"cmp_{m}" in dev for m in COMPARED):
        dec = decide(dev, a.reports, lat)
        re = reembed_decision(dec["winner"], a.reports)
    res = {"dev": dev, "train": train, "decision": dec, "reembed": re}
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "comparison.json").write_text(json.dumps(res, indent=1), encoding="utf-8", newline="\n")
    (a.out / "comparison.md").write_text(render(dev, train, dec, re), encoding="utf-8", newline="\n")
    print(render(dev, train, dec, re))
    return 0


if __name__ == "__main__":
    sys.exit(main())
