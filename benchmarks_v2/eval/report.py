"""Report assembly (JSON) and rendering (Markdown)."""
from __future__ import annotations

import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import HARNESS_VERSION
from .gates import gate_table_lines
from .metrics import RANKING_METRICS, SCENARIO_METRICS

REPORT_SCHEMA = "tre-eval-report/1"
REPO_ROOT = Path(__file__).resolve().parents[2]


def git_info() -> dict:
    def git(*args):
        try:
            return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            return None
    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--", "benchmarks_v2")
    return {"commit": commit or None, "branch": git("rev-parse", "--abbrev-ref", "HEAD") or None,
            "harness_dirty": bool(status) if status is not None else None}


def build_report(analysis: dict, *, ds_info: dict, run, split: str, slices: list[str] | None, settings: dict,
                 flags: dict, gates: dict | None = None) -> dict:
    import numpy as np
    meta = run.meta or {}
    sessions = meta.get("sessions", [])
    server = None
    if sessions:
        last = sessions[-1]
        server = {"host": last.get("host"), "platform": last.get("platform"), "python": last.get("python"),
                  "service_info": last.get("service_info"), "load_average_start": sessions[0].get("load_average_start"),
                  "load_average_end": last.get("load_average_end"), "harness_commit_at_run": last.get("harness_commit"),
                  "sessions": len(sessions)}
    rep = {
        "schema": REPORT_SCHEMA,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness": {"version": HARNESS_VERSION, **git_info(), "python": platform.python_version(),
                    "numpy": np.__version__},
        "dataset": ds_info,
        "variant": {"name": run.variant, "config": meta.get("config"), "run_file": run.path, "run_sha256": run.sha256,
                    "run_warnings": run.warnings[:50], "n_run_warnings": len(run.warnings), "server": server},
        "split": split,
        "slices": slices,
        "settings": settings,
        "flags": flags,
        **analysis,
    }
    rep["gates"] = gates
    return rep


def default_paths(out_dir: Path, variant: str, split: str) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{variant}-{split}-{datetime.now().strftime('%Y%m%d')}"
    cand, k = stem, 1
    while (out_dir / f"{cand}.json").exists() or (out_dir / f"{cand}.md").exists():
        k += 1
        cand = f"{stem}-{k}"
    return out_dir / f"{cand}.json", out_dir / f"{cand}.md"


def write_report(rep: dict, json_path: Path, md_path: Path) -> None:
    Path(json_path).write_text(json.dumps(rep, indent=1, sort_keys=False, default=_json_default) + "\n", encoding="utf-8")
    Path(md_path).write_text(render_markdown(rep), encoding="utf-8")


def _json_default(o):
    if isinstance(o, (set, tuple)):
        return list(o)
    if hasattr(o, "item"):
        return o.item()
    raise TypeError(type(o).__name__)


# --------------------------------------------------------------------------------------------- markdown
def f3(x: Any) -> str:
    if x is None:
        return "–"
    return f"{x:.3f}"


def cell(e: dict | None) -> str:
    if not e or e.get("value") is None:
        return "–"
    s = f3(e["value"])
    if e.get("ci"):
        s += f" [{f3(e['ci'][0])}, {f3(e['ci'][1])}]"
    return s


SHORT = {"success@1": "S@1", "success@5": "S@5", "mrr@10": "MRR@10", "ndcg@10": "nDCG@10", "recall@10": "R@10",
         "recall@50": "R@50", "recall@100": "R@100", "set_recall@10": "SetR@10"}


def _order(rep: dict) -> list[str]:
    pops = rep["populations"]
    slices = [k for k, v in pops.items() if v.get("kind") == "slice"]
    rest = [k for k, v in pops.items() if v.get("kind") != "slice" and k != "overall"]
    return slices + ["overall"] + rest


def render_markdown(rep: dict) -> str:
    L: list[str] = []
    v, ds, h = rep["variant"], rep["dataset"], rep["harness"]
    L.append(f"# Evaluation report: {v['name']} on {rep['split']}")
    L.append("")
    flags = rep.get("flags", {})
    warn = []
    if flags.get("allow_unjudged") and flags.get("unjudged_positions", 0) > 0:
        warn.append(f"**PROVISIONAL: {flags['unjudged_positions']} top-10 documents are unjudged "
                    f"(--allow-unjudged).** Values count an unjudged document as giving no gain; the "
                    f"'if unjudged relevant' column shows the other extreme.")
    if flags.get("incomplete"):
        warn.append(f"**INCOMPLETE RUN: {len(rep.get('missing_qids', []))} selected queries have no record.**")
    if flags.get("unjudged_positions", 0) > 0 and not flags.get("allow_unjudged"):
        warn.append(f"**{flags['unjudged_positions']} top-10 documents are unjudged; gate evaluation fails.**")
    L += [w + "\n" for w in warn]
    L.append("| Item | Value |")
    L.append("|---|---|")
    srv = v.get("server") or {}
    items = [
        ("Created (UTC)", rep["created_at"]),
        ("Harness", f"{h.get('version')} commit `{h.get('commit')}`" + (" (benchmarks_v2 modified)" if h.get("harness_dirty") else "")),
        ("Dataset", f"version {ds.get('version')} at `{ds.get('root')}`"),
        ("Manifest sha256", f"`{ds.get('manifest_sha256')}`" + (" (files verified)" if ds.get("manifest_verified") else " (files not verified against manifest)")),
        ("Query file sha256", f"`{(ds.get('files', {}).get('queries') or {}).get('sha256')}`"),
        ("Qrels file sha256", f"`{(ds.get('files', {}).get('qrels') or {}).get('sha256')}`"),
        ("Run file", f"`{v['run_file']}` sha256 `{v['run_sha256']}`"),
        ("Variant config", f"`{json.dumps(v.get('config'), sort_keys=True)}`" if v.get("config") else "–"),
        ("Server", f"{srv.get('host')} ({srv.get('platform')}), load {srv.get('load_average_start')} -> {srv.get('load_average_end')}" if srv else "–"),
        ("Service health", f"`{json.dumps(srv.get('service_info'), sort_keys=True)[:400]}`" if srv.get("service_info") else "–"),
        ("Split / slices", f"{rep['split']} / {', '.join(rep['slices']) if rep.get('slices') else 'all'}"),
        ("Queries", f"{rep['n_evaluated']} evaluated of {rep['n_selected']} selected"),
        ("Settings", ", ".join(f"{k}={val}" for k, val in rep["settings"].items())),
    ]
    for k, val in items:
        L.append(f"| {k} | {val} |")
    L.append("")
    L.append("Intervals are 95% query-level bootstrap percentile intervals "
             f"({rep['settings'].get('bootstrap')} resamples, seed {rep['settings'].get('seed')}); macro intervals are "
             "stratified by slice. Definitions: `benchmarks_v2/eval/METHODS.md`.")
    L.append("")

    pops = rep["populations"]
    order = _order(rep)
    L.append("## Ranking quality")
    L.append("")
    L.append("| Population | n | " + " | ".join(SHORT[m] for m in RANKING_METRICS) + " | Unjudged@10 |")
    L.append("|---|---|" + "---|" * len(RANKING_METRICS) + "---|")
    for name in order:
        P = pops[name]
        if name == "overall":
            mac = rep.get("macro", {})
            L.append("| **macro (slices)** | – | " + " | ".join(cell(mac.get(m)) for m in RANKING_METRICS) + " | – |")
        u = P["unjudged"]
        ustr = f"{u['unjudged_positions']}/{u['top10_positions']}" + (f" ({f3(u['rate'])})" if u["rate"] is not None else "")
        label = f"**{name}**" if name == "overall" else name
        L.append(f"| {label} | {P['n_answerable']} | " + " | ".join(cell(P["metrics"].get(m)) for m in RANKING_METRICS)
                 + f" | {ustr} |")
    L.append("")
    if any(P["unjudged"]["unjudged_positions"] for P in pops.values()):
        L.append("### Sensitivity to unjudged documents")
        L.append("")
        L.append("| Population | unjudged | " + " | ".join(f"{SHORT[m]} value / if unjudged relevant" for m in SCENARIO_METRICS) + " |")
        L.append("|---|---|" + "---|" * len(SCENARIO_METRICS))
        for name in order:
            P = pops[name]
            if not P["unjudged"]["unjudged_positions"]:
                continue
            L.append(f"| {name} | {P['unjudged']['unjudged_positions']} | " + " | ".join(
                f"{f3(P['metrics'][m]['value'])} / {f3(P['metrics'][m].get('if_unjudged_relevant'))}" for m in SCENARIO_METRICS) + " |")
        L.append("")
        L.append(f"Pairs to judge: {len(rep.get('unjudged_pairs', []))} (export with `python -m benchmarks_v2.eval pool`).")
        L.append("")

    L.append("## Abstention and errors")
    L.append("")
    L.append("| Population | n | False-accept rate (unanswerable) | Abstention rate (answerable) | AURC | Max coverage | Errors | HTTP 504 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for name in order:
        P = pops[name]
        a = P["abstention"]
        far = a["false_accept_rate"]
        far_s = cell(far) + (f" ({far['false_accepts']}/{far['n']})" if far["n"] else "")
        if far["n"] and not far.get("tiers_available"):
            far_s += " (no tiers)"
        rc = a.get("risk_coverage") or {}
        aurc = cell({"value": rc.get("aurc"), "ci": rc.get("ci")}) if rc else "–"
        L.append(f"| {name} | {P['n_queries']} | {far_s} | {cell(a['abstention_rate_answerable'])} | {aurc} | "
                 f"{f3(rc.get('max_coverage')) if rc else '–'} | {P['errors']['count']} | {P['errors']['http_504']} |")
    L.append("")

    L.append("## Calibration")
    L.append("")
    L.append("| Population | pairs | ECE (bins) | Brier | unjudged excluded |")
    L.append("|---|---|---|---|---|")
    for name in order:
        c = pops[name]["calibration"]
        ece = c["ece"]
        L.append(f"| {name} | {c['n_pairs']} | {cell(ece)} ({ece['bins_effective']}/{ece['bins_requested']}) | "
                 f"{cell(c['brier'])} | {c['unjudged_excluded']} |")
    L.append("")
    L.append("Observed precision per tier (pairs in the top "
             f"{rep['settings'].get('calib_depth')}, label {pops['overall']['calibration']['label']}):")
    L.append("")
    L.append("| Population | Tier | n | Precision | Wilson 95% | Bootstrap 95% |")
    L.append("|---|---|---|---|---|---|")
    for name in order:
        for t, e in pops[name]["calibration"]["tiers"].items():
            w = e.get("wilson")
            b = e.get("bootstrap")
            L.append(f"| {name} | {t} | {e['n']} | {f3(e['precision'])} | "
                     f"{'[' + f3(w[0]) + ', ' + f3(w[1]) + ']' if w else '–'} | "
                     f"{'[' + f3(b[0]) + ', ' + f3(b[1]) + ']' if b else '–'} |")
    L.append("")
    rel = pops["overall"]["calibration"]["reliability"]
    if rel:
        L.append("Reliability diagram data (overall, equal-mass bins):")
        L.append("")
        L.append("| Bin | n | p range | mean p | observed | Wilson 95% |")
        L.append("|---|---|---|---|---|---|")
        for i, r in enumerate(rel, 1):
            w = r.get("observed_wilson")
            L.append(f"| {i} | {r['n']} | {f3(r['p_min'])}–{f3(r['p_max'])} | {f3(r['mean_probability'])} | "
                     f"{f3(r['observed'])} | {'[' + f3(w[0]) + ', ' + f3(w[1]) + ']' if w else '–'} |")
        L.append("")

    L.append("## Latency (end to end, ms)")
    L.append("")
    L.append("| Population | n | p50 | p95 | p99 | max |")
    L.append("|---|---|---|---|---|---|")
    for name in order:
        lt = pops[name]["latency_ms"]

        def lc(e):
            if not e or e.get("value") is None:
                return "–"
            s = f"{e['value']:.0f}"
            if e.get("ci"):
                s += f" [{e['ci'][0]:.0f}, {e['ci'][1]:.0f}]"
            return s
        mx = "–" if lt["max"] is None else "%.0f" % lt["max"]
        L.append(f"| {name} | {lt['n']} | {lc(lt['p50'])} | {lc(lt['p95'])} | {lc(lt['p99'])} | {mx} |")
    L.append("")

    if rep.get("parent_pairs"):
        L.append("## Derived queries against their parents")
        L.append("")
        L.append("| Pair | metric | n pairs | missing parent | diff (derived - parent) | p |")
        L.append("|---|---|---|---|---|---|")
        for name, pp in rep["parent_pairs"].items():
            for m, e in pp["metrics"].items():
                L.append(f"| {name} | {m} | {pp['n_pairs']} | {pp['missing_parent']} | {cell({'value': e['diff'], 'ci': e['ci']})} | "
                         f"{f3(e.get('p_two_sided'))} |")
            if not pp["metrics"]:
                L.append(f"| {name} | – | 0 | {pp['missing_parent']} | – | – |")
        L.append("")

    for c in rep.get("comparisons", []):
        L.append(f"## Comparison: {c['direction']}")
        L.append("")
        L.append(f"Reference run `{c['reference_run']}` (sha256 `{c['reference_run_sha256']}`). Paired bootstrap over the "
                 f"same queries; p is two-sided for H0: diff = 0. Non-inferiority: lower {rep['settings'].get('ni_alpha')} "
                 f"percentile of the difference >= -margin (margin {rep['settings'].get('ni_margin')}).")
        L.append("")
        L.append("| Population | metric | " + c["direction"].split(" - ")[0] + " | " + c["direction"].split(" - ")[1]
                 + " | diff [95% CI] | p | non-inferior |")
        L.append("|---|---|---|---|---|---|---|")
        for name in order + ["macro"]:
            block = c["macro"] if name == "macro" else c["populations"].get(name)
            if not block:
                continue
            for m in RANKING_METRICS:
                e = block.get(m)
                if not e or e.get("diff") is None:
                    continue
                ni = e.get("noninferiority")
                ni_s = "–" if not ni else (f"{'yes' if ni['noninferior'] else 'no'} (lower {f3(ni['lower'])})")
                L.append(f"| {name} | {SHORT[m]} | {f3(e.get('mean_a'))} | {f3(e.get('mean_b'))} | "
                         f"{cell({'value': e['diff'], 'ci': e['ci']})} | {f3(e.get('p_two_sided'))} | {ni_s} |")
        L.append("")

    g = rep.get("gates")
    if g:
        L.append(f"## Release gates: {g['overall']}" + (" (provisional: unjudged documents waived)" if g.get("provisional") else ""))
        L.append("")
        L.append(f"Configuration `{g.get('config')}`, status {g.get('config_status')}. Counts: "
                 + ", ".join(f"{k} {v_}" for k, v_ in g["counts"].items()))
        L.append("")
        L += gate_table_lines(g)
        L.append("")
    w = list(ds.get("warnings", []))
    if rep.get("equivalence_grade_conflicts"):
        w.append(f"{rep['equivalence_grade_conflicts']} equivalence units have members judged with different grades "
                 "(the maximum grade is used)")
    if v.get("n_run_warnings"):
        w.append(f"{v['n_run_warnings']} run-file warnings, first: {v['run_warnings'][0]}")
    if w:
        L.append("## Warnings")
        L.append("")
        L += [f"- {x}" for x in w]
        L.append("")
    return "\n".join(L)
