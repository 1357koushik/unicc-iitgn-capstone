"""Score a run against a dataset: per-query results, per-population aggregates with bootstrap intervals,
macro averages, parent-pair (T6) differences and paired comparisons with other runs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

import numpy as np

from . import calibration as cal
from . import stats
from .metrics import (DEPTH, RANKING_METRICS, SCENARIO_METRICS, QueryResult, Settings, evaluate_query,
                      query_judgements)
from .schema import SLICES, TIERS, Dataset, Query, Run

HTTP_504_PREFIX = "http_504"
CURVE_POINTS = 200


class ScoringError(ValueError):
    pass


# --------------------------------------------------------------------------------------------- evaluation
def evaluate_run(ds: Dataset, run: Run, queries: list[Query], s: Settings, allow_incomplete: bool = False
                 ) -> tuple[list[QueryResult], list[str]]:
    missing = [q.qid for q in queries if q.qid not in run.records]
    if missing and not allow_incomplete:
        raise ScoringError(f"{run.path}: run is incomplete: {len(missing)} of {len(queries)} selected queries have "
                           f"no record (first: {', '.join(missing[:5])}); finish the run (it is resumable) or "
                           f"pass --allow-incomplete")
    unknown = [qid for qid in run.records if qid not in ds.queries]
    if unknown:
        raise ScoringError(f"{run.path}: {len(unknown)} qid(s) are not in the loaded dataset "
                           f"(first: {', '.join(sorted(unknown)[:5])}); test-split qids need TRE_OPEN_SEALED=E1")
    results = []
    for q in queries:
        rec = run.records.get(q.qid)
        if rec is None:
            continue
        qj = query_judgements(q, ds.qrels.get(q.qid, {}), ds.equivalence)
        if q.answerable and not any(g >= s.min_grade for g in qj.unit_grade.values()):
            raise ScoringError(f"{q.qid}: answerable query has no document with grade >= {s.min_grade} in qrels")
        results.append(evaluate_query(q, rec, qj, ds.equivalence, s))
    return results, missing


def grade_conflicts(ds: Dataset, queries: list[Query]) -> int:
    return sum(query_judgements(q, ds.qrels.get(q.qid, {}), ds.equivalence).conflicts for q in queries)


# --------------------------------------------------------------------------------------------- populations
def build_populations(queries: list[Query], pop_defs: dict[str, dict] | None) -> dict[str, dict]:
    """Return name -> {"kind", "index": [positions in queries], "definition"}."""
    pops: dict[str, dict] = {}
    for sl in SLICES:
        idx = [i for i, q in enumerate(queries) if q.slice == sl]
        if idx:
            pops[sl] = {"kind": "slice", "index": idx, "definition": {"slices": [sl]}}
    pops["overall"] = {"kind": "overall", "index": list(range(len(queries))), "definition": {"all": True}}
    th = [i for i, q in enumerate(queries) if q.temporal_holdout]
    if th:
        pops["temporal_holdout"] = {"kind": "subset", "index": th, "definition": {"temporal_holdout": True}}
    for name, d in (pop_defs or {}).items():
        idx = [i for i, q in enumerate(queries) if population_member(q, d)]
        if idx:
            pops[name] = {"kind": "group", "index": idx, "definition": d}
    return pops


def population_member(q: Query, d: dict) -> bool:
    if "slices" in d and q.slice not in d["slices"]:
        return False
    if "exclude_slices" in d and q.slice in d["exclude_slices"]:
        return False
    if "temporal_holdout" in d and q.temporal_holdout != bool(d["temporal_holdout"]):
        return False
    if "meta" in d:
        m = d["meta"]
        if q.meta.get(m["key"]) not in m.get("in", []):
            return False
    return True


# --------------------------------------------------------------------------------------------- aggregation
@dataclass
class Linear:
    names: list[str]
    num: np.ndarray
    den: np.ndarray


def linear_stats(rs: list[QueryResult]) -> Linear:
    names, nums, dens = [], [], []

    def add(name, num, den):
        names.append(name)
        nums.append(np.asarray(num, dtype=float))
        dens.append(np.asarray(den, dtype=float))

    for m in RANKING_METRICS:
        add(m, [r.metrics.get(m) or 0.0 for r in rs], [r.metrics.get(m) is not None for r in rs])
    add("false_accept_rate", [r.false_accept or 0 for r in rs], [not r.answerable for r in rs])
    add("abstention_rate_answerable", [r.abstained and r.answerable for r in rs], [r.answerable for r in rs])
    add("abstention_rate_unanswerable", [r.abstained and not r.answerable for r in rs], [not r.answerable for r in rs])
    add("error_rate", [r.error is not None for r in rs], [1] * len(rs))
    add("unjudged_rate@10", [r.unjudged_top10 for r in rs], [r.top10_positions if r.answerable else 0 for r in rs])
    add("brier", [sum((p - y) ** 2 for p, y in r.calib) for r in rs], [len(r.calib) for r in rs])
    for t in TIERS:
        add(f"precision:{t}", [sum(lab for tt, lab in r.tiers if tt == t) for r in rs],
            [sum(1 for tt, _ in r.tiers if tt == t) for r in rs])
    return Linear(names, np.vstack(nums).T if rs else np.zeros((0, len(names))),
                  np.vstack(dens).T if rs else np.zeros((0, len(names))))


def _v(x):
    if x is None:
        return None
    x = float(x)
    return None if np.isnan(x) else x


def summarize(rs: list[QueryResult], s: Settings, key: str, run_has_tiers: bool = True) -> dict:
    """Aggregate one population. ``run_has_tiers``: whether the variant returns confidence tiers at all
    (without tiers a false accept cannot be recognised, and the false-accept gate is not evaluable)."""
    n = len(rs)
    lin = linear_stats(rs)
    point = stats.ratio_point(lin.num, lin.den)

    # Calibration pairs.
    probs, labels, groups = [], [], []
    for qi, r in enumerate(rs):
        for p, y in r.calib:
            probs.append(p)
            labels.append(y)
            groups.append(qi)
    sp = cal.SortedPredictions(np.array(probs), np.array(labels), np.array(groups, dtype=np.int64))
    ece_point, ece_bins = cal.ece(sp, None, s.ece_bins)

    # Risk-coverage.
    rc_pop = [qi for qi, r in enumerate(rs) if not r.rc_excluded]
    rc_n = float(len(rc_pop))
    rc = cal.RiskCoverage([r.rc_key for r in rs], [r.rc_wrong for r in rs], list(range(n)))
    rc_defined = any(r.rc_key is not None for r in rs)
    rc_mask = np.array([0.0 if r.rc_excluded else 1.0 for r in rs])
    aurc_point, maxcov = rc.aurc(rc_mask.copy(), rc_n) if rc_defined else (float("nan"), 0.0)

    lat = np.array([r.latency_ms for r in rs], dtype=float)
    lat_point = np.percentile(lat, [50, 95, 99]) if n else np.full(3, np.nan)

    boot = boot_extra = None
    if s.bootstrap > 0 and n > 0:
        def extra(counts: np.ndarray) -> np.ndarray:
            out = np.empty((counts.shape[0], 5))
            for i, c in enumerate(counts):
                cf = c.astype(float)
                out[i, 0] = cal.ece(sp, cf[sp.group], s.ece_bins)[0] if len(sp) else np.nan
                if rc_defined:
                    w = cf * rc_mask
                    out[i, 1] = rc.aurc(w, float(w.sum()))[0]
                else:
                    out[i, 1] = np.nan
                out[i, 2:5] = cal.weighted_percentiles(lat, c, [50, 95, 99])
            return out
        boot, boot_extra = stats.bootstrap_ratios(lin.num, lin.den, s.bootstrap, s.seed, key, extra)

    def ci_of(j):
        return stats.percentile_interval(boot[:, j], s.ci) if boot is not None else None

    def ci_extra(j):
        return stats.percentile_interval(boot_extra[:, j], s.ci) if boot_extra is not None else None

    col = {name: j for j, name in enumerate(lin.names)}
    unj_pos = int(sum(r.unjudged_top10 for r in rs))
    out: dict[str, Any] = {
        "n_queries": n,
        "n_answerable": int(sum(r.answerable for r in rs)),
        "n_unanswerable": int(sum(not r.answerable for r in rs)),
        "metrics": {},
        "unjudged": {
            "top10_positions": int(sum(r.top10_positions for r in rs if r.answerable)),
            "unjudged_positions": unj_pos,
            "rate": _v(point[col["unjudged_rate@10"]]),
            "rate_ci": ci_of(col["unjudged_rate@10"]),
            "queries_with_unjudged": int(sum(r.unjudged_top10 > 0 for r in rs)),
        },
    }
    for m in RANKING_METRICS:
        j = col[m]
        d = int(lin.den[:, j].sum())
        entry = {"value": _v(point[j]), "ci": ci_of(j), "n": d}
        if m in SCENARIO_METRICS and unj_pos > 0 and d > 0:
            vals = [r.scenario.get(m) for r in rs if r.scenario.get(m) is not None]
            entry["if_unjudged_relevant"] = float(np.mean(vals)) if vals else None
        out["metrics"][m] = entry
    n_un = out["n_unanswerable"]
    far_succ = float(lin.num[:, col["false_accept_rate"]].sum())
    out["abstention"] = {
        "false_accept_rate": {"value": _v(point[col["false_accept_rate"]]), "ci": ci_of(col["false_accept_rate"]),
                              "wilson": list(cal.wilson_interval(far_succ, n_un, s.ci)) if n_un else None,
                              "n": n_un, "false_accepts": int(far_succ),
                              "tiers_available": run_has_tiers},
        "abstention_rate_answerable": {"value": _v(point[col["abstention_rate_answerable"]]),
                                       "ci": ci_of(col["abstention_rate_answerable"]), "n": out["n_answerable"]},
        "abstention_rate_unanswerable": {"value": _v(point[col["abstention_rate_unanswerable"]]),
                                         "ci": ci_of(col["abstention_rate_unanswerable"]), "n": n_un},
        "risk_coverage": None,
    }
    if rc_defined:
        cov, risk = rc.curve(rc_mask.copy(), rc_n)
        step = max(1, int(np.ceil(len(cov) / CURVE_POINTS)))
        pts = [[float(c), float(r_)] for c, r_ in zip(cov[::step], risk[::step])]
        if len(cov) and (not pts or pts[-1][0] != float(cov[-1])):
            pts.append([float(cov[-1]), float(risk[-1])])
        out["abstention"]["risk_coverage"] = {
            "aurc": _v(aurc_point), "ci": ci_extra(1), "max_coverage": maxcov,
            "risk_at_max_coverage": float(risk[-1]) if len(risk) else None,
            "n_population": int(rc_n), "n_candidates": int(sum(r.rc_key is not None for r in rs)),
            "excluded_unjudged_top1": int(sum(r.rc_excluded for r in rs)), "points": pts}
    out["errors"] = {"count": int(sum(r.error is not None for r in rs)),
                     "http_504": int(sum(1 for r in rs if r.error and r.error.startswith(HTTP_504_PREFIX))),
                     "rate": _v(point[col["error_rate"]]), "rate_ci": ci_of(col["error_rate"])}
    n_pairs = len(sp)
    out["calibration"] = {
        "n_pairs": n_pairs, "n_queries_with_pairs": int(sum(1 for r in rs if r.calib)),
        "unjudged_excluded": int(sum(r.calib_unjudged for r in rs)),
        "label": f"grade >= {s.min_grade}", "depth": s.calib_depth,
        "ece": {"value": _v(ece_point) if n_pairs else None, "ci": ci_extra(0), "bins_requested": s.ece_bins,
                "bins_effective": ece_bins, "binning": "equal-mass"},
        "brier": {"value": _v(point[col["brier"]]), "ci": ci_of(col["brier"])},
        "reliability": cal.reliability(sp, s.ece_bins, s.ci) if n_pairs else [],
        "tiers": {},
    }
    for t in TIERS:
        j = col[f"precision:{t}"]
        nt = float(lin.den[:, j].sum())
        if nt == 0:
            continue
        kt = float(lin.num[:, j].sum())
        out["calibration"]["tiers"][t] = {"n": int(nt), "relevant": int(kt), "precision": kt / nt,
                                          "wilson": list(cal.wilson_interval(kt, nt, s.ci)), "bootstrap": ci_of(j)}
    out["latency_ms"] = {"n": n, "mean": _v(lat.mean()) if n else None, "max": _v(lat.max()) if n else None,
                         "p50": {"value": _v(lat_point[0]), "ci": ci_extra(2)},
                         "p95": {"value": _v(lat_point[1]), "ci": ci_extra(3)},
                         "p99": {"value": _v(lat_point[2]), "ci": ci_extra(4)}}
    return out


def macro(results: list[QueryResult], pops: dict[str, dict], s: Settings) -> dict:
    out = {}
    slices = [name for name, p in pops.items() if p["kind"] == "slice"]
    for m in RANKING_METRICS:
        nums, dens, pts, used = [], [], [], []
        for sl in slices:
            rs = [results[i] for i in pops[sl]["index"]]
            den = np.array([r.metrics.get(m) is not None for r in rs], dtype=float)
            if den.sum() == 0:
                continue
            num = np.array([r.metrics.get(m) or 0.0 for r in rs], dtype=float)
            nums.append(num[:, None])
            dens.append(den[:, None])
            pts.append(num.sum() / den.sum())
            used.append(sl)
        if not pts:
            out[m] = {"value": None, "ci": None, "slices": []}
            continue
        ci = None
        if s.bootstrap > 0:
            boot = stats.macro_bootstrap(nums, dens, s.bootstrap, s.seed, f"macro|{m}")
            ci = stats.percentile_interval(boot, s.ci)
        out[m] = {"value": float(np.mean(pts)), "ci": ci, "slices": used}
    return out


def metric_vector(results: list[QueryResult], idx: Iterable[int], m: str) -> np.ndarray:
    return np.array([np.nan if results[i].metrics.get(m) is None else results[i].metrics[m] for i in idx], dtype=float)


def parent_pairs(results: list[QueryResult], queries: list[Query], defs: dict[str, dict] | None, s: Settings) -> dict:
    out = {}
    pos = {q.qid: i for i, q in enumerate(queries)}
    for name, d in (defs or {}).items():
        children = [i for i, q in enumerate(queries) if q.slice == d["slice"]]
        pairs, missing = [], 0
        for i in children:
            p = queries[i].meta.get(d["parent_key"])
            if isinstance(p, str) and p in pos:
                pairs.append((i, pos[p]))
            else:
                missing += 1
        entry = {"slice": d["slice"], "parent_key": d["parent_key"], "n_children": len(children),
                 "n_pairs": len(pairs), "missing_parent": missing, "metrics": {}}
        if pairs:
            for m in d.get("metrics", ["ndcg@10"]):
                a = metric_vector(results, [c for c, _ in pairs], m)
                b = metric_vector(results, [p for _, p in pairs], m)
                entry["metrics"][m] = stats.paired_difference(a, b, s.bootstrap, s.seed, f"parent|{name}", s.ci)
        out[name] = entry
    return out


def compare(results_a: list[QueryResult], results_b: list[QueryResult], pops: dict[str, dict], s: Settings,
            metrics: Iterable[str] = RANKING_METRICS) -> dict:
    """Paired comparison A - B per population and metric; non-inferiority for s.ni_metrics."""
    assert [r.qid for r in results_a] == [r.qid for r in results_b]
    out: dict[str, Any] = {"populations": {}, "macro": {}}
    for name, p in pops.items():
        entry = {}
        for m in metrics:
            a = metric_vector(results_a, p["index"], m)
            b = metric_vector(results_b, p["index"], m)
            margin = s.ni_margin if m in s.ni_metrics else None
            entry[m] = stats.paired_difference(a, b, s.bootstrap, s.seed, f"cmp|{name}", s.ci, margin, s.ni_alpha)
        out["populations"][name] = entry
    slices = [name for name, p in pops.items() if p["kind"] == "slice"]
    for m in metrics:
        strata = [(metric_vector(results_a, pops[sl]["index"], m), metric_vector(results_b, pops[sl]["index"], m))
                  for sl in slices]
        margin = s.ni_margin if m in s.ni_metrics else None
        out["macro"][m] = stats.stratified_paired_macro(strata, s.bootstrap, s.seed, f"cmpmacro|{m}", s.ci,
                                                        margin, s.ni_alpha)
    return out


def per_query_rows(results: list[QueryResult]) -> list[dict]:
    rows = []
    for r in results:
        rows.append({"qid": r.qid, "slice": r.slice, "answerable": r.answerable,
                     "metrics": {k: v for k, v in r.metrics.items() if v is not None},
                     "unjudged_top10": r.unjudged_top10, "abstained": r.abstained, "error": r.error,
                     "false_accept": r.false_accept, "latency_ms": r.latency_ms})
    return rows


def score(ds: Dataset, run: Run, queries: list[Query], s: Settings, pop_defs: dict | None = None,
          parent_defs: dict | None = None, compare_runs: list[Run] | None = None,
          allow_incomplete: bool = False) -> dict:
    results, missing = evaluate_run(ds, run, queries, s, allow_incomplete)
    evaluated = [q for q in queries if q.qid in run.records]
    pops = build_populations(evaluated, pop_defs)
    run_has_tiers = any(r.tier is not None for rec in run.records.values() for r in rec.ranked)
    analysis: dict[str, Any] = {
        "run_has_tiers": run_has_tiers,
        "run_has_probabilities": any(r.probability is not None for rec in run.records.values() for r in rec.ranked),
        "n_selected": len(queries), "n_evaluated": len(results), "missing_qids": missing,
        "equivalence_grade_conflicts": grade_conflicts(ds, evaluated),
        "populations": {}, "macro": macro(results, pops, s),
        "population_definitions": {k: {"kind": v["kind"], "definition": v["definition"], "n": len(v["index"])}
                                   for k, v in pops.items()},
    }
    for name, p in pops.items():
        analysis["populations"][name] = summarize([results[i] for i in p["index"]], s, f"pop|{name}", run_has_tiers)
        analysis["populations"][name]["kind"] = p["kind"]
    analysis["parent_pairs"] = parent_pairs(results, evaluated, parent_defs, s)
    analysis["comparisons"] = []
    for other in compare_runs or []:
        rb, missing_b = evaluate_run(ds, other, evaluated, s, allow_incomplete)
        if missing_b:
            raise ScoringError(f"{other.path}: comparison run lacks {len(missing_b)} of the evaluated queries; "
                               f"paired comparison needs the same queries")
        cmp_ = compare(results, rb, pops, s)
        cmp_.update({"reference_variant": other.variant, "reference_run": other.path,
                     "reference_run_sha256": other.sha256, "direction": f"{run.variant} - {other.variant}"})
        analysis["comparisons"].append(cmp_)
    analysis["per_query"] = per_query_rows(results)
    analysis["unjudged_pairs"] = sorted({(r.qid, d) for r in results for d, _ in r.unjudged_docs})
    return analysis
