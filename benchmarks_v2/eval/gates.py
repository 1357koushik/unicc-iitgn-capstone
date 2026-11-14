"""Release-gate evaluation from a report JSON and ``gates.yaml`` (METHODS.md section 9)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_GATES = Path(__file__).with_name("gates.yaml")
KINDS = ("metric", "abstention", "tier_precision", "calibration", "latency", "errors", "comparison",
         "noninferiority", "parent_pair", "judgement_completeness")
PASS, FAIL, MISSING, NA, WAIVED = "PASS", "FAIL", "MISSING", "NOT_APPLICABLE", "WAIVED"


class GateConfigError(ValueError):
    pass


def load_gates(path: Path | None = None) -> dict:
    path = Path(path or DEFAULT_GATES)
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    problems = []
    if not isinstance(cfg, dict) or not isinstance(cfg.get("gates"), list):
        raise GateConfigError(f"{path}: expected a mapping with a 'gates' list")
    ids = set()
    for g in cfg["gates"]:
        gid = g.get("id")
        if not gid or gid in ids:
            problems.append(f"gate id {gid!r} missing or duplicate")
        ids.add(gid)
        if g.get("kind") not in KINDS:
            problems.append(f"{gid}: kind {g.get('kind')!r} is not one of {', '.join(KINDS)}")
        if g.get("kind") in ("comparison", "noninferiority") and g.get("reference") not in (cfg.get("references") or {}):
            problems.append(f"{gid}: reference {g.get('reference')!r} is not defined under 'references'")
        if g.get("kind") == "parent_pair" and g.get("pair") not in (cfg.get("parent_pairs") or {}):
            problems.append(f"{gid}: pair {g.get('pair')!r} is not defined under 'parent_pairs'")
    if problems:
        raise GateConfigError(f"{path}:\n  " + "\n  ".join(problems))
    cfg["_path"] = str(path)
    return cfg


def _fmt(x: Any) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.4f}"
    return str(x)


def _check_point(value, ci, g) -> tuple[str, list[str]]:
    """Apply min / max / lower_min / upper_max; returns (status, threshold descriptions)."""
    th, ok = [], True
    if "min" in g:
        th.append(f">= {g['min']}")
        ok &= value >= g["min"]
    if "max" in g:
        th.append(f"<= {g['max']}")
        ok &= value <= g["max"]
    if "lower_min" in g:
        th.append(f"lower >= {g['lower_min']}")
        ok &= ci is not None and ci[0] >= g["lower_min"]
    if "upper_max" in g:
        th.append(f"upper <= {g['upper_max']}")
        ok &= ci is not None and ci[1] <= g["upper_max"]
    return (PASS if ok else FAIL), th


def _missing(g, pop, why) -> dict:
    status = NA if g.get("allow_not_applicable") else MISSING
    return {"id": g["id"], "population": pop, "status": status, "observed": None, "threshold": "", "note": why}


def _populations(g) -> list[str]:
    if "populations" in g:
        return list(g["populations"])
    return [g.get("population", "overall")]


def _find_comparison(report: dict, ref_variant: str) -> dict | None:
    for c in report.get("comparisons", []):
        if c.get("reference_variant") == ref_variant:
            return c
    return None


def evaluate_one(report: dict, cfg: dict, g: dict, pop: str, allow_unjudged: bool) -> dict:
    kind = g["kind"]
    pops = report.get("populations", {})
    base = {"id": g["id"] if "populations" not in g else f"{g['id']}[{pop}]", "description": g.get("description", ""),
            "kind": kind, "population": pop}
    if kind == "parent_pair":
        pp = report.get("parent_pairs", {}).get(g["pair"])
        if not pp or g["metric"] not in pp.get("metrics", {}) or pp["metrics"][g["metric"]].get("diff") is None:
            return {**base, **_missing(g, pop, f"parent pair {g['pair']} / {g['metric']} not in report"), "id": base["id"]}
        e = pp["metrics"][g["metric"]]
        ok = e["diff"] >= g["min_diff"]
        return {**base, "population": pp["slice"], "status": PASS if ok else FAIL,
                "observed": {"diff": e["diff"], "ci": e["ci"], "n_pairs": pp["n_pairs"]},
                "threshold": f"diff >= {g['min_diff']}",
                "note": f"{pp['missing_parent']} derived queries without an evaluated parent" if pp["missing_parent"] else ""}
    if kind in ("comparison", "noninferiority"):
        ref = cfg["references"][g["reference"]]
        if report.get("variant", {}).get("name") == ref:
            return {**base, "status": NA, "observed": None, "threshold": "",
                    "note": f"report is the reference variant {ref} itself"}
        c = _find_comparison(report, ref)
        if c is None:
            return {**base, "status": MISSING, "observed": None, "threshold": "",
                    "note": f"no comparison against {ref} in report (score --compare <{ref} run>)"}
        e = (c["macro"] if pop == "macro" else c["populations"].get(pop, {})).get(g["metric"])
        if not e or e.get("diff") is None:
            return {**base, "status": MISSING, "observed": None, "threshold": "", "note": f"{pop}/{g['metric']} not compared"}
        if kind == "comparison":
            ok, th = e["diff"] >= g.get("min_diff", float("-inf")), [f"diff >= {g.get('min_diff')}"]
            if "diff_lower_gt" in g:
                th.append(f"lower > {g['diff_lower_gt']}")
                ok &= e["ci"] is not None and e["ci"][0] > g["diff_lower_gt"]
            return {**base, "status": PASS if ok else FAIL, "reference": ref,
                    "observed": {"diff": e["diff"], "ci": e["ci"], "p_two_sided": e.get("p_two_sided")},
                    "threshold": ", ".join(th), "note": ""}
        ni = e.get("noninferiority")
        if not ni:
            return {**base, "status": MISSING, "observed": None, "threshold": "",
                    "note": f"{g['metric']} was not tested for non-inferiority (add it to --ni-metrics)"}
        if abs(ni["alpha"] - g.get("alpha", 0.025)) > 1e-12:
            return {**base, "status": FAIL, "observed": ni, "threshold": "",
                    "note": f"report used alpha {ni['alpha']}, gate needs {g.get('alpha', 0.025)}; re-score"}
        ok = ni["lower"] is not None and ni["lower"] >= -g["margin"]
        return {**base, "status": PASS if ok else FAIL, "reference": ref,
                "observed": {"diff": e["diff"], "lower": ni["lower"], "alpha": ni["alpha"]},
                "threshold": f"lower >= -{g['margin']}", "note": ""}

    P = pops.get(pop)
    if P is None:
        return {**base, **_missing(g, pop, f"population {pop} not in report"), "id": base["id"]}
    if kind == "judgement_completeness":
        u = P["unjudged"]["unjudged_positions"]
        ok = u <= g.get("max", 0)
        status = PASS if ok else (WAIVED if allow_unjudged else FAIL)
        return {**base, "status": status, "observed": {"unjudged_positions": u, "rate": P["unjudged"]["rate"]},
                "threshold": f"<= {g.get('max', 0)}",
                "note": "waived with --allow-unjudged: every result is provisional" if status == WAIVED else ""}
    if kind == "metric":
        e = P["metrics"].get(g["metric"])
        if not e or e.get("value") is None:
            return {**base, **_missing(g, pop, f"{g['metric']} undefined for {pop}"), "id": base["id"]}
        st, th = _check_point(e["value"], e.get("ci"), g)
        return {**base, "status": st, "observed": {"value": e["value"], "ci": e.get("ci"), "n": e.get("n")},
                "threshold": ", ".join(th), "note": ""}
    if kind == "abstention":
        e = P["abstention"].get(g["metric"])
        if not e or e.get("value") is None:
            return {**base, **_missing(g, pop, f"{g['metric']} undefined for {pop}"), "id": base["id"]}
        note = ""
        if g["metric"] == "false_accept_rate" and not e.get("tiers_available", True):
            return {**base, **_missing(g, pop, "variant returns no confidence tiers; false accepts cannot be judged"),
                    "id": base["id"]}
        st, th = _check_point(e["value"], e.get("ci"), g)
        return {**base, "status": st, "observed": {"value": e["value"], "ci": e.get("ci"), "n": e.get("n")},
                "threshold": ", ".join(th), "note": note}
    if kind == "tier_precision":
        t = P["calibration"]["tiers"].get(g["tier"])
        if not t:
            return {**base, **_missing(g, pop, f"no {g['tier']} results in {pop}"), "id": base["id"]}
        mode = g.get("interval", "both")
        bounds = []
        if mode in ("wilson", "both"):
            bounds.append(t["wilson"][0] if t.get("wilson") else None)
        if mode in ("bootstrap", "both"):
            bounds.append(t["bootstrap"][0] if t.get("bootstrap") else None)
        lower = None if any(b is None for b in bounds) else min(bounds)
        ci = None if lower is None else [lower, 1.0]
        st, th = _check_point(t["precision"], ci, g)
        return {**base, "status": st, "observed": {"value": t["precision"], "n": t["n"], "wilson": t.get("wilson"),
                                                   "bootstrap": t.get("bootstrap"), "lower_used": lower},
                "threshold": ", ".join(th) + f" ({mode} lower bound)", "note": ""}
    if kind == "calibration":
        e = P["calibration"].get(g["metric"])
        if not e or e.get("value") is None:
            return {**base, **_missing(g, pop, f"no probabilities in {pop}"), "id": base["id"]}
        st, th = _check_point(e["value"], e.get("ci"), g)
        obs = {"value": e["value"], "ci": e.get("ci"), "n_pairs": P["calibration"]["n_pairs"]}
        if g["metric"] == "ece":
            obs["bins"] = e.get("bins_effective")
        return {**base, "status": st, "observed": obs, "threshold": ", ".join(th), "note": ""}
    if kind == "latency":
        e = P["latency_ms"].get(g["stat"])
        if not e or e.get("value") is None:
            return {**base, **_missing(g, pop, "no latency data"), "id": base["id"]}
        st, th = _check_point(e["value"], e.get("ci"), g)
        note = ""
        if "target" in g:
            note = f"target {g['target']} ms {'met' if e['value'] <= g['target'] else 'not met'}"
        return {**base, "status": st, "observed": {"value": e["value"], "ci": e.get("ci")},
                "threshold": ", ".join(th), "note": note}
    if kind == "errors":
        v = P["errors"].get(g["metric"])
        if v is None:
            return {**base, **_missing(g, pop, f"{g['metric']} not in report"), "id": base["id"]}
        st, th = _check_point(v, None, g)
        return {**base, "status": st, "observed": {"value": v, "errors": P["errors"]["count"]},
                "threshold": ", ".join(th), "note": ""}
    raise GateConfigError(f"unknown kind {kind}")


def evaluate_gates(report: dict, cfg: dict, allow_unjudged: bool = False) -> dict:
    results = []
    for g in cfg["gates"]:
        pops = [g["pair"]] if g["kind"] == "parent_pair" else _populations(g)
        for pop in pops:
            results.append(evaluate_one(report, cfg, g, pop, allow_unjudged))
    bad = [r for r in results if r["status"] in (FAIL, MISSING)]
    waived = [r for r in results if r["status"] == WAIVED]
    overall = FAIL if bad else PASS
    return {"overall": overall, "provisional": bool(waived), "allow_unjudged": allow_unjudged,
            "config": cfg.get("_path"), "config_status": cfg.get("status"), "frozen": cfg.get("frozen"),
            "counts": {s: sum(1 for r in results if r["status"] == s) for s in (PASS, FAIL, MISSING, NA, WAIVED)},
            "results": results}


def gate_table_lines(g: dict) -> list[str]:
    lines = ["| Gate | Population | Status | Observed | Threshold | Note |", "|---|---|---|---|---|---|"]
    for r in g["results"]:
        obs = r.get("observed") or {}
        if "value" in obs:
            o = _fmt(obs["value"])
            if obs.get("ci"):
                o += f" [{_fmt(obs['ci'][0])}, {_fmt(obs['ci'][1])}]"
        elif "diff" in obs:
            o = f"diff {_fmt(obs['diff'])}"
            if obs.get("ci"):
                o += f" [{_fmt(obs['ci'][0])}, {_fmt(obs['ci'][1])}]"
            if obs.get("lower") is not None:
                o += f", lower {_fmt(obs['lower'])}"
        elif "unjudged_positions" in obs:
            o = f"{obs['unjudged_positions']} unjudged (rate {_fmt(obs['rate'])})"
        else:
            o = "n/a"
        lines.append(f"| {r['id']} | {r['population']} | **{r['status']}** | {o} | {r.get('threshold', '')} | "
                     f"{r.get('note', '')} |")
    return lines
