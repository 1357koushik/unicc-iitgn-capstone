"""Per-query metrics (definitions in METHODS.md, sections 2-4). Standard library only.

All ranking metrics use the list order of the run file; scores are never used to re-sort, so tied scores
keep the order the system returned.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from .schema import TIER_RANK, Equivalence, Query, RunRecord

DEPTH = 10  # depth for unjudged counting, nDCG, MRR, the pool and calibration
UNJUDGED_RELEVANT_GRADE = 2  # grade assumed for unjudged documents in the "if unjudged were relevant" scenario

# Ranking metrics, all defined only for answerable queries.
RANKING_METRICS = ("success@1", "success@5", "mrr@10", "ndcg@10", "recall@10", "recall@50", "recall@100",
                   "set_recall@10")
# Metrics that are also reported under the "unjudged documents relevant" scenario.
SCENARIO_METRICS = ("success@1", "success@5", "mrr@10", "ndcg@10")


def gain(grade: int) -> float:
    """Exponential gain 2^grade - 1 (grade 2 -> 3, grade 1 -> 1, grade 0 -> 0)."""
    return float(2 ** grade - 1)


def discount(rank: int) -> float:
    """Standard log2 discount for 1-based rank: 1 / log2(rank + 1)."""
    return 1.0 / math.log2(rank + 1)


def dcg(gains: list[float], k: int = DEPTH) -> float:
    return sum(g * discount(i) for i, g in enumerate(gains[:k], 1))


@dataclass
class Settings:
    min_grade: int = 2  # a unit is "relevant" for binary metrics if its grade >= min_grade
    abstain_is_miss: bool = True  # an abstained answerable query scores 0 on ranking metrics
    calib_depth: int = DEPTH  # results per query that enter calibration and tier precision
    ece_bins: int = 10
    false_accept_min_tier: str = "PARTIAL"
    bootstrap: int = 10_000
    seed: int = 20261114
    ci: float = 0.95
    ni_alpha: float = 0.025  # one-sided alpha of the non-inferiority test (lower end of the two-sided 95% CI)
    ni_margin: float = 0.01
    ni_metrics: tuple = ("ndcg@10", "success@1")

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["ni_metrics"] = list(self.ni_metrics)
        return d


@dataclass
class QueryJudgements:
    """Judgements for one query, at the level of equivalence units."""

    answerable: bool
    unit_grade: dict[str, int]  # judged units -> grade (max over judged members)
    conflicts: int = 0  # units whose judged members carry different grades

    def judged(self, unit: str) -> bool:
        return (not self.answerable) or unit in self.unit_grade

    def grade(self, unit: str) -> int | None:
        if not self.answerable:
            return 0
        return self.unit_grade.get(unit)


def query_judgements(query: Query, doc_grades: dict[str, int], eq: Equivalence) -> QueryJudgements:
    unit_grade: dict[str, int] = {}
    seen_grades: dict[str, set[int]] = {}
    for doc, g in doc_grades.items():
        u = eq.unit(doc)
        seen_grades.setdefault(u, set()).add(g)
        unit_grade[u] = max(g, unit_grade.get(u, -1))
    conflicts = sum(1 for s in seen_grades.values() if len(s) > 1)
    return QueryJudgements(query.answerable, unit_grade, conflicts)


@dataclass
class QueryResult:
    qid: str
    slice: str
    answerable: bool
    temporal_holdout: bool
    metrics: dict[str, float | None] = field(default_factory=dict)  # None = undefined for this query
    scenario: dict[str, float | None] = field(default_factory=dict)  # "unjudged relevant" scenario
    top10_positions: int = 0
    unjudged_top10: int = 0
    unjudged_docs: list[tuple[str, int]] = field(default_factory=list)  # (doc_id, rank) unjudged in top 10
    abstained: bool = False
    error: str | None = None
    false_accept: int | None = None  # unanswerable queries only
    latency_ms: float = 0.0
    calib: list[tuple[float, int]] = field(default_factory=list)  # (probability, label)
    tiers: list[tuple[str, int]] = field(default_factory=list)  # (tier, label)
    calib_unjudged: int = 0
    rc_key: tuple | None = None  # confidence key of the top result; None = never accepted
    rc_wrong: int | None = None
    rc_excluded: bool = False  # top result unjudged: left out of the risk-coverage curve
    has_confidence: bool = False


def ranking_metrics(units: list[str], qj: QueryJudgements, min_grade: int) -> tuple[dict, dict, int, list[int]]:
    """Compute ranking metrics for one answerable query.

    ``units`` is the ranked list mapped to equivalence units (duplicates allowed: a later member of a unit
    already seen occupies its rank but has no gain and is not a new hit).

    Returns (metrics, scenario_metrics, unjudged_positions_in_top10, ranks_of_unjudged_in_top10).
    """
    first = []
    seen: set[str] = set()
    for u in units:
        first.append(u not in seen)
        seen.add(u)
    judged = [qj.judged(u) for u in units]
    grades = [qj.grade(u) for u in units]

    relevant = {u for u, g in qj.unit_grade.items() if g >= min_grade}
    ideal = sorted((g for g in qj.unit_grade.values() if g >= 1), reverse=True)
    idcg = dcg([gain(g) for g in ideal])

    unjudged_ranks = [i for i, (j, _) in enumerate(zip(judged[:DEPTH], units[:DEPTH]), 1) if not j]

    def metrics_for(rel_flags: list[bool], gains: list[float], idcg_value: float) -> dict:
        m: dict[str, float | None] = {}
        m["success@1"] = 1.0 if any(rel_flags[:1]) else 0.0
        m["success@5"] = 1.0 if any(rel_flags[:5]) else 0.0
        rr = 0.0
        for i, r in enumerate(rel_flags[:DEPTH], 1):
            if r:
                rr = 1.0 / i
                break
        m["mrr@10"] = rr
        m["ndcg@10"] = dcg(gains) / idcg_value if idcg_value > 0 else None
        return m

    # Value: unjudged documents contribute no gain (and are counted separately).
    rel = [bool(f and j and g is not None and g >= min_grade) for f, j, g in zip(first, judged, grades)]
    gains = [gain(g) if (f and j and g is not None) else 0.0 for f, j, g in zip(first, judged, grades)]
    m = metrics_for(rel, gains, idcg)
    for k in (10, 50, 100):
        found = {u for u in units[:k] if u in relevant}
        m[f"recall@{k}"] = len(found) / len(relevant) if relevant else None
    if len(relevant) >= 2:
        m["set_recall@10"] = len({u for u in units[:DEPTH] if u in relevant}) / min(len(relevant), DEPTH)
    else:
        m["set_recall@10"] = None

    # Scenario: every unjudged unit in the top 10 has grade UNJUDGED_RELEVANT_GRADE (and joins the ideal).
    sc_units = {u for u, f, j in zip(units[:DEPTH], first[:DEPTH], judged[:DEPTH]) if f and not j}
    if sc_units:
        g_un = UNJUDGED_RELEVANT_GRADE
        rel_s = [bool(f and ((not j and u in sc_units and g_un >= min_grade) or (j and g is not None and g >= min_grade)))
                 for u, f, j, g in zip(units, first, judged, grades)]
        gains_s = [(gain(g_un) if (not j and u in sc_units) else (gain(g) if (j and g is not None) else 0.0)) if f else 0.0
                   for u, f, j, g in zip(units, first, judged, grades)]
        ideal_s = sorted(ideal + [g_un] * len(sc_units), reverse=True)
        sc = metrics_for(rel_s, gains_s, dcg([gain(g) for g in ideal_s]))
    else:
        sc = {k: m[k] for k in SCENARIO_METRICS}
    return m, sc, len(unjudged_ranks), unjudged_ranks


def confidence_key(tier: str | None, probability: float | None) -> tuple | None:
    """Ordering key of a result's confidence: tier rank first, then probability (see METHODS.md 5.3)."""
    if tier is None and probability is None:
        return None
    return (TIER_RANK[tier] if tier is not None else -1, probability if probability is not None else 0.0)


def evaluate_query(query: Query, record: RunRecord, qj: QueryJudgements, eq: Equivalence, s: Settings) -> QueryResult:
    res = QueryResult(query.qid, query.slice, query.answerable, query.temporal_holdout)
    res.abstained = record.abstained
    res.error = record.error
    res.latency_ms = record.latency_ms
    ranked = [] if record.error is not None else list(record.ranked)
    units_all = [eq.unit(r.doc_id) for r in ranked]

    # Ranking metrics (answerable only).
    if query.answerable:
        scored_units = [] if (record.abstained and s.abstain_is_miss) else units_all
        m, sc, n_unj, unj_ranks = ranking_metrics(scored_units, qj, s.min_grade)
        res.metrics, res.scenario = m, sc
        res.top10_positions = min(len(scored_units), DEPTH)
        res.unjudged_top10 = n_unj
        res.unjudged_docs = [(ranked[r - 1].doc_id, r) for r in unj_ranks]
    else:
        res.metrics = {k: None for k in RANKING_METRICS}
        res.scenario = {k: None for k in SCENARIO_METRICS}
        res.top10_positions = min(len(units_all), DEPTH)

    # Abstention.
    if not query.answerable:
        top = ranked[0] if ranked else None
        accepted = (not record.abstained and top is not None and top.tier is not None
                    and TIER_RANK[top.tier] >= TIER_RANK[s.false_accept_min_tier])
        res.false_accept = 1 if accepted else 0

    # Calibration and tier precision: every returned result in the first calib_depth positions.
    for r, u in zip(ranked[: s.calib_depth], units_all[: s.calib_depth]):
        if r.probability is not None or r.tier is not None:
            res.has_confidence = True
        if not qj.judged(u):
            if r.probability is not None or r.tier is not None:
                res.calib_unjudged += 1
            continue
        g = qj.grade(u)
        label = 1 if (g is not None and g >= s.min_grade) else 0
        if r.probability is not None:
            res.calib.append((r.probability, label))
        if r.tier is not None:
            res.tiers.append((r.tier, label))

    # Risk-coverage: the query is "accepted" at threshold t if its top result's confidence key >= t.
    if ranked and not record.abstained:
        top = ranked[0]
        key = confidence_key(top.tier, top.probability)
        if key is not None:
            u = units_all[0]
            if query.answerable and not qj.judged(u):
                res.rc_excluded = True
            else:
                g = qj.grade(u)
                res.rc_key = key
                res.rc_wrong = 0 if (query.answerable and g is not None and g >= s.min_grade) else 1
    return res
