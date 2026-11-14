"""Query item model and the shared quality controls (overlap filter, splits, temporal flag)."""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .common import OVERLAP_THRESHOLD, SPLIT_RATIOS, SPLITS, TEMPORAL_DAYS, stable_key
from .text import overlap, token_set

GENERATED = {"name": "generated"}


@dataclass
class Item:
    slice: str
    text: str
    qrels: list[dict]                      # {doc_id, grade, origin}
    source: dict
    meta: dict = field(default_factory=dict)
    answerable: bool = True
    overlap_exempt: bool = False           # T1 identifiers, T7, T9 (has its own copy rule)
    link_keys: set = field(default_factory=set)   # extra split-group keys (e.g. T9 subject)
    forced_split: str | None = None
    qid: str = ""
    split: str = ""
    temporal_holdout: bool = False
    max_overlap: float | None = None

    def targets(self) -> list[str]:
        return [q["doc_id"] for q in self.qrels if q["grade"] == 2]

    def cve_docs(self) -> list[str]:
        return sorted({q["doc_id"] for q in self.qrels if q["doc_id"].startswith("CVE-")})

    def to_query(self) -> dict:
        return {"qid": self.qid, "slice": self.slice, "split": self.split, "text": self.text,
                "answerable": self.answerable, "temporal_holdout": self.temporal_holdout,
                "source": self.source, "meta": self.meta}

    def to_qrels(self) -> list[dict]:
        rows = []
        for q in sorted(self.qrels, key=lambda r: (-r["grade"], r["doc_id"])):
            rows.append({"qid": self.qid, "doc_id": q["doc_id"], "grade": q["grade"], "origin": q["origin"]})
        return rows


def qrel(doc_id: str, grade: int, origin: str) -> dict:
    return {"doc_id": doc_id, "grade": grade, "origin": origin}


# --------------------------------------------------------------------------- overlap filter
class OverlapFilter:
    """Drops (query, target) pairs whose query shares more than 60% of its content tokens with the
    target's corpus text; a query with no surviving grade-2 target is dropped."""

    def __init__(self, u, threshold: float = OVERLAP_THRESHOLD):
        self.u = u
        self.threshold = threshold
        self._tok: dict[str, set] = {}
        self.before: dict[str, list[float]] = defaultdict(list)
        self.after: dict[str, list[float]] = defaultdict(list)
        self.dropped_pairs: dict[str, int] = defaultdict(int)
        self.dropped_queries: dict[str, int] = defaultdict(int)

    def doc_tokens(self, doc_id: str) -> set:
        t = self._tok.get(doc_id)
        if t is None:
            t = self._tok[doc_id] = token_set(self.u.corpus_text(doc_id))
        return t

    def score(self, item: Item) -> float:
        ovs = [overlap(item.text, self.doc_tokens(d)) for d in item.targets() if d.startswith("CVE-")]
        return max(ovs) if ovs else 0.0

    def apply(self, item: Item) -> bool:
        """Mutates item.qrels; returns False when the query must be dropped."""
        if item.overlap_exempt:
            return True
        keep = []
        ovs = []
        for q in item.qrels:
            if q["grade"] == 2 and q["doc_id"].startswith("CVE-"):
                ov = overlap(item.text, self.doc_tokens(q["doc_id"]))
                ovs.append(ov)
                if ov > self.threshold:
                    self.dropped_pairs[item.slice] += 1
                    continue
            keep.append(q)
        before = max(ovs) if ovs else 0.0
        self.before[item.slice].append(before)
        if not any(q["grade"] == 2 for q in keep):
            self.dropped_queries[item.slice] += 1
            return False
        item.qrels = keep
        kept_ovs = [overlap(item.text, self.doc_tokens(q["doc_id"])) for q in keep
                    if q["grade"] == 2 and q["doc_id"].startswith("CVE-")]
        item.max_overlap = round(max(kept_ovs), 4) if kept_ovs else 0.0
        return True


def histogram(values: list[float]) -> dict:
    bins = [0] * 10
    for v in values:
        bins[min(9, int(v * 10 + 1e-9))] += 1
    vs = sorted(values)

    def q(p: float) -> float | None:
        if not vs:
            return None
        return round(vs[min(len(vs) - 1, int(p * (len(vs) - 1) + 0.5))], 3)

    return {"n": len(vs), "bins_0.1": bins, "p50": q(0.5), "p90": q(0.9), "max": round(vs[-1], 3) if vs else None,
            "share_gt_0.6": round(sum(1 for v in vs if v > 0.6) / len(vs), 4) if vs else None}


# --------------------------------------------------------------------------- splits
class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def group_keys(item: Item, eqmap) -> set[str]:
    keys = set(item.link_keys)
    for d in item.cve_docs():
        keys.add(d)
        sid = eqmap.set_of.get(d) if eqmap is not None else None
        if sid:
            keys.add(sid)
    return keys


def assign_splits(items: list[Item], eqmap, seed: int) -> dict:
    """Group queries that share any CVE document (any grade), equivalence set or link key; assign each
    group one split. Allowed splits are the intersection over the slices in the group; groups holding a
    temporal-holdout query never go to train. Greedy balancing toward the per-slice ratios of plan 6.3,
    in a seeded order (large groups first). Deterministic."""
    n = len(items)
    uf = _UF(n)
    owner: dict[str, int] = {}
    for i, it in enumerate(items):
        for k in sorted(group_keys(it, eqmap)):
            if k in owner:
                uf.union(owner[k], i)
            else:
                owner[k] = i
    comps: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        comps[uf.find(i)].append(i)
    totals: dict[str, int] = defaultdict(int)
    for it in items:
        totals[it.slice] += 1
    current: dict[tuple[str, str], int] = defaultdict(int)
    order = sorted(comps.values(), key=lambda c: (-len(c), stable_key(seed, "split", items[c[0]].slice,
                                                                     items[c[0]].text)))
    forced_conflicts = 0
    for comp in order:
        slices = defaultdict(int)
        for i in comp:
            slices[items[i].slice] += 1
        allowed = [s for s in SPLITS if all(SPLIT_RATIOS[sl][s] > 0 for sl in slices)]
        if any(items[i].temporal_holdout for i in comp):
            allowed = [s for s in allowed if s != "train"] or allowed
        forced = {items[i].forced_split for i in comp if items[i].forced_split}
        if forced:
            if len(forced) > 1:
                forced_conflicts += 1
            f = sorted(forced)[0]
            choice = f
        else:
            best = None
            for s in allowed:
                # deficit gain: how far each slice is below its target share in split s
                cost = 0.0
                for sl, cnt in slices.items():
                    for sp in SPLITS:
                        target = SPLIT_RATIOS[sl][sp] * totals[sl]
                        cur = current[(sl, sp)] + (cnt if sp == s else 0)
                        cost += (cur - target) ** 2
                key = (cost, stable_key(seed, "tie", s, items[comp[0]].text))
                if best is None or key < best[0]:
                    best = (key, s)
            choice = best[1]
        for i in comp:
            items[i].split = choice
            current[(items[i].slice, choice)] += 1
    sizes = sorted((len(c) for c in comps.values()), reverse=True)
    return {"groups": len(comps), "largest_groups": sizes[:10], "forced_conflicts": forced_conflicts}


# --------------------------------------------------------------------------- temporal
def temporal_flag(item: Item, u, build_date: dt.date) -> bool:
    lo = build_date - dt.timedelta(days=TEMPORAL_DAYS)
    for d in item.targets():
        if d.startswith("CVE-"):
            p = u.published(d)
            if p:
                try:
                    pd = dt.date.fromisoformat(p[:10])
                except ValueError:
                    continue
                if lo < pd <= build_date:
                    return True
    return False


def summarize(items: list[Item]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for it in items:
        out.setdefault(it.slice, {s: 0 for s in SPLITS})
        out[it.slice][it.split] += 1
    return {k: out[k] for k in sorted(out)}


def as_dict(x: Any) -> Any:
    return x
