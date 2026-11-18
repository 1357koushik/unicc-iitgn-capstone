"""Calibration, interval and selective-prediction statistics (METHODS.md sections 5-6).

Every function accepts per-item weights so that the bootstrap can evaluate it on a resample (weight =
number of times the item's query was drawn). With all weights 1 the functions give the point estimates
defined in METHODS.md.
"""
from __future__ import annotations

import math
from statistics import NormalDist

import numpy as np


def z_value(ci: float = 0.95) -> float:
    return NormalDist().inv_cdf(0.5 + ci / 2.0)


def wilson_interval(successes: float, n: float, ci: float = 0.95) -> tuple[float, float] | None:
    """Wilson score interval for a binomial proportion (no continuity correction)."""
    if n <= 0:
        return None
    z = z_value(ci)
    p = successes / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo = 0.0 if successes <= 0 else max(0.0, centre - half)  # exact 0 / 1 at the boundaries (no rounding residue)
    hi = 1.0 if successes >= n else min(1.0, centre + half)
    return lo, hi


class SortedPredictions:
    """Predictions sorted ascending by probability, with tie-group ends precomputed.

    ``order`` is a stable argsort, so the result never depends on input order beyond the tie rule.
    """

    def __init__(self, prob: np.ndarray, label: np.ndarray, group: np.ndarray):
        prob = np.asarray(prob, dtype=float)
        order = np.argsort(prob, kind="stable")
        self.p = prob[order]
        self.y = np.asarray(label, dtype=float)[order]
        self.group = np.asarray(group, dtype=np.int64)[order]  # query index of each prediction
        n = len(self.p)
        # tie_end[i] = last sorted index whose probability equals p[i]
        self.tie_end = np.empty(n, dtype=np.int64)
        if n:
            change = np.nonzero(np.diff(self.p) != 0)[0]  # last index of each run except the final one
            ends = np.append(change, n - 1)
            starts = np.insert(change + 1, 0, 0)
            for s, e in zip(starts, ends):
                self.tie_end[s:e + 1] = e

    def __len__(self) -> int:
        return len(self.p)


def equal_mass_bins(sp: SortedPredictions, w: np.ndarray, n_bins: int) -> list[tuple[int, int]]:
    """Bins as (start, end) inclusive index ranges over the sorted predictions.

    Boundary k (k = 1..B-1) is placed after the first sorted position whose cumulative weight reaches
    k*W/B, then moved forward to the end of that position's run of tied probabilities. Empty bins (zero
    weight) are dropped.
    """
    n = len(sp)
    if n == 0:
        return []
    c = np.cumsum(w)
    total = c[-1]
    if total <= 0:
        return []
    targets = total * np.arange(1, n_bins) / n_bins
    idx = np.searchsorted(c, targets - 1e-9 * total, side="left")
    idx = np.minimum(idx, n - 1)
    ends = sorted(set(int(sp.tie_end[i]) for i in idx) | {n - 1})
    bins, start = [], 0
    for e in ends:
        if e >= start:
            if c[e] - (c[start - 1] if start > 0 else 0.0) > 0:
                bins.append((start, e))
            start = e + 1
    return bins


def ece(sp: SortedPredictions, w: np.ndarray | None, n_bins: int) -> tuple[float, int]:
    """Expected calibration error with equal-mass bins: sum_b (W_b / W) * |mean p_b - mean y_b|."""
    if len(sp) == 0:
        return float("nan"), 0
    w = np.ones(len(sp)) if w is None else w
    bins = equal_mass_bins(sp, w, n_bins)
    total = float(w.sum())
    if total <= 0:
        return float("nan"), 0
    out = 0.0
    for s, e in bins:
        ww = w[s:e + 1]
        wb = ww.sum()
        out += (wb / total) * abs(float(ww @ sp.p[s:e + 1]) / wb - float(ww @ sp.y[s:e + 1]) / wb)
    return out, len(bins)


def reliability(sp: SortedPredictions, n_bins: int, ci: float = 0.95) -> list[dict]:
    w = np.ones(len(sp))
    rows = []
    for s, e in equal_mass_bins(sp, w, n_bins):
        n = e - s + 1
        pos = float(sp.y[s:e + 1].sum())
        lo_hi = wilson_interval(pos, n, ci)
        rows.append({"n": n, "p_min": float(sp.p[s]), "p_max": float(sp.p[e]),
                     "mean_probability": float(sp.p[s:e + 1].mean()), "observed": pos / n,
                     "observed_wilson": list(lo_hi) if lo_hi else None})
    return rows


def brier(p: np.ndarray, y: np.ndarray, w: np.ndarray | None = None) -> float:
    if len(p) == 0:
        return float("nan")
    w = np.ones(len(p)) if w is None else w
    tot = w.sum()
    return float(w @ ((p - y) ** 2) / tot) if tot > 0 else float("nan")


class RiskCoverage:
    """Risk-coverage curve over queries (METHODS.md 5.3).

    Candidates are queries whose top result has a confidence key; they are sorted by key, highest first,
    and grouped by equal key (a threshold accepts a whole tie group or none of it). ``n_population`` counts
    all queries of the population except those excluded because their top result is unjudged.
    """

    def __init__(self, keys: list[tuple | None], wrong: list[int | None], query_index: list[int]):
        cand = [(k, wr, qi) for k, wr, qi in zip(keys, wrong, query_index) if k is not None]
        cand.sort(key=lambda t: t[0], reverse=True)
        self.q = np.array([qi for _, _, qi in cand], dtype=np.int64)
        self.wrong = np.array([wr for _, wr, _ in cand], dtype=float)
        gid, prev = [], object()
        g = -1
        for k, _, _ in cand:
            if k != prev:
                g += 1
                prev = k
            gid.append(g)
        self.gid = np.array(gid, dtype=np.int64)
        self.n_groups = g + 1

    def curve(self, qweight: np.ndarray, n_population: float) -> tuple[np.ndarray, np.ndarray]:
        if self.n_groups == 0 or n_population <= 0:
            return np.array([]), np.array([])
        w = qweight[self.q]
        acc = np.bincount(self.gid, weights=w, minlength=self.n_groups).cumsum()
        err = np.bincount(self.gid, weights=w * self.wrong, minlength=self.n_groups).cumsum()
        keep = np.concatenate(([True], np.diff(acc) > 0)) & (acc > 0)
        acc, err = acc[keep], err[keep]
        return acc / n_population, err / acc

    def aurc(self, qweight: np.ndarray, n_population: float) -> tuple[float, float]:
        """Area under the risk-coverage step curve, and the maximum coverage reached."""
        cov, risk = self.curve(qweight, n_population)
        if len(cov) == 0:
            return float("nan"), 0.0
        widths = np.diff(np.concatenate(([0.0], cov)))
        return float(widths @ risk), float(cov[-1])


def weighted_percentiles(values: np.ndarray, counts: np.ndarray, qs: list[float]) -> np.ndarray:
    """Percentiles (linear interpolation, numpy default) of the sample in which value i appears counts[i] times."""
    sample = np.repeat(values, counts.astype(np.int64))
    if len(sample) == 0:
        return np.full(len(qs), np.nan)
    return np.percentile(sample, qs)
