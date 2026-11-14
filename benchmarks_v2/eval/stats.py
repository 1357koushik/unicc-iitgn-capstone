"""Query-level bootstrap (METHODS.md section 7).

A resample draws n query indices uniformly with replacement from the n queries of a population and is
represented by the count vector c (c_i = times query i was drawn). Statistics are recomputed on each
resample with weights c. Random streams are seeded from (seed, sha256(key)), so a population's resamples
do not depend on which other populations are evaluated or in which order.
"""
from __future__ import annotations

import hashlib
from typing import Callable, Iterator

import numpy as np

CHUNK = 250  # resamples generated per block; fixed so results do not depend on memory settings


def rng_for(seed: int, key: str) -> np.random.Generator:
    h = hashlib.sha256(key.encode("utf-8")).digest()
    return np.random.default_rng([int(seed), int.from_bytes(h[:8], "little"), int.from_bytes(h[8:16], "little")])


def count_blocks(n: int, n_boot: int, seed: int, key: str) -> Iterator[np.ndarray]:
    """Yield (b, n) int count matrices, n_boot rows in total."""
    rng = rng_for(seed, key)
    done = 0
    while done < n_boot:
        b = min(CHUNK, n_boot - done)
        idx = rng.integers(0, n, size=(b, n))
        flat = idx + (np.arange(b)[:, None] * n)
        counts = np.bincount(flat.ravel(), minlength=b * n).reshape(b, n)
        yield counts
        done += b


def stratified_count_blocks(sizes: list[int], n_boot: int, seed: int, key: str) -> Iterator[list[np.ndarray]]:
    """Yield, per block, one count matrix per stratum (resampling within each stratum independently)."""
    gens = [count_blocks(n, n_boot, seed, f"{key}|stratum{i}") for i, n in enumerate(sizes)]
    while True:
        try:
            yield [next(g) for g in gens]
        except StopIteration:
            return


def percentile_interval(values: np.ndarray, ci: float = 0.95) -> list[float] | None:
    v = values[~np.isnan(values)]
    if len(v) == 0:
        return None
    a = (1.0 - ci) / 2.0 * 100.0
    lo, hi = np.percentile(v, [a, 100.0 - a])
    return [float(lo), float(hi)]


def ratio_point(num: np.ndarray, den: np.ndarray) -> np.ndarray:
    d = den.sum(axis=0)
    with np.errstate(invalid="ignore", divide="ignore"):
        return np.where(d > 0, num.sum(axis=0) / np.where(d > 0, d, 1), np.nan)


def bootstrap_ratios(num: np.ndarray, den: np.ndarray, n_boot: int, seed: int, key: str,
                     extra: Callable[[np.ndarray], np.ndarray] | None = None) -> tuple[np.ndarray, np.ndarray | None]:
    """Bootstrap distribution of sum(c*num[:, j]) / sum(c*den[:, j]) for every column j.

    ``num`` and ``den`` are (n_queries, n_stats). ``extra`` maps a (b, n) count block to a (b, k) array
    of further (non-linear) statistics computed on the same resamples.
    Returns (n_boot, n_stats) and optionally (n_boot, k); undefined resamples are NaN.
    """
    n = num.shape[0]
    outs, extras = [], []
    for counts in count_blocks(n, n_boot, seed, key):
        cf = counts.astype(float)
        a, b = cf @ num, cf @ den
        with np.errstate(invalid="ignore", divide="ignore"):
            outs.append(np.where(b > 0, a / np.where(b > 0, b, 1), np.nan))
        if extra is not None:
            extras.append(extra(counts))
    return np.vstack(outs), (np.vstack(extras) if extra is not None else None)


def p_two_sided(boot: np.ndarray) -> float | None:
    """Two-sided p-value dual to the percentile interval for H0: difference = 0."""
    v = boot[~np.isnan(boot)]
    if len(v) == 0:
        return None
    b = len(v)
    le, ge = int((v <= 0).sum()), int((v >= 0).sum())
    return float(min(1.0, 2.0 * min(le + 1, ge + 1) / (b + 1)))


def p_noninferiority(boot: np.ndarray, margin: float) -> float | None:
    """One-sided p-value for H0: difference <= -margin (percentile-bootstrap dual)."""
    v = boot[~np.isnan(boot)]
    if len(v) == 0:
        return None
    return float((int((v <= -margin).sum()) + 1) / (len(v) + 1))


def paired_difference(a: np.ndarray, b: np.ndarray, n_boot: int, seed: int, key: str, ci: float,
                      margin: float | None = None, ni_alpha: float = 0.025) -> dict:
    """Paired bootstrap of mean(a - b) over queries where both are defined (NaN = undefined)."""
    mask = ~(np.isnan(a) | np.isnan(b))
    d = np.where(mask, a - b, 0.0)
    n = int(mask.sum())
    if n == 0:
        return {"n": 0, "diff": None, "ci": None, "p_two_sided": None}
    boot, _ = bootstrap_ratios(d[:, None], mask.astype(float)[:, None], n_boot, seed, key)
    boot = boot[:, 0]
    out = {"n": n, "diff": float(d.sum() / n), "mean_a": float(a[mask].mean()), "mean_b": float(b[mask].mean()),
           "ci": percentile_interval(boot, ci), "p_two_sided": p_two_sided(boot)}
    if margin is not None:
        out["noninferiority"] = noninferiority(boot, margin, ni_alpha)
    return out


def noninferiority(boot: np.ndarray, margin: float, alpha: float) -> dict:
    v = boot[~np.isnan(boot)]
    lower = float(np.percentile(v, alpha * 100.0)) if len(v) else None
    return {"margin": margin, "alpha": alpha, "lower": lower,
            "noninferior": (lower is not None and lower >= -margin),
            "p": p_noninferiority(boot, margin)}


def stratified_paired_macro(strata: list[tuple[np.ndarray, np.ndarray]], n_boot: int, seed: int, key: str,
                            ci: float, margin: float | None = None, ni_alpha: float = 0.025) -> dict:
    """Macro (unweighted mean over strata) of per-stratum mean differences, resampled within strata."""
    pts, nums, dens = [], [], []
    for a, b in strata:
        mask = ~(np.isnan(a) | np.isnan(b))
        if mask.sum() == 0:
            continue
        d = np.where(mask, a - b, 0.0)
        nums.append(d)
        dens.append(mask.astype(float))
        pts.append(d.sum() / mask.sum())
    if not pts:
        return {"strata": 0, "diff": None, "ci": None, "p_two_sided": None}
    boot = macro_bootstrap(nums, dens, n_boot, seed, key)
    out = {"strata": len(pts), "diff": float(np.mean(pts)), "ci": percentile_interval(boot, ci),
           "p_two_sided": p_two_sided(boot)}
    if margin is not None:
        out["noninferiority"] = noninferiority(boot, margin, ni_alpha)
    return out


def macro_bootstrap(nums: list[np.ndarray], dens: list[np.ndarray], n_boot: int, seed: int, key: str) -> np.ndarray:
    """Stratified bootstrap of mean over strata of (sum c*num / sum c*den) within each stratum.

    ``nums`` and ``dens`` are lists of 1-D arrays, one per stratum."""
    nums = [np.asarray(x, dtype=float).ravel() for x in nums]
    dens = [np.asarray(x, dtype=float).ravel() for x in dens]
    sizes = [len(x) for x in nums]
    rows = []
    for blocks in stratified_count_blocks(sizes, n_boot, seed, key):
        per = []
        for counts, num, den in zip(blocks, nums, dens):
            cf = counts.astype(float)
            a, b = cf @ num, cf @ den
            with np.errstate(invalid="ignore", divide="ignore"):
                per.append(np.where(b > 0, a / np.where(b > 0, b, 1), np.nan))
        with np.errstate(invalid="ignore"):
            stack = np.vstack(per)  # (strata, b)
            valid = ~np.isnan(stack)
            s = np.where(valid, stack, 0.0).sum(axis=0)
            k = valid.sum(axis=0)
            rows.append(np.where(k > 0, s / np.where(k > 0, k, 1), np.nan))
    return np.concatenate(rows)
