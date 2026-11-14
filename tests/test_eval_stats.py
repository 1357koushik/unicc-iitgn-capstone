"""B4 bootstrap statistics: interval coverage, paired test, non-inferiority, stratified macro, determinism."""
from __future__ import annotations

import numpy as np
import pytest

from benchmarks_v2.eval import stats


def mean_ci(values, n_boot=1000, seed=1, key="k", ci=0.95):
    v = np.asarray(values, dtype=float)
    boot, _ = stats.bootstrap_ratios(v[:, None], np.ones((len(v), 1)), n_boot, seed, key)
    return stats.percentile_interval(boot[:, 0], ci)


def test_interval_coverage_on_known_mean():
    # 300 synthetic experiments, each 150 Bernoulli(0.8) queries (like one gated slice). A 95% percentile
    # interval should contain 0.8 in about 95% of experiments; a +-3 point band allows for Monte Carlo
    # noise (sd of the coverage estimate ~1.3 points) and the known slight under-coverage of percentile
    # intervals for proportions at this size.
    rng = np.random.default_rng(7)
    hits = 0
    for e in range(300):
        x = (rng.random(150) < 0.8).astype(float)
        lo, hi = mean_ci(x, n_boot=1000, seed=e)
        hits += lo <= 0.8 <= hi
    assert 0.92 <= hits / 300 <= 0.98


def test_interval_coverage_continuous_metric():
    # nDCG-like values in [0, 1]: Beta(2, 1) has mean 2/3.
    rng = np.random.default_rng(11)
    hits = 0
    for e in range(200):
        x = rng.beta(2, 1, 200)
        lo, hi = mean_ci(x, n_boot=1000, seed=100 + e)
        hits += lo <= 2 / 3 <= hi
    assert 0.91 <= hits / 200 <= 0.99


def test_interval_degenerate_and_seeded():
    assert mean_ci([1.0] * 50) == [1.0, 1.0]
    a = mean_ci(np.arange(100) % 3, seed=5, key="x")
    assert a == mean_ci(np.arange(100) % 3, seed=5, key="x")       # same seed and key: identical
    assert a != mean_ci(np.arange(100) % 3, seed=6, key="x")       # different seed: different resamples


def test_resampling_is_uniform_with_replacement():
    # Each query is drawn n times per resample on average: mean count per query = 1.
    counts = np.vstack(list(stats.count_blocks(40, 2000, 3, "u")))
    assert counts.shape == (2000, 40)
    assert (counts.sum(axis=1) == 40).all()
    assert counts.mean() == pytest.approx(1.0)
    assert counts.var() == pytest.approx(1 - 1 / 40, rel=0.05)   # multinomial variance n p (1 - p)


def test_paired_identical_runs_give_p_one():
    rng = np.random.default_rng(0)
    a = (rng.random(400) < 0.6).astype(float)
    r = stats.paired_difference(a, a.copy(), 2000, 1, "same", 0.95, margin=0.01)
    assert r["diff"] == 0.0 and r["ci"] == [0.0, 0.0] and r["p_two_sided"] == 1.0
    assert r["noninferiority"]["noninferior"] is True


def test_paired_test_detects_planted_difference():
    # A succeeds on 70% of 500 queries; B equals A except that 50 of A's successes are failures in B.
    rng = np.random.default_rng(1)
    a = (rng.random(500) < 0.7).astype(float)
    b = a.copy()
    b[np.flatnonzero(a == 1)[:50]] = 0.0
    r = stats.paired_difference(a, b, 5000, 2, "planted", 0.95)
    assert r["diff"] == pytest.approx(50 / 500)
    assert r["ci"][0] > 0.0 and r["p_two_sided"] < 0.001


def test_paired_test_no_difference_is_not_significant():
    # 40 queries where A wins and 40 where B wins: diff 0, p large.
    a = np.zeros(1000)
    b = np.zeros(1000)
    a[:40] = 1
    b[40:80] = 1
    r = stats.paired_difference(a, b, 5000, 3, "even", 0.95)
    assert r["diff"] == 0.0 and r["p_two_sided"] > 0.5 and r["ci"][0] < 0 < r["ci"][1]


def test_noninferiority_accepts_equal_and_rejects_worse():
    rng = np.random.default_rng(4)
    ceiling = (rng.random(3000) < 0.75).astype(float)
    # Planted equal system: 15 queries better and 15 worse than the ceiling (diff 0, sd ~0.0018).
    equal = ceiling.copy()
    ones, zeros = np.flatnonzero(ceiling == 1), np.flatnonzero(ceiling == 0)
    equal[ones[:15]] = 0
    equal[zeros[:15]] = 1
    r = stats.paired_difference(equal, ceiling, 5000, 5, "ni-eq", 0.95, margin=0.01)
    assert r["diff"] == 0.0
    assert r["noninferiority"]["noninferior"] is True and r["noninferiority"]["lower"] > -0.01
    assert r["noninferiority"]["p"] < 0.025
    # Planted worse system: 3 points worse (90 of 3000 successes lost) -> lower bound below -0.01.
    worse = ceiling.copy()
    worse[ones[:90]] = 0
    r = stats.paired_difference(worse, ceiling, 5000, 5, "ni-worse", 0.95, margin=0.01)
    assert r["diff"] == pytest.approx(-0.03)
    assert r["noninferiority"]["noninferior"] is False and r["noninferiority"]["lower"] < -0.01
    assert r["noninferiority"]["p"] > 0.5
    # Slightly worse but clearly within the margin (0.2 point) is accepted.
    near = ceiling.copy()
    near[ones[:6]] = 0
    r = stats.paired_difference(near, ceiling, 5000, 5, "ni-near", 0.95, margin=0.01)
    assert r["noninferiority"]["noninferior"] is True


def test_noninferiority_lower_is_the_alpha_percentile():
    boot = np.linspace(-0.05, 0.05, 1001)
    ni = stats.noninferiority(boot, 0.01, 0.025)
    assert ni["lower"] == pytest.approx(np.percentile(boot, 2.5))
    assert ni["noninferior"] is False                 # lower = -0.0475
    assert ni["p"] == pytest.approx((int((boot <= -0.01).sum()) + 1) / 1002)


def test_p_value_formula():
    assert stats.p_two_sided(np.zeros(99)) == 1.0
    assert stats.p_two_sided(np.full(99, 0.2)) == pytest.approx(2 * 1 / 100)
    # 10 of 99 at or below zero: p = 2 * (10 + 1) / 100 = 0.22
    v = np.concatenate([np.full(10, -0.1), np.full(89, 0.1)])
    assert stats.p_two_sided(v) == pytest.approx(0.22)


def test_stratified_macro_point_and_interval():
    # Stratum 1: 100 queries mean 0.9; stratum 2: 20 queries mean 0.5. Macro = 0.7 (micro would be 0.8333).
    s1 = np.array([1.0] * 90 + [0.0] * 10)
    s2 = np.array([1.0] * 10 + [0.0] * 10)
    boot = stats.macro_bootstrap([s1, s2], [np.ones(100), np.ones(20)], 4000, 9, "m")
    assert np.mean(boot) == pytest.approx(0.7, abs=0.01)
    # Each stratum keeps its size in every resample: the sd of the macro is 0.5*sqrt(0.09/100 + 0.25/20)
    assert np.std(boot) == pytest.approx(0.5 * np.sqrt(0.09 / 100 + 0.25 / 20), rel=0.1)
    r = stats.stratified_paired_macro([(s1, np.zeros(100)), (s2, np.zeros(20))], 2000, 9, "pm", 0.95)
    assert r["diff"] == pytest.approx(0.7) and r["strata"] == 2


def test_undefined_values_are_excluded_not_zero():
    a = np.array([1.0, np.nan, 0.0, 1.0])
    b = np.array([0.0, 1.0, np.nan, 1.0])
    r = stats.paired_difference(a, b, 500, 1, "nan", 0.95)
    assert r["n"] == 2 and r["diff"] == pytest.approx(0.5)  # pairs (1,0) and (1,1)
