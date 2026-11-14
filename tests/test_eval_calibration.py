"""B4 calibration statistics against values computed by hand: Wilson interval, ECE (equal mass, ties), Brier."""
from __future__ import annotations

import numpy as np
import pytest

from benchmarks_v2.eval.calibration import SortedPredictions, brier, ece, equal_mass_bins, reliability, wilson_interval


def sp(p, y):
    return SortedPredictions(np.array(p, dtype=float), np.array(y, dtype=float), np.arange(len(p)))


def test_wilson_known_values():
    # x = 0, n = 10: upper = z^2 / (n + z^2) = 3.841459 / 13.841459 = 0.277533
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.277533, abs=1e-6)
    # x = 10, n = 10: symmetric -> [0.722467, 1]
    lo, hi = wilson_interval(10, 10)
    assert lo == pytest.approx(0.722467, abs=1e-6) and hi == 1.0
    # x = 5, n = 10: centre 0.5, half = 1.96 * sqrt(0.025 + 0.0096037) / 1.384146 = 0.263414
    lo, hi = wilson_interval(5, 10)
    assert lo == pytest.approx(0.236586, abs=1e-5) and hi == pytest.approx(0.763414, abs=1e-5)
    # x = 81, n = 263 (Newcombe 1998 example 2): 0.2553 to 0.3662
    lo, hi = wilson_interval(81, 263)
    assert lo == pytest.approx(0.2553, abs=1e-4) and hi == pytest.approx(0.3662, abs=1e-4)
    assert wilson_interval(0, 0) is None


def test_ece_two_equal_mass_bins_by_hand():
    p = [0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]
    y = [0, 0, 1, 0, 1, 1, 0, 1, 1, 1]
    # bin 1 = five lowest: mean p = 1.6/5 = 0.32, observed 2/5 = 0.4 -> |diff| 0.08
    # bin 2 = five highest: mean p = 4.34/5 = 0.868, observed 4/5 = 0.8 -> 0.068
    # ECE = 0.5 * 0.08 + 0.5 * 0.068 = 0.074
    v, nb = ece(sp(p, y), None, 2)
    assert v == pytest.approx(0.074) and nb == 2
    # one bin: |mean p - mean y| = |5.94/10 - 0.6| = 0.006
    assert ece(sp(p, y), None, 1)[0] == pytest.approx(0.006)
    # ten bins of one each: mean |p - y| = (0.1+0.2+0.7+0.4+0.4+0.3+0.8+0.1+0.05+0.01)/10 = 0.306
    assert ece(sp(p, y), None, 10)[0] == pytest.approx(0.306)


def test_ece_ties_stay_in_one_bin_and_order_does_not_matter():
    p = [0.2, 0.5, 0.5, 0.5, 0.9, 0.9]
    y = [0, 1, 0, 1, 1, 1]
    # 2 bins: boundary after the ceil(6/2) = 3rd smallest (a 0.5), moved to the end of the 0.5 run (4th).
    # bin 1 = {0.2, 0.5, 0.5, 0.5}: mean p 0.425, observed 0.5 -> 0.075 * 4/6 = 0.05
    # bin 2 = {0.9, 0.9}: |0.9 - 1| = 0.1 * 2/6 = 0.033333 -> ECE 0.083333
    s = sp(p, y)
    assert equal_mass_bins(s, np.ones(6), 2) == [(0, 3), (4, 5)]
    v, nb = ece(s, None, 2)
    assert v == pytest.approx(0.05 + 0.1 / 3) and nb == 2
    perm = [4, 1, 5, 0, 3, 2]
    assert ece(sp([p[i] for i in perm], [y[i] for i in perm]), None, 2)[0] == pytest.approx(v)
    # all predictions tied -> one bin whatever B is
    v, nb = ece(sp([0.7] * 5, [1, 1, 0, 1, 0]), None, 10)
    assert nb == 1 and v == pytest.approx(abs(0.7 - 0.6))


def test_ece_weights_equal_duplicated_items():
    # A bootstrap resample that draws item i c_i times must give the ECE of the expanded sample.
    p = [0.1, 0.35, 0.4, 0.8, 0.9]
    y = [0, 1, 0, 1, 1]
    w = np.array([2.0, 0.0, 1.0, 3.0, 1.0])
    expanded_p = [0.1, 0.1, 0.4, 0.8, 0.8, 0.8, 0.9]
    expanded_y = [0, 0, 0, 1, 1, 1, 1]
    s = sp(p, y)
    for b in (1, 2, 3, 5):
        assert ece(s, w, b)[0] == pytest.approx(ece(sp(expanded_p, expanded_y), None, b)[0])


def test_brier_by_hand():
    # ((0.8 - 1)^2 + (0.3 - 0)^2) / 2 = (0.04 + 0.09) / 2 = 0.065
    assert brier(np.array([0.8, 0.3]), np.array([1.0, 0.0])) == pytest.approx(0.065)
    assert np.isnan(brier(np.array([]), np.array([])))


def test_reliability_rows():
    rows = reliability(sp([0.1, 0.2, 0.8, 0.9], [0, 1, 1, 1]), 2)
    assert [r["n"] for r in rows] == [2, 2]
    assert rows[0]["mean_probability"] == pytest.approx(0.15) and rows[0]["observed"] == 0.5
    assert rows[1]["observed"] == 1.0 and rows[1]["observed_wilson"][1] == 1.0
