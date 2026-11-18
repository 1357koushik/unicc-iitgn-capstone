"""
Explains, in plain English, why the sensor flagged a connection.

During training the sensor remembers what NORMAL traffic looks like (for every
measurement: which values occur and how often). To explain a connection it looks for
the measurements that are rare among normal connections, e.g.

    "Connections to the same machine in the last 2 seconds: 511 (normal: usually 1 to 147).
     Higher than any normal connection seen in training."

and says which of the three models raised the alarm.

What each measurement means, and how its values are shown, comes from the dataset's
description (network_sensor/spec.py).
"""
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from network_sensor.spec import DEFAULT_DATASET, DatasetSpec, get_spec

# A value counts as a reason when at most this share of normal connections has it.
# Chosen on TRAINING data (not the test file) by comparing 1%, 2%, 5% and 10% with the
# explanation check in evaluate.py: at 1% a third of alerts had no reason that mattered;
# 2% gave nearly every alert a reason, and higher bars added little but weaker reasons.
RARE_SHARE = 0.02

MODEL_TITLES = {"isolation_forest": "Isolation Forest", "one_class_svm": "One-Class SVM",
                "random_forest": "Random Forest"}


class NormalProfile:
    """What normal traffic looks like, learned from the normal training connections."""

    def __init__(self, normal: pd.DataFrame, importance: Dict[str, float],
                 spec: Optional[DatasetSpec] = None):
        spec = spec or get_spec()
        self.dataset = spec.name
        self.rows = int(len(normal))
        self.numeric = {}
        for column in spec.numeric_columns:
            v = normal[column].to_numpy(dtype=float)
            values, counts = np.unique(v, return_counts=True)
            self.numeric[column] = {
                "values": values,
                "cumulative": np.cumsum(counts),
                "p5": float(np.quantile(v, 0.05)),
                "median": float(np.median(v)),
                "p95": float(np.quantile(v, 0.95)),
            }
        self.categorical = {c: normal[c].value_counts(normalize=True).to_dict() for c in spec.categorical_columns}
        self.most_common = {c: str(normal[c].mode().iloc[0]) for c in spec.categorical_columns}
        # How much the Random Forest relies on each measurement (used to break ties).
        self.importance = importance

    @property
    def spec(self) -> DatasetSpec:
        # Profiles saved before there was more than one dataset are NSL-KDD profiles.
        return get_spec(getattr(self, "dataset", DEFAULT_DATASET))

    def typical_value(self, column: str):
        """The value to use as 'normal' for this measurement."""
        if column in self.spec.categorical_columns:
            return self.most_common[column]
        return self.numeric[column]["median"]

    def typical_text(self, column: str) -> str:
        spec = self.spec
        if column in spec.categorical_columns:
            return f"usually {spec.format_value(column, self.most_common[column])}"
        s = self.numeric[column]
        low, high = spec.format_value(column, s["p5"]), spec.format_value(column, s["p95"])
        return f"usually {low}" if low == high else f"usually {low} to {high}"

    def rarity(self, column: str, x: np.ndarray):
        """For each value: (share of normal connections at least as extreme, direction)."""
        if column in self.spec.categorical_columns:
            freq = self.categorical[column]
            shares = np.array([freq.get(str(value), 0.0) for value in x], dtype=float)
            return shares, np.full(len(x), "unusual", dtype=object)
        s = self.numeric[column]
        values, cumulative = s["values"], s["cumulative"]
        total = cumulative[-1]
        x = np.asarray(x, dtype=float)
        n_below = np.searchsorted(values, x, side="left")          # unique values smaller than x
        count_below = np.where(n_below > 0, cumulative[n_below - 1], 0)
        n_upto = np.searchsorted(values, x, side="right")          # unique values up to x
        count_upto = np.where(n_upto > 0, cumulative[n_upto - 1], 0)
        share_high = (total - count_below) / total                  # normal connections >= x
        share_low = count_upto / total                              # normal connections <= x
        high = share_high <= share_low
        return np.where(high, share_high, share_low), np.where(high, "high", "low").astype(object)


def _reason_text(column: str, value, share: float, direction: str, profile: NormalProfile) -> str:
    spec = profile.spec
    description = spec.descriptions[column]
    start = f"{description}: {spec.format_value(column, value)} (normal: {profile.typical_text(column)})."
    how_many = "Fewer than 0.1%" if share < 0.001 else f"Only {share:.1%}"
    if direction == "unusual" or column in spec.yes_no_columns:
        if share == 0:
            return f"{start} Never seen in normal traffic."
        return f"{start} {how_many} of normal connections have this."
    if share == 0:
        return f"{start} {'Higher' if direction == 'high' else 'Lower'} than any normal connection seen in training."
    return f"{start} {how_many} of normal connections are this {direction}."


def _decision_text(votes: Dict[str, int], score: float) -> str:
    rf = votes["random_forest"] == 1
    both = votes["isolation_forest"] == 1 and votes["one_class_svm"] == 1
    one = votes["isolation_forest"] + votes["one_class_svm"] == 1
    if rf and both:
        return (f"Matches known attack patterns (Random Forest score {score:.0%}), "
                "and both anomaly models found it abnormal.")
    if rf:
        return f"Matches known attack patterns (Random Forest score {score:.0%})."
    if both:
        return ("Both anomaly models found it abnormal, although it does not match a known attack "
                "pattern - possibly a new kind of attack.")
    if one:
        return "Not flagged: only one of the two anomaly models found it unusual, which is not enough."
    return "Not flagged: no model found it suspicious."


def explain_rows(profile: NormalProfile, features: pd.DataFrame, votes: pd.DataFrame,
                 verdicts: np.ndarray, rf_scores: np.ndarray, top_n: int = 3) -> List[dict]:
    """One explanation per connection. `features` must already be checked by prepare_features.

    rf_scores: the Random Forest's score for "attack" (the share of its trees voting
    attack). It is a ranking signal, not a calibrated probability: even a 99% score can
    be a false alarm."""
    spec = profile.spec
    shares, directions = {}, {}
    for column in spec.feature_columns:
        shares[column], directions[column] = profile.rarity(column, features[column].to_numpy())

    explanations = []
    for i in range(len(features)):
        candidates = [c for c in spec.feature_columns if shares[c][i] <= RARE_SHARE]
        candidates.sort(key=lambda c: (shares[c][i], -profile.importance.get(c, 0.0)))
        reasons, used_groups = [], set()
        for column in candidates:
            group = spec.group_of.get(column, column)
            if group in used_groups:
                continue
            used_groups.add(group)
            value = features[column].iloc[i]
            share, direction = float(shares[column][i]), str(directions[column][i])
            reasons.append({
                "feature": column,
                "description": spec.descriptions[column],
                "value": value if column in spec.categorical_columns else float(value),
                "normal": profile.typical_text(column),
                "share_of_normal": share,
                "direction": direction,
                "related_features": spec.groups.get(group, [column]),
                "text": _reason_text(column, value, share, direction, profile),
            })
            if len(reasons) == top_n:
                break

        row_votes = {name: int(votes[name].iloc[i]) for name in MODEL_TITLES}
        score = float(rf_scores[i])
        decision = _decision_text(row_votes, score)
        is_attack = int(verdicts[i]) == 1
        if is_attack and reasons:
            summary = decision + " Main reason: " + reasons[0]["text"]
        elif is_attack:
            summary = decision + (" No single measurement is unusual on its own; the alert comes from "
                                  "the combination of measurements.")
        else:
            summary = decision
        explanations.append({
            "verdict": "attack" if is_attack else "normal",
            "flagged_by": [MODEL_TITLES[n] for n, v in row_votes.items() if v == 1],
            "votes": row_votes,
            "random_forest_score": score,
            "decision": decision,
            "reasons": reasons,
            "summary": summary,
        })
    return explanations
