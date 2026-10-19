"""
Explains, in plain English, why the sensor flagged a connection.

During training the sensor remembers what NORMAL traffic looks like (for every
measurement: which values occur and how often). To explain a connection it looks for
the measurements that are rare among normal connections, e.g.

    "Connections to the same machine in the last 2 seconds: 511 (normal: usually 1 to 147).
     Higher than any normal connection seen in training."

and says which of the three models raised the alarm.
"""
from typing import Dict, List

import numpy as np
import pandas as pd

from network_sensor.datasets import CATEGORICAL_COLUMNS, FEATURE_COLUMNS, NUMERIC_COLUMNS

# A value counts as a reason when at most this share of normal connections has it.
# Chosen on TRAINING data (not the test file) by comparing 1%, 2%, 5% and 10% with the
# explanation check in evaluate.py: at 1% a third of alerts had no reason that mattered;
# 2% gave nearly every alert a reason, and higher bars added little but weaker reasons.
RARE_SHARE = 0.02

# Plain-English meaning of each measurement (definitions from the KDD Cup 1999 /
# NSL-KDD documentation). "Recent" = the 2 seconds before this connection;
# "last 100" = the 100 connections before it that went to the same destination machine.
FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "duration": "Length of the connection",
    "protocol_type": "Protocol",
    "service": "Network service on the destination",
    "flag": "Connection status",
    "src_bytes": "Data sent by the source",
    "dst_bytes": "Data sent back by the destination",
    "land": "Source and destination are the same machine and port",
    "wrong_fragment": "Malformed packet fragments",
    "urgent": "Urgent packets",
    "hot": "'Hot' actions (e.g. entering system folders, running programs)",
    "num_failed_logins": "Failed login attempts",
    "logged_in": "Login succeeded",
    "num_compromised": "'Compromised' conditions",
    "root_shell": "Administrator (root) shell obtained",
    "su_attempted": "'su root' command attempted",
    "num_root": "Administrator (root) accesses",
    "num_file_creations": "Files created",
    "num_shells": "Shell prompts opened",
    "num_access_files": "Operations on access-control files",
    "num_outbound_cmds": "Outbound commands in an FTP session",
    "is_host_login": "Login is on the 'hot' list",
    "is_guest_login": "Guest login",
    "count": "Connections to the same machine in the last 2 seconds",
    "srv_count": "Connections to the same service in the last 2 seconds",
    "serror_rate": "Recent connections to this machine left half-open (SYN errors)",
    "srv_serror_rate": "Recent connections to this service left half-open (SYN errors)",
    "rerror_rate": "Recent connections to this machine rejected",
    "srv_rerror_rate": "Recent connections to this service rejected",
    "same_srv_rate": "Recent connections to this machine using the same service",
    "diff_srv_rate": "Recent connections to this machine using different services",
    "srv_diff_host_rate": "Recent connections to this service going to different machines",
    "dst_host_count": "Of the last 100 connections, number going to this machine",
    "dst_host_srv_count": "Of the last 100 connections, number going to this machine and service",
    "dst_host_same_srv_rate": "Of the last 100 connections to this machine, share using the same service",
    "dst_host_diff_srv_rate": "Of the last 100 connections to this machine, share using different services",
    "dst_host_same_src_port_rate": "Of the last 100 connections to this machine, share from the same source port",
    "dst_host_srv_diff_host_rate": "Of the last 100 connections to this service, share going to different machines",
    "dst_host_serror_rate": "Of the last 100 connections to this machine, share left half-open",
    "dst_host_srv_serror_rate": "Of the last 100 connections to this service, share left half-open",
    "dst_host_rerror_rate": "Of the last 100 connections to this machine, share rejected",
    "dst_host_srv_rerror_rate": "Of the last 100 connections to this service, share rejected",
}

# What the connection-status codes mean (they come from the Bro/Zeek network monitor).
FLAG_MEANINGS = {
    "SF": "normal start and finish",
    "S0": "request sent, never answered - half-open",
    "S1": "connected, not closed",
    "S2": "connected, only the source tried to close",
    "S3": "connected, only the destination tried to close",
    "REJ": "connection refused",
    "RSTO": "source aborted the connection",
    "RSTR": "destination aborted the connection",
    "RSTOS0": "source sent a request and then aborted, no answer",
    "SH": "source sent a request and a close, no answer - a stealth scan pattern",
    "OTH": "no start of the connection was seen",
}

# Measurements that tell the same story; only the rarest one of each group is shown,
# so an analyst does not read "half-open" four times.
FEATURE_GROUPS = {
    "half_open": ["serror_rate", "srv_serror_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate"],
    "rejected": ["rerror_rate", "srv_rerror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"],
    "service_mix": ["same_srv_rate", "diff_srv_rate", "dst_host_same_srv_rate", "dst_host_diff_srv_rate"],
    "recent_volume": ["count", "srv_count"],
    "volume_last_100": ["dst_host_count", "dst_host_srv_count"],
    "spread": ["srv_diff_host_rate", "dst_host_srv_diff_host_rate"],
    "root_activity": ["num_root", "num_compromised"],
}
GROUP_OF = {f: g for g, members in FEATURE_GROUPS.items() for f in members}

YES_NO_COLUMNS = {"land", "logged_in", "root_shell", "is_host_login", "is_guest_login"}

MODEL_TITLES = {"isolation_forest": "Isolation Forest", "one_class_svm": "One-Class SVM",
                "random_forest": "Random Forest"}


def format_value(column: str, value) -> str:
    if column == "flag":
        return f"{value} = {FLAG_MEANINGS.get(str(value), 'unknown status')}"
    if column in CATEGORICAL_COLUMNS:
        return str(value)
    v = float(value)
    if column.endswith("_rate"):
        return f"{v:.0%}"
    if column in YES_NO_COLUMNS:
        return "yes" if v >= 1 else "no"
    if column in ("src_bytes", "dst_bytes"):
        return f"{v:,.0f} bytes"
    if column == "duration":
        return f"{v:,.0f} seconds"
    return f"{v:,.0f}"



class NormalProfile:
    """What normal traffic looks like, learned from the normal training connections."""

    def __init__(self, normal: pd.DataFrame, importance: Dict[str, float]):
        self.rows = int(len(normal))
        self.numeric = {}
        for column in NUMERIC_COLUMNS:
            v = normal[column].to_numpy(dtype=float)
            values, counts = np.unique(v, return_counts=True)
            self.numeric[column] = {
                "values": values,
                "cumulative": np.cumsum(counts),
                "p5": float(np.quantile(v, 0.05)),
                "median": float(np.median(v)),
                "p95": float(np.quantile(v, 0.95)),
            }
        self.categorical = {c: normal[c].value_counts(normalize=True).to_dict() for c in CATEGORICAL_COLUMNS}
        self.most_common = {c: str(normal[c].mode().iloc[0]) for c in CATEGORICAL_COLUMNS}
        # How much the Random Forest relies on each measurement (used to break ties).
        self.importance = importance

    def typical_value(self, column: str):
        """The value to use as 'normal' for this measurement."""
        if column in CATEGORICAL_COLUMNS:
            return self.most_common[column]
        return self.numeric[column]["median"]

    def typical_text(self, column: str) -> str:
        if column in CATEGORICAL_COLUMNS:
            return f"usually {format_value(column, self.most_common[column])}"
        s = self.numeric[column]
        low, high = format_value(column, s["p5"]), format_value(column, s["p95"])
        return f"usually {low}" if low == high else f"usually {low} to {high}"

    def rarity(self, column: str, x: np.ndarray):
        """For each value: (share of normal connections at least as extreme, direction)."""
        if column in CATEGORICAL_COLUMNS:
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
    description = FEATURE_DESCRIPTIONS[column]
    start = f"{description}: {format_value(column, value)} (normal: {profile.typical_text(column)})."
    how_many = "Fewer than 0.1%" if share < 0.001 else f"Only {share:.1%}"
    if direction == "unusual" or column in YES_NO_COLUMNS:
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
    shares, directions = {}, {}
    for column in FEATURE_COLUMNS:
        shares[column], directions[column] = profile.rarity(column, features[column].to_numpy())

    explanations = []
    for i in range(len(features)):
        candidates = [c for c in FEATURE_COLUMNS if shares[c][i] <= RARE_SHARE]
        candidates.sort(key=lambda c: (shares[c][i], -profile.importance.get(c, 0.0)))
        reasons, used_groups = [], set()
        for column in candidates:
            group = GROUP_OF.get(column, column)
            if group in used_groups:
                continue
            used_groups.add(group)
            value = features[column].iloc[i]
            share, direction = float(shares[column][i]), str(directions[column][i])
            reasons.append({
                "feature": column,
                "description": FEATURE_DESCRIPTIONS[column],
                "value": value if column in CATEGORICAL_COLUMNS else float(value),
                "normal": profile.typical_text(column),
                "share_of_normal": share,
                "direction": direction,
                "related_features": FEATURE_GROUPS.get(group, [column]),
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
