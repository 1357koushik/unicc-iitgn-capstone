"""
Turns an alert into something an analyst can act on (Task 5.0 asks for "clear,
actionable insights"). Every alert gets:

  * a likely attack type - the known attack family the connection most resembles.
    It comes from a separate classifier trained on labelled ATTACKS only (see
    NetworkSensorModel.fit); it does not change which connections are flagged.
  * a priority - High, Medium or Low: what is at stake, by a fixed rule:
        - a known-pattern alert gets the impact of its likely attack type (the
          dataset's family_impact): High = could give an attacker control of a
          machine, an account or data; Medium = could make a service unavailable;
          Low = information gathering only;
        - a possible new attack (raised only by the two anomaly models) is Medium:
          its type is unknown, so it is worth a look but not first in line.
    The rule is not learned, so an analyst can always see why an alert got its
    priority. The evaluation report shows how many alerts of each priority were
    real attacks.
  * a certainty - how sure the sensor is, shown next to the priority rather than
    mixed into it: the Random Forest is rarely sure about rare attack types (on a
    validation slice of the NSL-KDD training data, 1 of 11 U2R attacks scored 90% or
    more, against 99.8% of DoS attacks), so lowering the priority of unsure alerts
    would push exactly the rare, most damaging types down the list.
  * a suggested next step - one first action for that attack type (the dataset's
    family_actions), or a general one for a possible new attack.
"""
from typing import List, Optional, Sequence, Tuple

PRIORITIES = ("High", "Medium", "Low")
IMPACT_MEANINGS = {
    "High": "could give an attacker control of a machine, an account or data",
    "Medium": "could make a service unavailable",
    "Low": "information gathering only",
}
NEW_ATTACK_PRIORITY = "Medium"
NEW_ATTACK_STEP = ("This does not match any attack the sensor has learned. Look at the reasons above and at "
                   "the source's other recent connections, keep a copy of the traffic if you can, and "
                   "escalate if it repeats or the target is important.")


def retrain_hint(dataset: str) -> str:
    option = "" if dataset == "nsl_kdd" else f" --dataset {dataset}"
    return ("Not available: this sensor was trained before attack types were added. "
            f"Retrain it on the server: python -m network_sensor.train{option}")


def priority_of(known_pattern: bool, likely_type: Optional[str], spec) -> Tuple[str, str]:
    """(priority, the reason in plain English) for one alert, by the rule above."""
    if not known_pattern:
        return NEW_ATTACK_PRIORITY, ("it does not match a known attack pattern, but both anomaly models "
                                     "found it abnormal - its type is unknown")
    impact = spec.family_impact.get(likely_type)
    if impact is None:      # every family has an impact (a test checks it); just in case
        return "Medium", f"likely {likely_type}"
    if impact == "Low":
        return impact, f"likely {likely_type}: {IMPACT_MEANINGS[impact]}"
    return impact, f"likely {likely_type}, which {IMPACT_MEANINGS[impact]}"


def certainty_of(votes: dict, random_forest_score: float) -> str:
    """How sure the sensor is about an alert, in plain English."""
    anomaly_models = votes["isolation_forest"] + votes["one_class_svm"]
    if votes["random_forest"] == 0:
        return "Low: only the two anomaly models flagged it"
    if anomaly_models == 2:
        return f"High: all three models flagged it (Random Forest score {random_forest_score:.0%})"
    return f"Medium: the Random Forest flagged it (score {random_forest_score:.0%})" + (
        ", and one anomaly model found it unusual" if anomaly_models == 1 else "")


def add_actions(explanations: List[dict], types: Optional[Sequence[str]],
                confidences: Optional[Sequence[float]], spec) -> None:
    """Add attack_type, priority, priority_reason, certainty and next_step to every alert in
    `explanations` (in place). `types` / `confidences` hold one value per ALERT, in
    order; None if this sensor has no attack-type classifier (trained before it existed)."""
    k = 0
    for e in explanations:
        if e["verdict"] != "attack":
            continue
        known = e["votes"]["random_forest"] == 1
        if types is None:
            e["attack_type"] = None
            e["priority"] = None
            e["priority_reason"] = retrain_hint(spec.name)
            e["certainty"] = certainty_of(e["votes"], e["random_forest_score"])
            e["next_step"] = None
            continue
        likely, confidence = str(types[k]), float(confidences[k])
        k += 1
        e["attack_type"] = {"likely": likely, "confidence": confidence, "matches_known_pattern": known,
                            "meaning": spec.family_meanings.get(likely, "")}
        e["priority"], e["priority_reason"] = priority_of(known, likely, spec)
        e["certainty"] = certainty_of(e["votes"], e["random_forest_score"])
        e["next_step"] = spec.family_actions.get(likely, NEW_ATTACK_STEP) if known else NEW_ATTACK_STEP


def priority_rank(alert: dict) -> int:
    """For sorting: High first, then Medium, then Low, then alerts without a priority."""
    return PRIORITIES.index(alert["priority"]) if alert.get("priority") in PRIORITIES else len(PRIORITIES)


# Columns that say WHERE a connection came from and went to. CICFlowMeter's full output
# has them (the MachineLearningCSV files keep only the destination port); the models never
# use them, but if a file has them, each alert shows them so the analyst knows which
# machines to look at.
IDENTITY_COLUMNS = ("Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp")


def where_of(connections, row: int) -> Optional[dict]:
    """The identity columns of one connection (by position), or None if the file has none."""
    present = [c for c in IDENTITY_COLUMNS if c in connections.columns]
    if not present:
        return None
    return {c: str(connections[c].iat[row]).strip() for c in present}


def count_by(alerts: List[dict], key) -> List[dict]:
    """[{"name": ..., "alerts": n}, ...], most alerts first, for the dashboard's charts."""
    counts = {}
    for a in alerts:
        name = key(a)
        counts[name] = counts.get(name, 0) + 1
    return [{"name": n, "alerts": c} for n, c in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def type_label(alert: dict) -> str:
    """How an alert's type is shown in the 'alerts by type' chart."""
    t = alert.get("attack_type")
    if not t:
        return "Type not available"
    return t["likely"] if t["matches_known_pattern"] else "Possible new attack"


def summarise(alerts: List[dict]) -> dict:
    """Counts of ALL alerts by priority and by likely type (the list sent back may be cut short)."""
    by_priority = {p: 0 for p in PRIORITIES}
    for a in alerts:
        if a.get("priority") in by_priority:
            by_priority[a["priority"]] += 1
    return {"by_priority": [{"name": p, "alerts": n} for p, n in by_priority.items()],
            "by_type": count_by(alerts, type_label)}
