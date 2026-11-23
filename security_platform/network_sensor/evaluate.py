"""
Tests the trained sensor on a dataset's test part and writes a report.

This is the evidence for UNICC evaluation Task 5.0, which is scored on PRECISION
with an acceptable result of 90 (out of 100).

Usage (in the project folder, with the .venv switched on):
    python -m network_sensor.evaluate                         # NSL-KDD
    python -m network_sensor.evaluate --dataset cicids2017    # CIC-IDS2017

Writes  data/network_sensor/reports/evaluation_report.json  and  .md
(for CIC-IDS2017: data/network_sensor/reports/cicids2017/)
"""
import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd

from network_sensor.actions import IMPACT_MEANINGS, PRIORITIES, priority_of
from network_sensor.datasets import DatasetError
from network_sensor.explain import RARE_SHARE
from network_sensor.models import MODEL_NAMES, NetworkSensorModel, _library_versions
from network_sensor.paths import model_path, reports_dir
from network_sensor.spec import DATASETS, DEFAULT_DATASET, get_spec, load_split

TARGET_PRECISION = 0.90     # UNICC evaluation sheet, Task 5.0: acceptable outcome 90, scored on precision
MODEL_TITLES = {"isolation_forest": "Isolation Forest", "one_class_svm": "One-Class SVM",
                "random_forest": "Random Forest", "combined": "Combined sensor"}


def compute_metrics(y_true, y_pred) -> Dict[str, float]:
    """Counts and rates for one set of answers (1 = attack, 0 = normal)."""
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())   # attacks correctly flagged
    fp = int(((y_pred == 1) & (y_true == 0)).sum())   # normal traffic wrongly flagged (false alarms)
    fn = int(((y_pred == 0) & (y_true == 1)).sum())   # attacks missed
    tn = int(((y_pred == 0) & (y_true == 0)).sum())   # normal traffic correctly left alone

    def ratio(a, b):
        return a / b if b else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "f1": ratio(2 * precision * recall, precision + recall),
        "accuracy": ratio(tp + tn, len(y_true)),
        "false_alarm_rate": ratio(fp, fp + tn),
        "true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
    }


def _detection(flagged: np.ndarray) -> Dict[str, float]:
    return {"attacks": int(len(flagged)), "detected": int(flagged.sum()),
            "detection_rate": float(flagged.mean()) if len(flagged) else 0.0}


def explanation_check(model: NetworkSensorModel, test_df: pd.DataFrame, explanations: list,
                      seed: int = 0) -> dict:
    """Are the explanations TRUE? For every alert that has reasons, reset the measurements
    named as reasons to their typical normal value and ask the sensor again. Then do the
    same with an equal number of OTHER, randomly chosen measurements. If the reasons point
    at what really drives the alert, far more alerts disappear in the first case."""
    alerts = [i for i, e in enumerate(explanations) if e["verdict"] == "attack"]
    checked = [i for i in alerts if explanations[i]["reasons"]]
    if not checked:
        return {"alerts": len(alerts), "alerts_with_reasons": 0}

    profile = model.normal_profile
    columns = list(model.spec.feature_columns)
    position = {c: k for k, c in enumerate(columns)}
    original = test_df.iloc[checked][columns].to_numpy(dtype=object)
    reset_reasons, reset_random = original.copy(), original.copy()
    rng = np.random.default_rng(seed)
    n_reset = []
    for row, i in enumerate(checked):
        named = sorted({f for r in explanations[i]["reasons"] for f in r["related_features"]})
        others = [c for c in columns if c not in named]
        for column in named:
            reset_reasons[row, position[column]] = profile.typical_value(column)
        for column in rng.choice(others, size=len(named), replace=False):
            reset_random[row, position[column]] = profile.typical_value(column)
        n_reset.append(len(named))

    def still_flagged(values):
        return model.predict(pd.DataFrame(values, columns=columns))

    return {
        "alerts": len(alerts),
        "alerts_with_reasons": len(checked),
        "measurements_reset_on_average": float(np.mean(n_reset)),
        "cleared_when_reasons_reset": float(1 - still_flagged(reset_reasons).mean()),
        "cleared_when_random_reset": float(1 - still_flagged(reset_random).mean()),
    }


def measure_speed(model: NetworkSensorModel, test_df: pd.DataFrame, batch_sizes=(1, 100, 1000),
                  repeats: int = 5) -> dict:
    """How long the sensor takes to check (and explain) connections on THIS computer.
    Live mode checks each second's arrivals as one batch, so the 1,000 row tells how
    much of each second a 1,000-connections-per-second feed uses."""
    model.explain(test_df.head(5))                                   # warm-up
    rows = []
    for n in batch_sizes:
        n = min(n, len(test_df))
        timings = []
        for k in range(repeats):
            start = (k * n) % max(1, len(test_df) - n + 1)
            batch = test_df.iloc[start:start + n]
            started = time.perf_counter()
            model.explain(batch)
            timings.append(time.perf_counter() - started)
        seconds = statistics.median(timings)
        rows.append({"batch_size": n, "batch_ms": round(seconds * 1000, 1),
                     "ms_per_connection": round(seconds * 1000 / n, 2),
                     "connections_per_second": int(n / seconds) if seconds > 0 else 0})
    return {"processor_cores": os.cpu_count(), "measurements": rows}


def sample_per_label(df: pd.DataFrame, per_label: int, seed: int = 0) -> pd.DataFrame:
    """Up to `per_label` randomly chosen rows of each label (all rows of rarer labels),
    in their original order. Used where checking every row would take too long or too
    much memory; keeping every label means rare attack types are still represented."""
    parts = [group.sample(n=min(per_label, len(group)), random_state=seed)
             for _, group in df.groupby("label", sort=True)]
    return pd.concat(parts).sort_index()


def actionable_check(model: NetworkSensorModel, test_df: pd.DataFrame, votes: pd.DataFrame,
                     combined: np.ndarray) -> Optional[dict]:
    """How useful are the actionable parts of the alerts (see actions.py)?
      * likely attack type: for every alert on a real attack, is the named family right?
      * priority: for each priority level, how many alerts were real attacks?
    Uses every flagged connection of the test part. None for sensors trained before
    the attack-type classifier existed."""
    if not model.has_attack_types:
        return None
    spec = model.spec
    flagged = combined == 1
    _, X = model._checked_matrix(test_df[flagged])
    types, _ = model.attack_types_of_matrix(X)
    del X
    known = votes["random_forest"].to_numpy()[flagged] == 1
    truth = test_df["attack_category"].to_numpy()[flagged]
    real = test_df["is_attack"].to_numpy()[flagged] == 1
    labels = test_df["label"].to_numpy()[flagged]
    seen_types = set(model.training_info.get("attack_types_seen_in_training", []))
    has_family = real & (truth != "unknown")
    correct = types == truth

    def accuracy(mask) -> dict:
        n = int(mask.sum())
        return {"alerts": n, "type_correct": int((correct & mask).sum()),
                "rate": float((correct & mask).sum() / n) if n else 0.0}

    by_family = []
    for family in spec.families:
        mask = has_family & known & (truth == family)
        wrong = pd.Series(types[mask & ~correct], dtype=object).value_counts()
        by_family.append({"family": family, **accuracy(mask),
                          "most_common_wrong_answer": (str(wrong.index[0]) if len(wrong) else None),
                          "wrong_answers": int(wrong.sum())})
    never_seen = has_family & ~np.isin(labels, list(seen_types))
    priorities = np.array([priority_of(k, t, spec)[0] for k, t in zip(known, types)])
    by_priority = []
    for level in PRIORITIES:
        mask = priorities == level
        n, attacks = int(mask.sum()), int((mask & real).sum())
        by_priority.append({"priority": level, "alerts": n, "real_attacks": attacks, "false_alarms": n - attacks,
                            "precision": attacks / n if n else 0.0})
    return {
        "type_of_known_pattern_alerts": {**accuracy(has_family & known), "by_family": by_family},
        "closest_type_of_possible_new_attacks": accuracy(has_family & ~known),
        "type_of_never_seen_attack_types": accuracy(never_seen) if never_seen.any() else None,
        "by_priority": by_priority,
        "rule": {"impact": {f: spec.family_impact.get(f) for f in spec.families}},
    }


def evaluate_model(model: NetworkSensorModel, test_df: pd.DataFrame,
                   explain_per_label: Optional[int] = None) -> dict:
    """Score the sensor on test_df (which needs label, is_attack and attack_category).

    The precision and recall numbers always use every connection. Explanations are kept
    in memory, so for very large test sets explain_per_label limits them to that many
    connections of each label (see sample_per_label); None = explain every connection."""
    spec = model.spec
    y = test_df["is_attack"].to_numpy()
    if explain_per_label is None:
        explained = test_df
        explanations = model.explain(test_df)
        votes = pd.DataFrame([e["votes"] for e in explanations], index=test_df.index)
    else:
        votes = model.votes(test_df)
        explained = sample_per_label(test_df, explain_per_label)
        explanations = model.explain(explained)
    combined = model.combine(votes)
    explained_flags = np.array([1 if e["verdict"] == "attack" else 0 for e in explanations])

    results = {name: compute_metrics(y, votes[name]) for name in MODEL_NAMES}
    results["combined"] = compute_metrics(y, combined)

    attacks = test_df["is_attack"].to_numpy() == 1
    by_category = {}
    for category in spec.families:
        mask = (test_df["attack_category"] == category).to_numpy()
        by_category[category] = _detection(combined[mask])

    seen_types = set(model.training_info.get("attack_types_seen_in_training", []))
    seen = test_df["label"].isin(seen_types).to_numpy()
    seen_vs_unseen = {
        "seen_in_training": _detection(combined[attacks & seen]),
        "never_seen_in_training": _detection(combined[attacks & ~seen]),
        "never_seen_attack_types": sorted(set(test_df.loc[attacks & ~seen, "label"])),
    }

    missed = (pd.Series(combined[attacks] == 0, index=test_df.index[attacks])
              .groupby(test_df.loc[attacks, "label"]).agg(["sum", "count"]))
    most_missed = [
        {"attack_type": label, "missed": int(row["sum"]), "total": int(row["count"]),
         "seen_in_training": label in seen_types}
        for label, row in missed.sort_values("sum", ascending=False).head(8).iterrows()
        if row["sum"] > 0
    ]

    # Which measurement is most often the main reason, per attack family (caught attacks only).
    main_reasons = {}
    examples = {}
    for category in spec.families:
        rows = [k for k in range(len(explained))
                if explained["attack_category"].iat[k] == category and explained_flags[k] == 1]
        firsts = pd.Series([explanations[k]["reasons"][0]["feature"] if explanations[k]["reasons"]
                            else "(no single unusual measurement)" for k in rows], dtype=object)
        main_reasons[category] = [{"feature": f, "description": spec.descriptions.get(f, f),
                                   "share_of_caught": float(n / len(rows))}
                                  for f, n in firsts.value_counts().head(3).items()] if rows else []
        if rows:
            examples[category] = {"attack_type": explained["label"].iat[rows[0]], **explanations[rows[0]]}
    explained_y = explained["is_attack"].to_numpy()
    false_alarms = [k for k in range(len(explained)) if explained_y[k] == 0 and explained_flags[k] == 1]
    if false_alarms:
        examples["False alarm"] = {"attack_type": spec.normal_label, **explanations[false_alarms[0]]}

    check = explanation_check(model, explained, explanations)
    actionable = actionable_check(model, test_df, votes, combined)
    if explain_per_label is not None:
        check["sample"] = (f"Checked on up to {explain_per_label:,} connections of each label "
                           f"({len(explained):,} connections in total).")

    achieved = results["combined"]["precision"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": f"{spec.title}, {spec.test_description}",
        "dataset_name": spec.name,
        "test_rows": int(len(y)),
        "test_attacks": int(attacks.sum()),
        "test_normal": int((~attacks).sum()),
        "criterion": {"source": "UNICC evaluation sheet, Task 5.0 (Network security AI sensor)",
                      "metric": "precision", "target": TARGET_PRECISION,
                      "achieved": achieved, "passed": achieved >= TARGET_PRECISION},
        "decision_rule": model.training_info.get("decision_rule"),
        "models": results,
        "family_meanings": {family: spec.family_meanings[family] for family in spec.families},
        "by_attack_category": by_category,
        "seen_vs_unseen": seen_vs_unseen,
        "most_missed_attack_types": most_missed,
        "explanations": {
            "check": check,
            "main_reasons_by_family": main_reasons,
            "examples": examples,
        },
        "actionable": actionable,
        "limitations": list(spec.limitations),
        "training_info": model.training_info,
        "library_versions": _library_versions(),
    }


def new_attack_check(dataset: str, train_df: pd.DataFrame, test_df: pd.DataFrame,
                     normal_sample: int = 50_000, settings=None, seed: int = 0, progress=None) -> dict:
    """Can the sensor catch an attack family it has NEVER seen? For each family: train a
    fresh sensor on the training data WITHOUT that family, then count how many of the
    family's test connections it flags (and which models flagged them), and how many
    normal test connections it wrongly flags (on a random sample of normal traffic)."""
    spec = get_spec(dataset)
    normal = test_df[test_df["is_attack"] == 0]
    if len(normal) > normal_sample:
        normal = normal.sample(n=normal_sample, random_state=seed)
    rows = []
    for family in spec.families:
        family_test = test_df[test_df["attack_category"] == family]
        in_training = train_df["attack_category"] == family
        if len(family_test) == 0 or not in_training.any():
            continue
        if progress:
            progress(family)
        model = NetworkSensorModel(settings, dataset=dataset).fit(train_df[~in_training])
        votes = model.votes(family_test)
        flagged = model.combine(votes).astype(bool)
        rf = votes["random_forest"].to_numpy().astype(bool)
        false_alarms = model.predict(normal)
        rows.append({
            "family": family,
            "attack_types": sorted(family_test["label"].unique()),
            "test_attacks": int(len(family_test)),
            "caught": int(flagged.sum()),
            "detection_rate": float(flagged.mean()),
            "caught_by_random_forest": int((flagged & rf).sum()),
            "caught_only_by_anomaly_models": int((flagged & ~rf).sum()),
            "false_alarm_rate": float(false_alarms.mean()),
        })
    return {"normal_connections_checked": int(len(normal)), "families": rows}


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def render_markdown(r: dict) -> str:
    c = r["criterion"]
    verdict = "PASSED" if c["passed"] else "NOT MET"
    lines = [
        "# Network Sensor - Evaluation Report (Task 5.0)",
        "",
        f"Generated {r['generated_at']} on {r['dataset']}: {r['test_rows']:,} connections "
        f"({r['test_attacks']:,} attacks, {r['test_normal']:,} normal).",
        "",
        f"**Criterion:** precision of at least {_pct(c['target'])} - source: {c['source']}.  ",
        f"**Result:** {_pct(c['achieved'])} - **{verdict}**",
        "",
        f"Decision rule: `{r['decision_rule']}`",
        "",
        "## Each model and the combined sensor",
        "",
        "| Model | Precision | Recall (attacks caught) | F1 | False alarm rate | Attacks caught | False alarms | Attacks missed |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for name in list(MODEL_NAMES) + ["combined"]:
        m = r["models"][name]
        title = f"**{MODEL_TITLES[name]}**" if name == "combined" else MODEL_TITLES[name]
        lines.append(f"| {title} | {_pct(m['precision'])} | {_pct(m['recall'])} | {m['f1']:.3f} | "
                     f"{_pct(m['false_alarm_rate'])} | {m['true_positives']:,} | {m['false_positives']:,} | "
                     f"{m['false_negatives']:,} |")
    lines += ["", "## Attacks caught by family (combined sensor)", "",
              "| Family | What it is | Attacks | Caught | Rate |", "|---|---|---|---|---|"]
    meaning = r["family_meanings"]
    for cat, d in r["by_attack_category"].items():
        lines.append(f"| {cat} | {meaning[cat]} | {d['attacks']:,} | {d['detected']:,} | {_pct(d['detection_rate'])} |")

    s = r["seen_vs_unseen"]
    lines += ["", "## Known vs brand-new attack types (combined sensor)", ""]
    if s["never_seen_attack_types"]:
        lines += ["| Attack types | Attacks | Caught | Rate |", "|---|---|---|---|",
                  f"| Seen during training | {s['seen_in_training']['attacks']:,} | "
                  f"{s['seen_in_training']['detected']:,} | {_pct(s['seen_in_training']['detection_rate'])} |",
                  f"| Never seen during training | {s['never_seen_in_training']['attacks']:,} | "
                  f"{s['never_seen_in_training']['detected']:,} | {_pct(s['never_seen_in_training']['detection_rate'])} |",
                  "", f"Attack types that appear only in the test file: {', '.join(s['never_seen_attack_types'])}."]
    else:
        lines.append("Every attack type in the test part also appears in the training part. How the sensor "
                     "does on attack types it has never seen is checked separately (see 'New attack types').")
    if r["most_missed_attack_types"]:
        lines += ["", "## Most-missed attack types", "", "| Attack type | Missed | Of | Seen in training? |",
                  "|---|---|---|---|"]
        for m in r["most_missed_attack_types"]:
            lines.append(f"| {m['attack_type']} | {m['missed']:,} | {m['total']:,} | "
                         f"{'yes' if m['seen_in_training'] else 'no'} |")
    new = r.get("new_attack_check")
    if new and new["families"]:
        lines += ["", "## New attack types (trained without them)", "",
                  "For each family, a fresh sensor was trained on the training part WITHOUT that family, "
                  "so the family is as new to it as a never-seen attack would be. Then it checked the "
                  "family's test connections, and a random sample of "
                  f"{new['normal_connections_checked']:,} normal test connections for false alarms.", "",
                  "| Family (never seen) | Attacks | Caught | Rate | By Random Forest | Only by anomaly models | "
                  "False alarm rate |", "|---|---|---|---|---|---|---|"]
        for f in new["families"]:
            lines.append(f"| {f['family']} | {f['test_attacks']:,} | {f['caught']:,} | {_pct(f['detection_rate'])} | "
                         f"{f['caught_by_random_forest']:,} | {f['caught_only_by_anomaly_models']:,} | "
                         f"{_pct(f['false_alarm_rate'])} |")
        lines += ["", "'By Random Forest' means the new attack still resembled other attack families it "
                      "knew; 'only by anomaly models' are catches that come purely from it looking abnormal."]
    ex = r["explanations"]
    check = ex["check"]
    lines += ["", "## Explanations", "",
              f"Every alert lists up to 3 measurements that are rare in normal traffic (seen in at most "
              f"{RARE_SHARE:.0%} of normal connections) and which models raised it. The {RARE_SHARE:.0%} "
              "bar was chosen on training data, not on this test file."]
    if check.get("sample"):
        lines += ["", check["sample"]]
    if check.get("alerts_with_reasons"):
        lines += [
            "", "**Are the explanations true?** For each alert, the measurements named as reasons "
            "were reset to their typical normal values and the sensor was asked again. As a "
            "comparison, the same number of other, randomly chosen measurements were reset instead.", "",
            "| | Share |", "|---|---|",
            f"| Alerts that name at least one reason | {_pct(check['alerts_with_reasons'] / check['alerts'])} "
            f"({check['alerts_with_reasons']:,} of {check['alerts']:,}) |",
            f"| Alerts that disappear when the **named reasons** are reset | "
            f"{_pct(check['cleared_when_reasons_reset'])} |",
            f"| Alerts that disappear when **random other** measurements are reset | "
            f"{_pct(check['cleared_when_random_reset'])} |",
            "", f"On average {check['measurements_reset_on_average']:.1f} measurements were reset per alert. "
            "Measurements that tell the same story (e.g. several rates of the same event) are reset together.",
        ]
    lines += ["", "**Most common main reason, per attack family:**", "",
              "| Family | Main reason (share of caught attacks) |", "|---|---|"]
    for cat in r["by_attack_category"]:
        items = ex["main_reasons_by_family"].get(cat, [])
        text = "; ".join(f"{i.get('description', i['feature'])} ({_pct(i['share_of_caught'])})"
                         for i in items) or "-"
        lines.append(f"| {cat} | {text} |")
    lines += ["", "**Examples** (the first caught attack of each family, and the first false alarm):"]
    for name, e in ex["examples"].items():
        lines += ["", f"*{name} - {e['attack_type']}* (raised by: {', '.join(e['flagged_by'])})", "",
                  f"> {e['decision']}"]
        lines += [f"> - {reason['text']}" for reason in e["reasons"]]
        if e.get("priority"):
            lines += [">", f"> **Priority {e['priority']}** ({e['priority_reason']}). "
                           f"**Certainty:** {e['certainty']}. **Next step:** {e['next_step']}"]

    act = r.get("actionable")
    if act:
        t = act["type_of_known_pattern_alerts"]
        lines += ["", "## Actionable alerts: likely attack type and priority", "",
                  "Every alert also names its **likely attack type** (from a separate classifier trained on the "
                  "labelled attacks only - it does not change which connections are flagged), a **priority** "
                  "and a **suggested next step** for that type.", "",
                  f"**Is the likely attack type right?** For known-pattern alerts on real attacks: "
                  f"{_pct(t['rate'])} ({t['type_correct']:,} of {t['alerts']:,}).", "",
                  "| Family | Alerts on this family | Type named correctly | Wrong | Most common wrong answer |",
                  "|---|---|---|---|---|"]
        for f in t["by_family"]:
            if f["alerts"]:
                lines.append(f"| {f['family']} | {f['alerts']:,} | {_pct(f['rate'])} | {f['wrong_answers']:,} | "
                             f"{f['most_common_wrong_answer'] or '-'} |")
        new_t = act["closest_type_of_possible_new_attacks"]
        if new_t["alerts"]:
            lines += ["", f"For possible new attacks (raised only by the anomaly models) the type is shown as the "
                          f"*closest* known type, with low certainty: it was right for {_pct(new_t['rate'])} "
                          f"of those that were real attacks ({new_t['type_correct']:,} of {new_t['alerts']:,})."]
        unseen = act.get("type_of_never_seen_attack_types")
        if unseen and unseen["alerts"]:
            lines += ["", f"For caught attacks of types never seen in training, the family was still named "
                          f"correctly for {_pct(unseen['rate'])} ({unseen['type_correct']:,} of {unseen['alerts']:,})."]
        impact = act["rule"]["impact"]
        lines += ["", "**Priority rule** (fixed in advance, not learned): start from what the likely attack type "
                      "could do - " + "; ".join(f"{level}: {', '.join(f for f in impact if impact[f] == level)} "
                                               f"({IMPACT_MEANINGS[level]})"
                                               for level in PRIORITIES if any(v == level for v in impact.values()))
                  + "; possible new attacks are Medium. The sensor's certainty is shown separately on each "
                    "alert, not mixed into the priority.", "",
                  "| Priority | Alerts | Real attacks | False alarms | Precision |", "|---|---|---|---|---|"]
        for p in act["by_priority"]:
            lines.append(f"| {p['priority']} | {p['alerts']:,} | {p['real_attacks']:,} | {p['false_alarms']:,} | "
                         f"{_pct(p['precision']) if p['alerts'] else '-'} |")

    speed = r.get("speed")
    if speed:
        lines += ["", "## Speed (real-time capacity)", "",
                  f"Measured on the computer that made this report ({speed['processor_cores']} processor cores). "
                  "Times include the plain-English explanations. Live mode checks each second's "
                  "arrivals together as one batch.", "",
                  "| Connections checked together | Time | Per connection | Connections per second |",
                  "|---|---|---|---|"]
        for m in speed["measurements"]:
            lines.append(f"| {m['batch_size']:,} | {m['batch_ms']:,} ms | {m['ms_per_connection']} ms | "
                         f"{m['connections_per_second']:,} |")
        biggest = speed["measurements"][-1]
        lines += ["", f"So one second of traffic at {biggest['batch_size']:,} connections per second takes about "
                      f"{biggest['batch_ms']:,} ms to check: alerts appear within about a second of the "
                      "connection arriving, as long as this stays below 1,000 ms."]

    lines += [
        "", "## How to read this", "",
        "- **Precision** - of everything the sensor flagged, the share that really were attacks. "
        "This is the Task 5.0 score.",
        "- **Recall** - of all real attacks, the share the sensor caught.",
        "- **False alarm rate** - of all normal connections, the share wrongly flagged.",
        "- **Random Forest score** - the share of its decision trees that voted 'attack'. Use it to "
        "rank alerts; it is not a guaranteed probability (false alarms can score 99%).",
        "", "## Limitations (state these when presenting)", "",
    ]
    lines += [f"- {limitation}" for limitation in r["limitations"]]
    info = r["training_info"]
    lines += ["", f"Trained {info.get('trained_at')} on {info.get('training_rows', 0):,} connections"
                  + (f" ({info['sample']['note']})" if info.get("sample") else "") + ". "
              "Library versions: " + ", ".join(f"{k} {v}" for k, v in r["library_versions"].items()) + ".",
              ""]
    return "\n".join(lines)


def write_reports(results: dict, folder: Path) -> Tuple[Path, Path]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / "evaluation_report.json"
    md_path = folder / "evaluation_report.md"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(results), encoding="utf-8")
    return json_path, md_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Score the trained network sensor on a dataset's test part.")
    parser.add_argument("--dataset", choices=DATASETS, default=DEFAULT_DATASET,
                        help="which dataset to test on (default: nsl_kdd)")
    parser.add_argument("--skip-new-attack-check", action="store_true",
                        help="CIC-IDS2017 only: skip retraining without each attack family (saves time)")
    args = parser.parse_args(argv)
    dataset, spec = args.dataset, get_spec(args.dataset)
    try:
        model = NetworkSensorModel.load(model_path(dataset), dataset=dataset)
        test = load_split(dataset, "test")
    except (FileNotFoundError, DatasetError, ValueError) as e:
        print(f"ERROR: {e}")
        return 1
    print(f"Checking {len(test):,} {spec.title} test connections ...")
    results = evaluate_model(model, test, explain_per_label=spec.explain_per_label)
    print("Measuring speed ...")
    results["speed"] = measure_speed(model, test)
    if spec.new_attack_check and not args.skip_new_attack_check:
        train = load_split(dataset, "train")
        print(f"New-attack check: training {len(spec.families)} more sensors, each without one attack family "
              "(this takes a while) ...")
        results["new_attack_check"] = new_attack_check(
            dataset, train, test, progress=lambda family: print(f"  without {family} ..."))

    print(f"\n{'Model':<18}{'Precision':>11}{'Recall':>9}{'False alarms':>14}")
    for name in list(MODEL_NAMES) + ["combined"]:
        m = results["models"][name]
        print(f"{MODEL_TITLES[name]:<18}{_pct(m['precision']):>11}{_pct(m['recall']):>9}"
              f"{m['false_positives']:>14,}")
    s = results["seen_vs_unseen"]
    if s["never_seen_in_training"]["attacks"]:
        print(f"\nAttacks caught - known types: {_pct(s['seen_in_training']['detection_rate'])}, "
              f"brand-new types: {_pct(s['never_seen_in_training']['detection_rate'])}")
    for f in results.get("new_attack_check", {}).get("families", []):
        print(f"Never-seen {f['family']:<14} caught {_pct(f['detection_rate']):>6}   "
              f"(false alarms {_pct(f['false_alarm_rate'])})")
    check = results["explanations"]["check"]
    if check.get("alerts_with_reasons"):
        print(f"Explanation check - alerts that disappear when the named reasons are reset: "
              f"{_pct(check['cleared_when_reasons_reset'])} (random other measurements: "
              f"{_pct(check['cleared_when_random_reset'])})")
    act = results.get("actionable")
    if act:
        t = act["type_of_known_pattern_alerts"]
        print(f"Likely attack type right for {_pct(t['rate'])} of known-pattern alerts on real attacks; "
              "precision by priority: " + ", ".join(f"{p['priority']} {_pct(p['precision'])} ({p['alerts']:,})"
                                                    for p in act["by_priority"] if p["alerts"]))
    fastest = results["speed"]["measurements"][-1]
    print(f"Speed - {fastest['batch_size']:,} connections checked together in {fastest['batch_ms']:,} ms "
          f"(about {fastest['connections_per_second']:,} per second on this computer)")
    c = results["criterion"]
    print(f"\nTask 5.0 target: precision >= {_pct(c['target'])}   "
          f"result: {_pct(c['achieved'])}   {'PASSED' if c['passed'] else 'NOT MET'}")

    json_path, md_path = write_reports(results, reports_dir(dataset))
    print(f"\nFull report: {md_path}\n             {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
