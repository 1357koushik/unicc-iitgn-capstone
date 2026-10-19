"""
Tests the trained sensor on the official NSL-KDD test file and writes a report.

This is the evidence for UNICC evaluation Task 5.0, which is scored on PRECISION
with an acceptable result of 90 (out of 100).

Usage (in the project folder, with the .venv switched on):
    python -m network_sensor.evaluate

Writes  data/network_sensor/reports/evaluation_report.json  and  .md
"""
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import pandas as pd

from network_sensor.datasets import FEATURE_COLUMNS, DatasetError, load_nsl_kdd
from network_sensor.explain import FEATURE_DESCRIPTIONS, RARE_SHARE
from network_sensor.models import MODEL_NAMES, NetworkSensorModel, _library_versions
from network_sensor.paths import model_path, reports_dir

TARGET_PRECISION = 0.90     # UNICC evaluation sheet, Task 5.0: acceptable outcome 90, scored on precision
CATEGORY_ORDER = ["DoS", "Probe", "R2L", "U2R"]
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
    position = {c: k for k, c in enumerate(FEATURE_COLUMNS)}
    original = test_df.iloc[checked][FEATURE_COLUMNS].to_numpy(dtype=object)
    reset_reasons, reset_random = original.copy(), original.copy()
    rng = np.random.default_rng(seed)
    n_reset = []
    for row, i in enumerate(checked):
        named = sorted({f for r in explanations[i]["reasons"] for f in r["related_features"]})
        others = [c for c in FEATURE_COLUMNS if c not in named]
        for column in named:
            reset_reasons[row, position[column]] = profile.typical_value(column)
        for column in rng.choice(others, size=len(named), replace=False):
            reset_random[row, position[column]] = profile.typical_value(column)
        n_reset.append(len(named))

    def still_flagged(values):
        return model.predict(pd.DataFrame(values, columns=FEATURE_COLUMNS))

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


def evaluate_model(model: NetworkSensorModel, test_df: pd.DataFrame) -> dict:
    y = test_df["is_attack"].to_numpy()
    explanations = model.explain(test_df)
    votes = pd.DataFrame([e["votes"] for e in explanations], index=test_df.index)
    combined = model.combine(votes)

    results = {name: compute_metrics(y, votes[name]) for name in MODEL_NAMES}
    results["combined"] = compute_metrics(y, combined)

    attacks = test_df["is_attack"].to_numpy() == 1
    by_category = {}
    for category in CATEGORY_ORDER:
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
    for category in CATEGORY_ORDER:
        rows = [k for k in range(len(test_df))
                if test_df["attack_category"].iat[k] == category and combined[k] == 1]
        firsts = pd.Series([explanations[k]["reasons"][0]["feature"] if explanations[k]["reasons"]
                            else "(no single unusual measurement)" for k in rows], dtype=object)
        main_reasons[category] = [{"feature": f, "share_of_caught": float(n / len(rows))}
                                  for f, n in firsts.value_counts().head(3).items()] if rows else []
        if rows:
            examples[category] = {"attack_type": test_df["label"].iat[rows[0]], **explanations[rows[0]]}
    false_alarms = [k for k in range(len(test_df)) if y[k] == 0 and combined[k] == 1]
    if false_alarms:
        examples["False alarm"] = {"attack_type": "normal", **explanations[false_alarms[0]]}

    achieved = results["combined"]["precision"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": "NSL-KDD, official test file KDDTest+.txt",
        "test_rows": int(len(y)),
        "test_attacks": int(attacks.sum()),
        "test_normal": int((~attacks).sum()),
        "criterion": {"source": "UNICC evaluation sheet, Task 5.0 (Network security AI sensor)",
                      "metric": "precision", "target": TARGET_PRECISION,
                      "achieved": achieved, "passed": achieved >= TARGET_PRECISION},
        "decision_rule": model.training_info.get("decision_rule"),
        "models": results,
        "by_attack_category": by_category,
        "seen_vs_unseen": seen_vs_unseen,
        "most_missed_attack_types": most_missed,
        "explanations": {
            "check": explanation_check(model, test_df, explanations),
            "main_reasons_by_family": main_reasons,
            "examples": examples,
        },
        "training_info": model.training_info,
        "library_versions": _library_versions(),
    }


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
    meaning = {"DoS": "flooding a service so real users cannot reach it",
               "Probe": "scanning for machines and open ports",
               "R2L": "an outsider trying to get in, e.g. guessing passwords",
               "U2R": "a logged-in user trying to become administrator"}
    for cat in CATEGORY_ORDER:
        d = r["by_attack_category"][cat]
        lines.append(f"| {cat} | {meaning[cat]} | {d['attacks']:,} | {d['detected']:,} | {_pct(d['detection_rate'])} |")

    s = r["seen_vs_unseen"]
    lines += ["", "## Known vs brand-new attack types (combined sensor)", "",
              "| Attack types | Attacks | Caught | Rate |", "|---|---|---|---|",
              f"| Seen during training | {s['seen_in_training']['attacks']:,} | "
              f"{s['seen_in_training']['detected']:,} | {_pct(s['seen_in_training']['detection_rate'])} |",
              f"| Never seen during training | {s['never_seen_in_training']['attacks']:,} | "
              f"{s['never_seen_in_training']['detected']:,} | {_pct(s['never_seen_in_training']['detection_rate'])} |",
              "", f"Attack types that appear only in the test file: {', '.join(s['never_seen_attack_types'])}."]
    if r["most_missed_attack_types"]:
        lines += ["", "## Most-missed attack types", "", "| Attack type | Missed | Of | Seen in training? |",
                  "|---|---|---|---|"]
        for m in r["most_missed_attack_types"]:
            lines.append(f"| {m['attack_type']} | {m['missed']:,} | {m['total']:,} | "
                         f"{'yes' if m['seen_in_training'] else 'no'} |")
    ex = r["explanations"]
    check = ex["check"]
    lines += ["", "## Explanations", "",
              f"Every alert lists up to 3 measurements that are rare in normal traffic (seen in at most "
              f"{RARE_SHARE:.0%} of normal connections) and which models raised it. The {RARE_SHARE:.0%} "
              "bar was chosen on training data, not on this test file."]
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
            "Measurements that tell the same story (e.g. the four 'half-open' rates) are reset together.",
        ]
    lines += ["", "**Most common main reason, per attack family:**", "",
              "| Family | Main reason (share of caught attacks) |", "|---|---|"]
    for cat in CATEGORY_ORDER:
        items = ex["main_reasons_by_family"].get(cat, [])
        text = "; ".join(f"{FEATURE_DESCRIPTIONS.get(i['feature'], i['feature'])} ({_pct(i['share_of_caught'])})"
                         for i in items) or "-"
        lines.append(f"| {cat} | {text} |")
    lines += ["", "**Examples** (the first caught attack of each family, and the first false alarm):"]
    for name, e in ex["examples"].items():
        lines += ["", f"*{name} - {e['attack_type']}* (raised by: {', '.join(e['flagged_by'])})", "",
                  f"> {e['decision']}"]
        lines += [f"> - {reason['text']}" for reason in e["reasons"]]

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
        "- NSL-KDD is built from 1998 network traffic. It is the standard public benchmark, but "
        "modern traffic looks different; a newer dataset (CIC-IDS2017) is planned.",
        "- The 41 measurements come with the dataset. The sensor does not yet compute them from "
        "live network traffic itself.",
        "- The test file deliberately contains attack types that are not in the training file, "
        "which is why recall is lower than precision.",
        "- Settings (anomaly share, tree counts) were fixed in advance and not tuned on the test file. "
        "The decision rule was chosen after an initial comparison of a few combinations on this same "
        "test file, so a fully independent check would use a second dataset.",
        "", f"Trained {r['training_info'].get('trained_at')} on {r['training_info'].get('training_rows', 0):,} "
        f"connections. Library versions: " + ", ".join(f"{k} {v}" for k, v in r["library_versions"].items()) + ".",
        "",
    ]
    return "\n".join(lines)


def write_reports(results: dict, folder: Path) -> Tuple[Path, Path]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / "evaluation_report.json"
    md_path = folder / "evaluation_report.md"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(results), encoding="utf-8")
    return json_path, md_path


def main() -> int:
    try:
        model = NetworkSensorModel.load(model_path())
        test = load_nsl_kdd("test")
    except (FileNotFoundError, DatasetError, ValueError) as e:
        print(f"ERROR: {e}")
        return 1
    print(f"Checking {len(test):,} test connections ...")
    results = evaluate_model(model, test)
    print("Measuring speed ...")
    results["speed"] = measure_speed(model, test)

    print(f"\n{'Model':<18}{'Precision':>11}{'Recall':>9}{'False alarms':>14}")
    for name in list(MODEL_NAMES) + ["combined"]:
        m = results["models"][name]
        print(f"{MODEL_TITLES[name]:<18}{_pct(m['precision']):>11}{_pct(m['recall']):>9}"
              f"{m['false_positives']:>14,}")
    s = results["seen_vs_unseen"]
    print(f"\nAttacks caught - known types: {_pct(s['seen_in_training']['detection_rate'])}, "
          f"brand-new types: {_pct(s['never_seen_in_training']['detection_rate'])}")
    check = results["explanations"]["check"]
    if check.get("alerts_with_reasons"):
        print(f"Explanation check - alerts that disappear when the named reasons are reset: "
              f"{_pct(check['cleared_when_reasons_reset'])} (random other measurements: "
              f"{_pct(check['cleared_when_random_reset'])})")
    fastest = results["speed"]["measurements"][-1]
    print(f"Speed - {fastest['batch_size']:,} connections checked together in {fastest['batch_ms']:,} ms "
          f"(about {fastest['connections_per_second']:,} per second on this computer)")
    c = results["criterion"]
    print(f"\nTask 5.0 target: precision >= {_pct(c['target'])}   "
          f"result: {_pct(c['achieved'])}   {'PASSED' if c['passed'] else 'NOT MET'}")

    json_path, md_path = write_reports(results, reports_dir())
    print(f"\nFull report: {md_path}\n             {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
