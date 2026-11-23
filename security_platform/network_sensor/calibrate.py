"""
Chooses the anomaly models' false-alarm budget (the "anomaly share": how much NORMAL
training traffic the Isolation Forest and the One-Class SVM may call unusual) using
TRAINING data only - never the test part.

How:
  1. Set aside a validation slice of the training part (one flow in five, chosen by a
     fingerprint of its measurements, so identical flows stay together).
  2. Train the sensor on the rest, once for each candidate share.
  3. Score each one on the validation slice.
  4. Rule, fixed before looking at any result: keep the LARGEST share (the one most
     sensitive to new kinds of attack) whose validation precision is at least
     VALIDATION_TARGET; if none reaches it, the smallest share.

Usage (in the project folder, with the .venv switched on):
    python -m network_sensor.calibrate --dataset cicids2017      # takes 10-20 minutes

It prints the table and the chosen share; the share is then written into the dataset's
description (anomaly_share in spec.py / cicids2017.py) with the date and the numbers.
"""
import argparse
import sys
from dataclasses import replace

import numpy as np
import pandas as pd

from network_sensor.datasets import DatasetError
from network_sensor.evaluate import compute_metrics
from network_sensor.models import NetworkSensorModel, SensorSettings
from network_sensor.spec import DATASETS, get_spec, load_split

CANDIDATES = (0.05, 0.02, 0.01, 0.005, 0.002)
# Above the Task 5.0 target of 90%, leaving room for new traffic looking different.
VALIDATION_TARGET = 0.95


def validation_mask(df: pd.DataFrame, feature_columns) -> np.ndarray:
    """One flow in five, by a fingerprint of its measurements. (The CIC-IDS2017 train/test
    split uses the last two digits of the same fingerprint; this uses the next digit,
    so the two choices are independent.)"""
    fingerprint = pd.util.hash_pandas_object(df[list(feature_columns)], index=False).to_numpy()
    return (fingerprint // 100) % 5 == 0


def calibrate(dataset: str, full_training_part: pd.DataFrame, sampler=None, candidates=CANDIDATES,
              settings: SensorSettings = None, progress=None) -> dict:
    """Score each candidate share on a validation slice of the training part.
    sampler(rows) -> the rows to train on (e.g. the CIC-IDS2017 training sample)."""
    spec = get_spec(dataset)
    mask = validation_mask(full_training_part, spec.feature_columns)
    validation = full_training_part[mask]
    rest = full_training_part[~mask].reset_index(drop=True)
    train = sampler(rest) if sampler else rest
    y = validation["is_attack"].to_numpy()
    base = settings or SensorSettings()
    rows = []
    for share in candidates:
        if progress:
            progress(share)
        model = NetworkSensorModel(replace(base, anomaly_share=share), dataset=dataset).fit(train)
        votes = model.votes(validation)
        combined = model.combine(votes)
        m = compute_metrics(y, combined)
        only_anomaly = (combined == 1) & (votes["random_forest"].to_numpy() == 0)
        rows.append({
            "anomaly_share": share,
            "precision": m["precision"],
            "recall": m["recall"],
            "false_alarm_rate": m["false_alarm_rate"],
            "false_alarms": m["false_positives"],
            "attacks_caught_only_by_anomaly_models": int((only_anomaly & (y == 1)).sum()),
        })
    passing = [r for r in rows if r["precision"] >= VALIDATION_TARGET]
    chosen = max(passing, key=lambda r: r["anomaly_share"]) if passing else min(rows, key=lambda r: r["anomaly_share"])
    return {
        "dataset": dataset,
        "validation_rows": int(len(validation)),
        "validation_attacks": int(y.sum()),
        "training_rows": int(len(train)),
        "target_precision": VALIDATION_TARGET,
        "candidates": rows,
        "chosen_anomaly_share": chosen["anomaly_share"],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Choose the anomaly share on validation data from the training part.")
    parser.add_argument("--dataset", choices=DATASETS, required=True)
    dataset = parser.parse_args(argv).dataset
    spec = get_spec(dataset)
    try:
        if dataset == "cicids2017":
            from network_sensor.cicids2017 import load_cicids2017, training_sample
            full, sampler = load_cicids2017("train", sample=False), training_sample
        else:
            full, sampler = load_split(dataset, "train"), None
    except DatasetError as e:
        print(f"ERROR: {e}")
        return 1
    print(f"{spec.title}: choosing the anomaly share on a validation slice of the training part ...")
    result = calibrate(dataset, full, sampler, progress=lambda share: print(f"  trying {share:.1%} ..."))
    print(f"\nValidation: {result['validation_rows']:,} flows ({result['validation_attacks']:,} attacks); "
          f"trained on {result['training_rows']:,}.")
    print(f"{'Anomaly share':>14}{'Precision':>11}{'Recall':>9}{'False alarms':>14}{'Only anomaly models':>21}")
    for r in result["candidates"]:
        print(f"{r['anomaly_share']:>14.1%}{r['precision']:>11.1%}{r['recall']:>9.1%}"
              f"{r['false_alarms']:>14,}{r['attacks_caught_only_by_anomaly_models']:>21,}")
    print(f"\nRule: the largest share with validation precision >= {VALIDATION_TARGET:.0%}.  "
          f"Chosen: {result['chosen_anomaly_share']:.1%}  (currently in use: {spec.anomaly_share:.1%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
