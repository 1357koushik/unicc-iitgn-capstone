"""
Trains the network sensor on a dataset's training part and saves it.

Usage (in the project folder, with the .venv switched on):
    python -m network_sensor.train                         # NSL-KDD (the web app's default)
    python -m network_sensor.train --dataset cicids2017    # CIC-IDS2017
    python -m network_sensor.train --own-data FOLDER       # your own labelled CICFlowMeter
                                                           # files (see own_data.py)
"""
import argparse
import sys
import time

from network_sensor.datasets import DatasetError
from network_sensor.models import NetworkSensorModel
from network_sensor.paths import model_path
from network_sensor.spec import DATASETS, DEFAULT_DATASET, get_spec, load_split


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Train the network sensor.")
    parser.add_argument("--dataset", choices=DATASETS, default=None,
                        help="which dataset to train on (default: nsl_kdd)")
    parser.add_argument("--own-data", metavar="FOLDER",
                        help="train the sensor for CICFlowMeter files on your own labelled CICFlowMeter "
                             "CSV files instead (a folder of .csv files, or one file)")
    parser.add_argument("--accept-below-target", action="store_true",
                        help="with --own-data: install the new sensor even if its precision on the "
                             "test part is below the 90%% target")
    args = parser.parse_args(argv)
    if args.own_data:
        if args.dataset == "nsl_kdd":
            parser.error("--own-data trains the sensor for CICFlowMeter files; it cannot be used with "
                         "--dataset nsl_kdd (no tool writes NSL-KDD records from today's traffic)")
        return train_own_data(args.own_data, args.accept_below_target)
    if args.accept_below_target:
        parser.error("--accept-below-target only goes with --own-data")
    dataset = args.dataset or DEFAULT_DATASET
    spec = get_spec(dataset)
    try:
        train = load_split(dataset, "train")
    except DatasetError as e:
        print(f"ERROR: {e}")
        return 1
    n_attacks = int(train["is_attack"].sum())
    print(f"{spec.title} training data: {len(train):,} connections "
          f"({len(train) - n_attacks:,} normal, {n_attacks:,} attacks)")
    sample_note = train.attrs.get("sample_note")
    if sample_note:
        print(sample_note)
    print("Training the three models and the attack-type classifier (usually a minute or two) ...")

    started = time.perf_counter()
    model = NetworkSensorModel(dataset=dataset).fit(train)
    seconds = time.perf_counter() - started
    if train.attrs.get("sample"):
        model.training_info["sample"] = train.attrs["sample"]

    saved = model.save(model_path(dataset))
    print(f"Trained in {seconds:.0f} seconds. Saved to: {saved}")
    option = "" if dataset == DEFAULT_DATASET else f" --dataset {dataset}"
    print(f"\nNext step:  python -m network_sensor.evaluate{option}")
    return 0


def train_own_data(source: str, accept_below_target: bool) -> int:
    """--own-data: train, test and (if good enough) install. Returns 0 if the new sensor
    was installed, 1 if not (an error, or precision below the target)."""
    from network_sensor.own_data import run          # only needed for this option
    try:
        r = run(source, accept_below_target=accept_below_target)
    except DatasetError as e:
        print(f"ERROR: {e}")
        return 1
    c = r["test"]["combined"]
    print(f"\nOn the test part of your files: precision {100 * c['precision']:.1f}% "
          f"(target {100 * r['target_precision']:.0f}%), attacks caught {100 * c['recall']:.1f}%, "
          f"false alarms on {100 * c['false_alarm_rate']:.1f}% of normal traffic.")
    if r["installed"]:
        print(f"Installed: the web app now checks CICFlowMeter files with this sensor ({r['model_file']}).")
        if r["previous_model_file"]:
            print(f"The sensor it replaced is kept as {r['previous_model_file']}.")
        if not r["passed"]:
            print("WARNING: installed although precision is below the target (--accept-below-target).")
    else:
        print("NOT installed: precision is below the target, so the web app keeps its current sensor. "
              "Add more (and correctly) labelled traffic and train again, or use --accept-below-target.")
    print(f"Report: {r['report_file']}")
    return 0 if r["installed"] else 1


if __name__ == "__main__":
    sys.exit(main())
