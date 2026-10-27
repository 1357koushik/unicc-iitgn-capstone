"""
Trains the network sensor on a dataset's training part and saves it.

Usage (in the project folder, with the .venv switched on):
    python -m network_sensor.train                         # NSL-KDD (the web app's default)
    python -m network_sensor.train --dataset cicids2017    # CIC-IDS2017
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
    parser.add_argument("--dataset", choices=DATASETS, default=DEFAULT_DATASET,
                        help="which dataset to train on (default: nsl_kdd)")
    dataset = parser.parse_args(argv).dataset
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


if __name__ == "__main__":
    sys.exit(main())
