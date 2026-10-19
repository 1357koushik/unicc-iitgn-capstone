"""
Trains the network sensor on the NSL-KDD training file and saves it.

Usage (in the project folder, with the .venv switched on):
    python -m network_sensor.train
"""
import sys
import time

from network_sensor.datasets import DatasetError, load_nsl_kdd
from network_sensor.models import NetworkSensorModel
from network_sensor.paths import model_path


def main() -> int:
    try:
        train = load_nsl_kdd("train")
    except DatasetError as e:
        print(f"ERROR: {e}")
        return 1
    n_attacks = int(train["is_attack"].sum())
    print(f"Training data: {len(train):,} connections "
          f"({len(train) - n_attacks:,} normal, {n_attacks:,} attacks)")
    print("Training the three models (usually under a minute) ...")

    started = time.perf_counter()
    model = NetworkSensorModel().fit(train)
    seconds = time.perf_counter() - started

    saved = model.save(model_path())
    print(f"Trained in {seconds:.0f} seconds. Saved to: {saved}")
    print("\nNext step:  python -m network_sensor.evaluate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
