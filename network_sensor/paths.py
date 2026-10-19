"""Where the network sensor keeps its files.

Everything lives under  <project>/data/network_sensor/  which git ignores, so the
downloaded dataset, trained models and reports are never committed by accident.
"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    """The sensor's folder. The NETWORK_SENSOR_DATA_DIR setting can point it somewhere
    else (the tests use this so they never touch your real files)."""
    override = os.environ.get("NETWORK_SENSOR_DATA_DIR")
    return Path(override) if override else PROJECT_ROOT / "data" / "network_sensor"


def dataset_dir() -> Path:
    return data_dir() / "nsl_kdd"


def model_path() -> Path:
    return data_dir() / "models" / "sensor_model.joblib"


def reports_dir() -> Path:
    return data_dir() / "reports"
