"""Where the network sensor keeps its files.

Everything lives under  <project>/data/network_sensor/  which git ignores, so the
downloaded datasets, trained models and reports are never committed by accident:

    nsl_kdd/                          NSL-KDD files
    cicids2017/                       CIC-IDS2017, prepared from MachineLearningCSV.zip
    models/sensor_model.joblib        the NSL-KDD model (the web app's default)
    models/sensor_model_cicids2017.joblib
    reports/                          NSL-KDD evaluation report
    reports/cicids2017/               CIC-IDS2017 evaluation report
"""
import os
from pathlib import Path

from network_sensor.spec import DEFAULT_DATASET

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    """The sensor's folder. The NETWORK_SENSOR_DATA_DIR setting can point it somewhere
    else (the tests use this so they never touch your real files)."""
    override = os.environ.get("NETWORK_SENSOR_DATA_DIR")
    return Path(override) if override else PROJECT_ROOT / "data" / "network_sensor"


def dataset_dir(dataset: str = DEFAULT_DATASET) -> Path:
    return data_dir() / dataset


def model_path(dataset: str = DEFAULT_DATASET) -> Path:
    name = "sensor_model.joblib" if dataset == DEFAULT_DATASET else f"sensor_model_{dataset}.joblib"
    return data_dir() / "models" / name


def reports_dir(dataset: str = DEFAULT_DATASET) -> Path:
    folder = data_dir() / "reports"
    return folder if dataset == DEFAULT_DATASET else folder / dataset
