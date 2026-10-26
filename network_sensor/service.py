"""
What the web app uses to run the network sensor (kept out of backend/api/main.py so
that file only needs two short endpoints).

  read_connections(file_bytes) - turns an uploaded file into a table, or refuses it
  sensor.scan(table)           - checks every connection and returns ranked alerts, each
                                 with its likely attack type, priority and next step
  sensor.status()              - is the sensor trained, and how well did it score?
  live                         - live replays (see live.py)

Files can be in the NSL-KDD format or the CIC-IDS2017 format (the CSV files that the
CICFlowMeter tool writes); each format is checked by the sensor trained on that dataset.

The file size limit and accepted file types are checked by main.py, next to the
app's other input limits, before anything here runs.
"""
import csv
import io
import json
import threading
from pathlib import Path
from typing import Optional

import pandas as pd

from network_sensor.actions import IDENTITY_COLUMNS, priority_rank, summarise, where_of
from network_sensor.cicids2017 import clean_label
from network_sensor.datasets import FEATURE_COLUMNS, FILE_COLUMNS
from network_sensor.errors import ScanError
from network_sensor.evaluate import compute_metrics
from network_sensor.features import InputError
from network_sensor.live import LiveSessions
from network_sensor.models import NetworkSensorModel
from network_sensor.paths import model_path, reports_dir
from network_sensor.spec import DATASETS, DEFAULT_DATASET, dataset_of_columns, get_spec

MAX_CONNECTIONS = 25_000               # rows per file; keeps one scan to a few seconds
# Alerts sent back per scan: the most serious of EACH kind (known attack patterns, and
# possible new attacks raised only by the anomaly models). One shared cap would be
# filled entirely by known patterns - all three models agree on those - and the
# possible new attacks would never be shown. The totals are always reported.
MAX_ALERTS_PER_KIND = 300
MAX_TEXT_VALUE_CHARS = 40              # protocol / service / flag / port names are short
TEXT_COLUMNS = ("protocol_type", "service", "flag", "label") + IDENTITY_COLUMNS


def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    # Copies of the CIC-IDS2017 files saved by Windows tools can be in the Windows-1252
    # encoding (a dash in the web attack labels). Accept that too, but never binary files.
    if not any(b < 32 and b not in (9, 10, 13) for b in content):
        try:
            return content.decode("cp1252")
        except UnicodeDecodeError:
            pass
    raise ScanError(400, "The file must be a text (CSV) file in UTF-8.")


def read_connections(content: bytes) -> pd.DataFrame:
    """Read an uploaded file of connection records.

    Three layouts are accepted:
      * a CSV file whose first row names the columns and includes the 41 NSL-KDD
        measurement columns (extra columns such as 'label' are allowed),
      * a CIC-IDS2017 / CICFlowMeter CSV file (first row: 'Destination Port', 'Flow Duration',
        ...; a 'Label' column is allowed), or
      * a raw NSL-KDD file with no header row: 41 values per row, optionally followed
        by the label and the difficulty score (like KDDTest+.txt).
    If a label column is present it is used only to report how the sensor did on
    this file - never to make the decision."""
    text = _decode(content)
    lines = text.splitlines()
    first = next((line for line in lines if line.strip()), None)
    if first is None:
        raise ScanError(400, "The file is empty.")

    first_values = [value.strip() for value in next(csv.reader([first]))]
    cic_columns = get_spec("cicids2017").feature_columns
    if "Flow Duration" in first_values or "Destination Port" in first_values:
        header, names = 0, None
        missing = [c for c in cic_columns if c not in first_values]
        if missing:
            raise ScanError(400, "The header row looks like CIC-IDS2017 but is missing these columns: "
                                 f"{', '.join(missing[:10])}" + (" ..." if len(missing) > 10 else "") + ".")
    elif "duration" in first_values or "protocol_type" in first_values:
        header, names = 0, None
        missing = [c for c in FEATURE_COLUMNS if c not in first_values]
        if missing:
            raise ScanError(400, f"The header row is missing these columns: {', '.join(missing)}.")
    elif len(first_values) in (41, 42, 43):
        header, names = None, FILE_COLUMNS[:len(first_values)]
    else:
        raise ScanError(400, f"Each row has {len(first_values)} values. Expected a header row with the "
                             "NSL-KDD or CIC-IDS2017 column names, or rows of 41 values (optionally "
                             "followed by the label and the difficulty score), like the NSL-KDD files.")
    try:
        df = pd.read_csv(io.StringIO(text), header=header, names=names, dtype=str,
                         nrows=MAX_CONNECTIONS + 1, skip_blank_lines=True)
    except (pd.errors.ParserError, ValueError) as e:
        raise ScanError(400, f"The file could not be read as CSV: {str(e)[:200]}")

    df.columns = [str(c).strip() for c in df.columns]
    cic = dataset_of_columns(df.columns) == "cicids2017"
    if cic and "Label" in df.columns and "label" not in df.columns:
        df = df.rename(columns={"Label": "label"})
    if len(df) == 0:
        raise ScanError(400, "The file has no connection records.")
    if len(df) > MAX_CONNECTIONS:
        raise ScanError(413, f"Too many connections (limit {MAX_CONNECTIONS:,} per file). Split the file.")
    for column in TEXT_COLUMNS:
        if column in df.columns and (df[column].fillna("").str.len() > MAX_TEXT_VALUE_CHARS).any():
            raise ScanError(400, f"Column '{column}' has values longer than {MAX_TEXT_VALUE_CHARS} characters.")
    if "label" in df.columns:
        if df["label"].isna().any():
            raise ScanError(400, "The 'label' column has empty cells. Remove the column or fill it in.")
        df["label"] = df["label"].map(clean_label) if cic else df["label"].str.strip().str.rstrip(".")
    return df.reset_index(drop=True)


def dataset_of(connections: pd.DataFrame) -> str:
    """Which trained sensor checks this table: 'cicids2017' or 'nsl_kdd'."""
    return dataset_of_columns(connections.columns)


class SensorService:
    """Keeps the trained sensors (one per dataset) in memory and runs scans, one at a time."""

    def __init__(self):
        self._models = {}                    # dataset -> (model, (file path, file modification time))
        self._load_lock = threading.Lock()
        self._scan_lock = threading.Lock()

    def model(self, dataset: str = DEFAULT_DATASET) -> NetworkSensorModel:
        """The trained sensor for this dataset's format (raises ScanError 503 if there is none)."""
        return self._get_model(dataset)

    def _get_model(self, dataset: str = DEFAULT_DATASET) -> NetworkSensorModel:
        """The trained sensor. Loaded on first use, and loaded again automatically if
        it has been retrained since (the file on disk changed)."""
        spec = get_spec(dataset)
        path = model_path(dataset)
        if not path.exists():
            option = "" if dataset == DEFAULT_DATASET else f" --dataset {dataset}"
            what = "The network sensor" if dataset == DEFAULT_DATASET else f"The {spec.title} network sensor"
            raise ScanError(503, f"{what} has not been trained yet. On the server, run: "
                                 f"python -m network_sensor.train{option}")
        key = (str(path), path.stat().st_mtime_ns)
        with self._load_lock:
            model, loaded_from = self._models.get(dataset, (None, None))
            if loaded_from != key:
                try:
                    model = NetworkSensorModel.load(path, dataset=dataset)
                except ValueError as e:
                    raise ScanError(503, str(e))
                self._models[dataset] = (model, key)
            return model

    def _dataset_status(self, dataset: str) -> dict:
        spec = get_spec(dataset)
        try:
            model = self._get_model(dataset)
        except ScanError as e:
            return {"dataset": dataset, "title": spec.title, "ready": False, "message": e.message}
        info = model.training_info
        return {
            "dataset": dataset,
            "title": spec.title,
            "ready": True,
            "attack_types": model.has_attack_types,     # False: trained before attack types existed
            "trained_at": info.get("trained_at"),
            "training_connections": info.get("training_rows"),
            "decision_rule": info.get("decision_rule"),
            "evaluation": _latest_evaluation(reports_dir(dataset) / "evaluation_report.json"),
        }

    def status(self) -> dict:
        """The NSL-KDD sensor's status at the top level (as before), and every dataset's
        sensor under 'datasets'."""
        datasets = [self._dataset_status(d) for d in DATASETS]
        main = {k: v for k, v in datasets[0].items() if k not in ("dataset", "title")}
        if main["ready"]:
            main["max_connections"] = MAX_CONNECTIONS
        return {**main, "datasets": datasets}

    def scan(self, connections: pd.DataFrame) -> dict:
        dataset = dataset_of(connections)
        spec = get_spec(dataset)
        model = self._get_model(dataset)
        if not self._scan_lock.acquire(blocking=False):
            raise ScanError(429, "Another network scan is running. Please try again in a moment.")
        try:
            try:
                explanations = model.explain(connections)
            except InputError as e:
                raise ScanError(400, str(e))
        finally:
            self._scan_lock.release()

        has_labels = "label" in connections.columns
        alerts = []
        for i, e in enumerate(explanations):
            if e["verdict"] != "attack":
                continue
            alert = {"row": i + 1, **e}
            where = where_of(connections, i)
            if where:
                alert["where"] = where
            if has_labels:
                alert["label_in_file"] = connections["label"].iat[i]
            alerts.append(alert)
        # Most serious first: highest priority, then alerts all three models agree on,
        # then by Random Forest score.
        def seriousness(a):
            return (priority_rank(a), -sum(a["votes"].values()), -a["random_forest_score"], a["row"])

        known = sorted((a for a in alerts if a["votes"]["random_forest"] == 1), key=seriousness)
        new = sorted((a for a in alerts if a["votes"]["random_forest"] == 0), key=seriousness)
        shown = sorted(known[:MAX_ALERTS_PER_KIND] + new[:MAX_ALERTS_PER_KIND], key=seriousness)

        result = {
            "dataset": dataset,
            "dataset_title": spec.title,
            "connections": len(connections),
            "alerts_total": len(alerts),
            "known_pattern_alerts": len(known),
            "possible_new_attacks": len(new),
            "alerts_shown": len(shown),
            "max_alerts_per_kind": MAX_ALERTS_PER_KIND,
            **summarise(alerts),                          # counts of ALL alerts, for the charts
            "attack_types": model.has_attack_types,
            "alerts": shown,
            "model": {"trained_at": model.training_info.get("trained_at"),
                      "decision_rule": model.training_info.get("decision_rule")},
        }
        if has_labels:
            truth = (connections["label"] != spec.normal_label).astype(int)
            verdicts = [1 if e["verdict"] == "attack" else 0 for e in explanations]
            result["label_check"] = {
                "note": "Compared with the label column in your file (the labels were not used to decide).",
                **compute_metrics(truth, verdicts),
                "unknown_labels": sorted({lab for lab in connections["label"] if spec.family_of(lab) == "unknown"})[:20],
            }
        return result


# The one shared sensor, and the live replays, that the web app uses.
sensor = SensorService()
live = LiveSessions()


def _latest_evaluation(path: Path) -> Optional[dict]:
    """The headline numbers of the last 'python -m network_sensor.evaluate' run, if any."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        combined = report["models"]["combined"]
        return {"generated_at": report["generated_at"], "dataset": report["dataset"],
                "precision": combined["precision"], "recall": combined["recall"],
                "false_alarm_rate": combined["false_alarm_rate"],
                "target_precision": report["criterion"]["target"], "passed": report["criterion"]["passed"]}
    except (OSError, ValueError, KeyError, TypeError):
        return None
