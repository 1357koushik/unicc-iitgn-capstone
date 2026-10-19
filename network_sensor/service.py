"""
What the web app uses to run the network sensor (kept out of backend/api/main.py so
that file only needs two short endpoints).

  read_connections(file_bytes) - turns an uploaded file into a table, or refuses it
  sensor.scan(table)           - checks every connection and returns ranked alerts
  sensor.status()              - is the sensor trained, and how well did it score?

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

from network_sensor.datasets import FEATURE_COLUMNS, FILE_COLUMNS, attack_category
from network_sensor.evaluate import compute_metrics
from network_sensor.features import InputError
from network_sensor.models import NetworkSensorModel
from network_sensor.paths import model_path, reports_dir

MAX_CONNECTIONS = 25_000               # rows per file; keeps one scan to a few seconds
# Alerts sent back per scan: the most serious of EACH kind (known attack patterns, and
# possible new attacks raised only by the anomaly models). One shared cap would be
# filled entirely by known patterns - all three models agree on those - and the
# possible new attacks would never be shown. The totals are always reported.
MAX_ALERTS_PER_KIND = 300
MAX_TEXT_VALUE_CHARS = 40              # protocol / service / flag names are short


class ScanError(Exception):
    """The request cannot be done. status_code is the HTTP code to answer with."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def read_connections(content: bytes) -> pd.DataFrame:
    """Read an uploaded file of connection records.

    Two layouts are accepted:
      * a CSV file whose first row names the columns (it must include the 41 NSL-KDD
        measurement columns; extra columns such as 'label' are allowed), or
      * a raw NSL-KDD file with no header row: 41 values per row, optionally followed
        by the label and the difficulty score (like KDDTest+.txt).
    If a 'label' column is present it is used only to report how the sensor did on
    this file - never to make the decision."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ScanError(400, "The file must be a text (CSV) file in UTF-8.")
    lines = text.splitlines()
    first = next((line for line in lines if line.strip()), None)
    if first is None:
        raise ScanError(400, "The file is empty.")

    first_values = [value.strip() for value in next(csv.reader([first]))]
    if "duration" in first_values or "protocol_type" in first_values:
        header, names = 0, None
        missing = [c for c in FEATURE_COLUMNS if c not in first_values]
        if missing:
            raise ScanError(400, f"The header row is missing these columns: {', '.join(missing)}.")
    elif len(first_values) in (41, 42, 43):
        header, names = None, FILE_COLUMNS[:len(first_values)]
    else:
        raise ScanError(400, f"Each row has {len(first_values)} values. Expected a header row with the "
                             "41 NSL-KDD column names, or rows of 41 values (optionally followed by "
                             "the label and the difficulty score), like the NSL-KDD files.")
    try:
        df = pd.read_csv(io.StringIO(text), header=header, names=names, dtype=str,
                         nrows=MAX_CONNECTIONS + 1, skip_blank_lines=True)
    except (pd.errors.ParserError, ValueError) as e:
        raise ScanError(400, f"The file could not be read as CSV: {str(e)[:200]}")

    df.columns = [str(c).strip() for c in df.columns]
    if len(df) == 0:
        raise ScanError(400, "The file has no connection records.")
    if len(df) > MAX_CONNECTIONS:
        raise ScanError(413, f"Too many connections (limit {MAX_CONNECTIONS:,} per file). Split the file.")
    for column in ("protocol_type", "service", "flag", "label"):
        if column in df.columns and (df[column].fillna("").str.len() > MAX_TEXT_VALUE_CHARS).any():
            raise ScanError(400, f"Column '{column}' has values longer than {MAX_TEXT_VALUE_CHARS} characters.")
    if "label" in df.columns:
        if df["label"].isna().any():
            raise ScanError(400, "The 'label' column has empty cells. Remove the column or fill it in.")
        df["label"] = df["label"].str.strip().str.rstrip(".")
    return df.reset_index(drop=True)


class SensorService:
    """Keeps the trained sensor in memory and runs scans, one at a time."""

    def __init__(self):
        self._model: Optional[NetworkSensorModel] = None
        self._loaded_from = None             # (file path, file modification time)
        self._load_lock = threading.Lock()
        self._scan_lock = threading.Lock()

    def _get_model(self) -> NetworkSensorModel:
        """The trained sensor. Loaded on first use, and loaded again automatically if
        it has been retrained since (the file on disk changed)."""
        path = model_path()
        if not path.exists():
            raise ScanError(503, "The network sensor has not been trained yet. On the server, run: "
                                 "python -m network_sensor.train")
        key = (str(path), path.stat().st_mtime_ns)
        with self._load_lock:
            if self._loaded_from != key:
                try:
                    self._model = NetworkSensorModel.load(path)
                except ValueError as e:
                    raise ScanError(503, str(e))
                self._loaded_from = key
            return self._model

    def status(self) -> dict:
        try:
            model = self._get_model()
        except ScanError as e:
            return {"ready": False, "message": e.message}
        info = model.training_info
        return {
            "ready": True,
            "trained_at": info.get("trained_at"),
            "training_connections": info.get("training_rows"),
            "decision_rule": info.get("decision_rule"),
            "evaluation": _latest_evaluation(reports_dir() / "evaluation_report.json"),
            "max_connections": MAX_CONNECTIONS,
        }

    def scan(self, connections: pd.DataFrame) -> dict:
        model = self._get_model()
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
            if has_labels:
                alert["label_in_file"] = connections["label"].iat[i]
            alerts.append(alert)
        # Most serious first: alerts all three models agree on, then by Random Forest score.
        def seriousness(a):
            return (-sum(a["votes"].values()), -a["random_forest_score"], a["row"])

        known = sorted((a for a in alerts if a["votes"]["random_forest"] == 1), key=seriousness)
        new = sorted((a for a in alerts if a["votes"]["random_forest"] == 0), key=seriousness)
        shown = sorted(known[:MAX_ALERTS_PER_KIND] + new[:MAX_ALERTS_PER_KIND], key=seriousness)

        result = {
            "connections": len(connections),
            "alerts_total": len(alerts),
            "known_pattern_alerts": len(known),
            "possible_new_attacks": len(new),
            "alerts_shown": len(shown),
            "max_alerts_per_kind": MAX_ALERTS_PER_KIND,
            "alerts": shown,
            "model": {"trained_at": model.training_info.get("trained_at"),
                      "decision_rule": model.training_info.get("decision_rule")},
        }
        if has_labels:
            truth = (connections["label"] != "normal").astype(int)
            verdicts = [1 if e["verdict"] == "attack" else 0 for e in explanations]
            result["label_check"] = {
                "note": "Compared with the 'label' column in your file (the labels were not used to decide).",
                **compute_metrics(truth, verdicts),
                "unknown_labels": sorted({lab for lab in connections["label"] if attack_category(lab) == "unknown"})[:20],
            }
        return result


# The one shared sensor the web app uses.
sensor = SensorService()


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
