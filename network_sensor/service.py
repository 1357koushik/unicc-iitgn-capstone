"""
What the web app uses to run the network sensor (kept out of backend/api/main.py so
that file only needs two short endpoints).

  read_connections(file_bytes) - turns an uploaded file into a table, or refuses it
  sensor.scan(table)           - checks every connection and returns ranked alerts, each
                                 with its likely attack type, priority and next step
  sensor.alerts_csv(table)     - every alert as a CSV table, for download
  sensor.status()              - is the sensor trained, and how well did it score?
  live                         - live replays (see live.py)

Files can be in the NSL-KDD format or the CIC-IDS2017 format (the CSV files that the
CICFlowMeter tool writes); each format is checked by the sensor trained on that dataset -
or, for CICFlowMeter files, on your own labelled traffic if the server trained it so
(python -m network_sensor.train --own-data, see own_data.py).

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
from network_sensor.cicids2018 import COLUMNS_2018, is_cicflowmeter4, is_placeholder_label, rename_columns, translate_label
from network_sensor.datasets import FEATURE_COLUMNS, FILE_COLUMNS
from network_sensor.errors import ScanError
from network_sensor.evaluate import compute_metrics
from network_sensor.features import InputError
from network_sensor.live import LiveSessions
from network_sensor.models import NetworkSensorModel
from network_sensor.own_data import TRAINED_ON, own_data_evaluation
from network_sensor.paths import model_path, reports_dir
from network_sensor.spec import DATASETS, DEFAULT_DATASET, dataset_of_columns, get_spec

MAX_CONNECTIONS = 25_000               # rows per file; keeps one scan to a few seconds
# Alerts sent back per scan. The dashboard shows all alerts, or only known attack
# patterns, or only possible new attacks (raised only by the anomaly models), or one
# priority, and each of those views shows its MAX_ALERTS_PER_FILTER most serious alerts.
# So the most serious MAX_ALERTS_PER_FILTER of each GROUP (one kind at one priority) are
# sent back: every view's most serious alerts are then among them. One shared cap would
# be filled entirely by the most serious group (known patterns at High priority), and the
# other views would find nothing. The totals are always reported.
MAX_ALERTS_PER_FILTER = 300
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

    Four layouts are accepted:
      * a CSV file whose first row names the columns and includes the 41 NSL-KDD
        measurement columns (extra columns such as 'label' are allowed),
      * a CIC-IDS2017 / CICFlowMeter CSV file (first row: 'Destination Port', 'Flow Duration',
        ...; a 'Label' column is allowed),
      * a CSV file written by CICFlowMeter 4.0, as in CSE-CIC-IDS2018 ('Dst Port',
        'Tot Fwd Pkts', ...): the same measurements under shorter names, renamed here to
        the CIC-IDS2017 names (and its attack labels translated; see cicids2018.py), or
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
    flowmeter4 = is_cicflowmeter4(first_values)
    if flowmeter4:
        first_values = [COLUMNS_2018.get(v, v) for v in first_values]
    if "Flow Duration" in first_values or "Destination Port" in first_values:
        header, names = 0, None
        missing = [c for c in cic_columns if c not in first_values]
        if missing:
            looks_like = "CICFlowMeter 4.0 (CSE-CIC-IDS2018)" if flowmeter4 else "CIC-IDS2017"
            raise ScanError(400, f"The header row looks like {looks_like} but is missing these columns: "
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
    if flowmeter4:
        df = rename_columns(df)
        # The CSE-CIC-IDS2018 files repeat their header row in places.
        df = df[df["Destination Port"].str.strip() != "Dst Port"]
    cic = dataset_of_columns(df.columns) == "cicids2017"
    if cic and "Label" in df.columns and "label" not in df.columns:
        df = df.rename(columns={"Label": "label"})
    if flowmeter4 and "label" in df.columns and df["label"].fillna("").map(is_placeholder_label).all():
        # CICFlowMeter writes "No Label" (or "NeedManualLabel") when nobody labelled the flows.
        df = df.drop(columns="label")
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
        if flowmeter4:
            df["label"] = df["label"].map(translate_label)     # e.g. "DoS attacks-Hulk" -> "DoS Hulk"
        else:
            df["label"] = df["label"].map(clean_label) if cic else df["label"].str.strip().str.rstrip(".")
    return df.reset_index(drop=True)


def trained_on_own_data(model: NetworkSensorModel) -> bool:
    """Was this sensor trained on someone's own labelled files (python -m network_sensor.train
    --own-data), rather than on the public dataset of its format?"""
    return model.training_info.get("trained_on") == TRAINED_ON


def trained_on(model: NetworkSensorModel) -> str:
    """What the sensor learned from, for people: 'CIC-IDS2017' or 'your own labelled files'."""
    return "your own labelled files" if trained_on_own_data(model) else model.spec.title


def dataset_of(connections: pd.DataFrame) -> str:
    """Which trained sensor checks this table: 'cicids2017' or 'nsl_kdd'."""
    return dataset_of_columns(connections.columns)


def seriousness(alert: dict):
    """For sorting, most serious first: highest priority, then alerts all three models
    agree on, then by Random Forest score (then by row, so the order is always the same)."""
    return (priority_rank(alert), -sum(alert["votes"].values()), -alert["random_forest_score"], alert["row"])


# The columns of the downloadable alerts table, in order.
CSV_COLUMNS = ["Row", "Priority", "Kind", "Likely type", "Type model votes (%)", "Raised by",
               "Random Forest score (%)", "Certainty", "Reasons", "Where", "Next step"]
CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _csv_text(value) -> str:
    """A cell of text. Text from an uploaded file (labels, addresses) could start with "="
    and would then run as a formula when the CSV is opened in Excel ("CSV injection"), so
    such text starts with an apostrophe, which makes Excel show it as plain text."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(CSV_FORMULA_START) else text


def alerts_to_csv(alerts, has_labels: bool) -> str:
    """The alerts as CSV text (one row per alert, most serious first), for Excel."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS + (["Label in file"] if has_labels else []))
    for a in alerts:
        attack_type = a.get("attack_type") or {}
        row = [
            a["row"],
            _csv_text(a.get("priority", "")),
            "Known pattern" if a["votes"]["random_forest"] == 1 else "Possible new attack",
            _csv_text(attack_type.get("likely", "")),
            round(100 * attack_type["confidence"], 1) if "confidence" in attack_type else "",
            _csv_text("; ".join(a["flagged_by"])),
            round(100 * a["random_forest_score"], 1),
            _csv_text(a.get("certainty", "")),
            _csv_text(" | ".join(r["text"] for r in a["reasons"])),
            _csv_text(", ".join(f"{k} {v}" for k, v in a.get("where", {}).items())),
            _csv_text(a.get("next_step", "")),
        ]
        if has_labels:
            row.append(_csv_text(a.get("label_in_file", "")))
        writer.writerow(row)
    # The byte-order mark at the start tells Excel the file is UTF-8.
    return "\ufeff" + out.getvalue()


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
        own = trained_on_own_data(model)
        return {
            "dataset": dataset,
            "title": spec.title,
            "ready": True,
            "attack_types": model.has_attack_types,     # False: trained before attack types existed
            "trained_at": info.get("trained_at"),
            "training_connections": info.get("training_rows"),
            "trained_on": trained_on(model),
            "own_data": own,
            "decision_rule": info.get("decision_rule"),
            # A sensor trained on your own files is scored on their test part; the public
            # dataset's evaluation report says nothing about it.
            "evaluation": (own_data_evaluation(info) if own
                           else _latest_evaluation(reports_dir(dataset) / "evaluation_report.json")),
        }

    def status(self) -> dict:
        """The NSL-KDD sensor's status at the top level (as before), and every dataset's
        sensor under 'datasets'."""
        datasets = [self._dataset_status(d) for d in DATASETS]
        main = {k: v for k, v in datasets[0].items() if k not in ("dataset", "title")}
        if main["ready"]:
            main["max_connections"] = MAX_CONNECTIONS
        return {**main, "datasets": datasets}

    def _all_alerts(self, connections: pd.DataFrame):
        """Check every connection. Returns (dataset, spec, model, explanations, alerts):
        every alert, most serious first."""
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
        return dataset, spec, model, explanations, sorted(alerts, key=seriousness)

    def scan(self, connections: pd.DataFrame) -> dict:
        dataset, spec, model, explanations, alerts = self._all_alerts(connections)
        known = [a for a in alerts if a["votes"]["random_forest"] == 1]
        new = [a for a in alerts if a["votes"]["random_forest"] == 0]
        groups = {}
        for a in alerts:
            groups.setdefault((a["votes"]["random_forest"], a.get("priority")), []).append(a)
        shown = sorted((a for group in groups.values() for a in group[:MAX_ALERTS_PER_FILTER]), key=seriousness)

        result = {
            "dataset": dataset,
            "dataset_title": spec.title,
            "connections": len(connections),
            "alerts_total": len(alerts),
            "known_pattern_alerts": len(known),
            "possible_new_attacks": len(new),
            "alerts_shown": len(shown),
            "max_alerts_per_filter": MAX_ALERTS_PER_FILTER,
            **summarise(alerts),                          # counts of ALL alerts, for the charts
            "attack_types": model.has_attack_types,
            "alerts": shown,
            "trained_on": trained_on(model),
            "model": {"trained_at": model.training_info.get("trained_at"),
                      "decision_rule": model.training_info.get("decision_rule")},
        }
        if "label" in connections.columns:
            truth = (connections["label"] != spec.normal_label).astype(int)
            verdicts = [1 if e["verdict"] == "attack" else 0 for e in explanations]
            result["label_check"] = {
                "note": "Compared with the label column in your file (the labels were not used to decide).",
                **compute_metrics(truth, verdicts),
                "unknown_labels": sorted({lab for lab in connections["label"] if spec.family_of(lab) == "unknown"})[:20],
            }
        return result

    def alerts_csv(self, connections: pd.DataFrame):
        """EVERY alert in the file as a CSV table (the dashboard shows only the most serious).
        Returns (CSV text, facts for the audit log)."""
        dataset, _, model, _, alerts = self._all_alerts(connections)
        text = alerts_to_csv(alerts, has_labels="label" in connections.columns)
        return text, {"dataset": dataset, "connections": len(connections), "alerts": len(alerts),
                      "model_trained_at": model.training_info.get("trained_at"),
                      "model_trained_on": trained_on(model)}


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
