"""
Training the CICFlowMeter-format sensor on YOUR OWN network's labelled traffic.

The sensor that checks CICFlowMeter files is normally trained on the public CIC-IDS2017
dataset. On another network it does much worse: on CSE-CIC-IDS2018 it reached 57%
precision and caught 2.5% of the attacks (see cicids2018.py), because normal traffic and
attacks look different there. This command trains that sensor on your own traffic instead:

    python -m network_sensor.train --own-data "C:\\path\\to\\folder with your CSV files"

The files:
  * CSV files written by the official CICFlowMeter 4.0 (the Java tool from
    https://www.unb.ca/cic/research/applications.html), or in the CIC-IDS2017 layout.
    Not the Python package also called "cicflowmeter": it measures differently.
  * The Label column filled in for EVERY flow. CICFlowMeter writes "No Label"; replace it
    with "Benign" (or "Normal") for normal traffic and an attack name for attacks - for
    example from the times and machines of a penetration test. Attack names the sensor
    knows, so that its alerts get a likely type, a priority and a next step: the
    CIC-IDS2017 and CSE-CIC-IDS2018 names (such as "SSH-Patator" or "DoS attacks-Hulk"),
    or a family name: DoS, DDoS, PortScan, Brute Force, Web Attack, Botnet, Infiltration,
    Heartbleed. Other names still teach the sensor to flag those flows; their alerts get
    the closest known type.

What the command does:
  1. Reads every .csv file in the folder (or the one file given) and refuses flows without
     a label, and files without normal traffic or without any attack type it knows.
  2. Splits the flows into a training part (70%) and a test part (30%) the same way as
     CIC-IDS2017 (identical flows always land on the same side, so the test is fair).
  3. Trains the same four models on a random sample of the training part.
  4. Scores the new sensor on the test part. Only if its precision reaches the 90%
     target does it replace the sensor the web app uses; the replaced one is kept as
     models/sensor_model_cicids2017.previous.joblib. --accept-below-target installs it
     anyway. Below the target, nothing is replaced.
  5. Records in the model which files it learned from, with their SHA-256 fingerprints,
     and writes a report: reports/cicids2017/own_data_training.md / .json.

SECURITY: whoever chooses the training files decides what the sensor learns. Wrongly
labelled flows - by mistake or on purpose ("data poisoning") - teach it to ignore those
attacks. That is why training is a command on the server, not a button in the web app,
why the 90% check guards the replacement, and why the files' fingerprints are recorded.
"""
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from network_sensor.cicids2017 import (FAMILIES, FAMILY_OF_LABEL, MAY_BE_UNDEFINED, NORMAL_LABEL,
                                       NUMERIC_COLUMNS, TEST_SHARE, TRAINING_FLOWS_PER_ATTACK_TYPE,
                                       TRAINING_NORMAL_FLOWS, clean_label, family_of, split_of, to_flows)
from network_sensor.cicids2018 import (CHUNK_ROWS, _votes_in_batches, _weighted, is_placeholder_label,
                                       missing_columns, rename_columns, translate_label)
from network_sensor.datasets import DatasetError
from network_sensor.evaluate import TARGET_PRECISION
from network_sensor.models import NetworkSensorModel
from network_sensor.paths import model_path, reports_dir

DATASET = "cicids2017"          # the sensor that checks CICFlowMeter files
TRAINED_ON = "own_data"         # training_info["trained_on"] of a sensor trained here
# The test part is scored on a random sample too: up to this many normal flows and
# this many flows of each attack name, each counting for the flows it stands for.
TEST_NORMAL_FLOWS = 100_000
TEST_FLOWS_PER_ATTACK_TYPE = 20_000
# Fewer labelled flows than this cannot train or test the sensor meaningfully.
MIN_TRAINING_NORMAL = 200
MIN_TRAINING_ATTACKS = 20
MIN_TEST_NORMAL = 20
MIN_TEST_ATTACKS = 5
# More broken rows than this (empty or non-numeric measurements) means a damaged file.
MAX_BROKEN_SHARE = 0.05
REPORT_NAME = "own_data_training"


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


# Names the sensor knows, matched ignoring case, spaces and dashes.
_KNOWN_NAMES = {_key(name): name for name in (*FAMILY_OF_LABEL, *FAMILIES)}
_KNOWN_NAMES.update({_key(NORMAL_LABEL): NORMAL_LABEL, "normal": NORMAL_LABEL})


def own_label(raw) -> str:
    """A label as written in someone's own file -> the sensor's name for it:
    'Benign' / 'normal' -> 'BENIGN', 'DoS attacks-Hulk' -> 'DoS Hulk', 'brute force' ->
    'Brute Force'. Unknown attack names are kept as they are (tidied)."""
    text = translate_label(clean_label(str(raw).strip()))
    return _KNOWN_NAMES.get(_key(text), text)


def csv_files(source) -> List[Path]:
    """The .csv files to train on: the file given, or every .csv file in the folder."""
    source = Path(source)
    if source.is_file():
        return [source]
    if not source.is_dir():
        raise DatasetError(f"{source} was not found.")
    files = sorted(p for p in source.iterdir() if p.is_file() and p.suffix.lower() == ".csv")
    if not files:
        raise DatasetError(f"No .csv files in {source}.")
    return files


def _chunks(path: Path, usecols=None):
    """The file in pieces, as text. Repeated header rows (as in the CSE-CIC-IDS2018 files)
    are dropped. Read as Latin-1, which accepts any byte: the official CIC-IDS2017 files
    are not UTF-8, and odd characters only ever appear in labels (tidied by clean_label)."""
    for chunk in pd.read_csv(path, dtype=str, chunksize=CHUNK_ROWS, usecols=usecols,
                             encoding="latin-1", low_memory=False):
        chunk.columns = [str(c).strip() for c in chunk.columns]
        if "Label" in chunk.columns:
            chunk = chunk[chunk["Label"].fillna("").str.strip() != "Label"]
        yield chunk


def _check_header(path: Path) -> None:
    try:
        header = pd.read_csv(path, nrows=0, encoding="latin-1").columns
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as e:
        raise DatasetError(f"{path.name} could not be read as a CSV file: {str(e)[:200]}")
    columns = rename_columns(pd.DataFrame(columns=[str(c) for c in header])).columns
    missing = missing_columns(columns)
    if missing:
        raise DatasetError(f"{path.name} is not a CICFlowMeter file: it is missing these columns: "
                           f"{', '.join(missing[:8])}" + (" ..." if len(missing) > 8 else ""))
    if "Label" not in columns:
        raise DatasetError(f"{path.name} has no Label column. Add one and label every flow "
                           "(\"Benign\" for normal traffic, an attack name for attacks).")


def _raw_label_counts(path: Path) -> pd.Series:
    """How many flows have each label, as written in the file (reads only that column)."""
    counts = pd.Series(dtype="int64")
    for chunk in _chunks(path, usecols=lambda c: str(c).strip() == "Label"):
        counts = counts.add(chunk["Label"].fillna("").str.strip().value_counts(), fill_value=0)
    return counts.astype("int64")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def survey(paths: List[Path]) -> Tuple[List[dict], Dict[str, int]]:
    """Check every file and count its labels. Returns (one entry per file, flows per
    label over all files); raises DatasetError if the files cannot train a sensor."""
    files, totals, unlabelled = [], {}, {}
    for path in paths:
        _check_header(path)
        raw = _raw_label_counts(path)
        if raw.sum() == 0:
            raise DatasetError(f"{path.name} has no flows.")
        labels = {}
        for text, n in raw.items():
            if is_placeholder_label(text):
                unlabelled[path.name] = unlabelled.get(path.name, 0) + int(n)
                continue
            name = own_label(text)
            labels[name] = labels.get(name, 0) + int(n)
        for name, n in labels.items():
            totals[name] = totals.get(name, 0) + n
        files.append({"name": path.name, "sha256": _sha256(path), "flows": int(raw.sum()),
                      "labels": dict(sorted(labels.items(), key=lambda item: -item[1]))})
    if unlabelled:
        where = "; ".join(f"{name}: {n:,}" for name, n in unlabelled.items())
        raise DatasetError(f"Some flows have no label (\"No Label\" or empty) - {where}. Every flow must be "
                           "labelled \"Benign\" or with an attack name; remove the flows you cannot label.")
    found = ", ".join(sorted(totals)) or "none"
    if NORMAL_LABEL not in totals:
        raise DatasetError("No normal traffic: label normal flows \"Benign\" (or \"Normal\"). "
                           f"Labels found: {found}.")
    attacks = [name for name in totals if name != NORMAL_LABEL]
    if not attacks:
        raise DatasetError("No attacks: the sensor must see examples of attacks to learn them. "
                           f"Labels found: {found}.")
    if all(family_of(name) == "unknown" for name in attacks):
        raise DatasetError(
            f"None of the attack names is one the sensor knows ({', '.join(sorted(attacks))}), so its alerts "
            "could not say what kind of attack they are. Use a family name - " + ", ".join(FAMILIES) +
            " - or a CIC-IDS2017 / CSE-CIC-IDS2018 attack name.")
    return files, totals


def _valid_rows(chunk: pd.DataFrame) -> np.ndarray:
    """True for rows whose measurements are all usable numbers (a port 0-65535; the
    'may be undefined' rates are allowed to be empty or infinite, see spec.py)."""
    port = pd.to_numeric(chunk["Destination Port"], errors="coerce")
    ok = port.notna() & (port >= 0) & (port <= 65535) & (port == np.floor(port))
    for column in NUMERIC_COLUMNS:
        if column in MAY_BE_UNDEFINED:
            continue
        values = pd.to_numeric(chunk[column], errors="coerce").to_numpy(dtype=float)
        ok &= np.isfinite(values)
    return ok.to_numpy()


def sample_flows(paths: List[Path], totals: Dict[str, int], seed: int = 0) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, dict]]:
    """(training sample, test sample, broken rows per file). The training sample has up
    to about TRAINING_NORMAL_FLOWS normal flows and TRAINING_FLOWS_PER_ATTACK_TYPE flows of
    each attack name, as for CIC-IDS2017; the test sample up to TEST_* flows, each with a
    'weight': how many flows of the test part it stands for."""
    train_share = 1.0 - TEST_SHARE

    def keep(cap_normal: int, cap_attack: int, share: float) -> Dict[str, float]:
        return {name: min(1.0, (cap_normal if name == NORMAL_LABEL else cap_attack) / (share * n))
                for name, n in totals.items()}

    keep_train = keep(TRAINING_NORMAL_FLOWS, TRAINING_FLOWS_PER_ATTACK_TYPE, train_share)
    keep_test = keep(TEST_NORMAL_FLOWS, TEST_FLOWS_PER_ATTACK_TYPE, TEST_SHARE)
    keep_any = {name: max(keep_train[name], keep_test[name]) for name in totals}
    rng = np.random.default_rng(seed)
    train_parts, test_parts, broken = [], [], {}
    for path in paths:
        read = bad = 0
        for chunk in _chunks(path):
            raw = chunk["Label"].fillna("").str.strip()
            names = raw.map({text: own_label(text) for text in raw.unique()})
            draw = rng.random(len(chunk))
            # Only the flows that can end up in either sample are converted (much faster).
            candidate = draw < names.map(keep_any).fillna(0.0).to_numpy()
            if not candidate.any():
                continue
            chunk = rename_columns(chunk[candidate]).assign(Label=names[candidate].to_numpy())
            draw = draw[candidate]
            ok = _valid_rows(chunk)
            read += len(chunk)
            bad += int((~ok).sum())
            if not ok.any():
                continue
            flows = to_flows(chunk[ok])
            draw = draw[ok]
            side = split_of(flows)
            labels = flows["label"]
            in_train = (side == "train") & (draw < labels.map(keep_train).to_numpy())
            in_test = (side == "test") & (draw < labels.map(keep_test).to_numpy())
            if in_train.any():
                train_parts.append(flows[in_train])
            if in_test.any():
                test = flows[in_test].copy()
                test["weight"] = 1.0 / test["label"].map(keep_test).to_numpy()
                test_parts.append(test)
        broken[path.name] = {"checked": read, "broken": bad}
        if read and bad / read > MAX_BROKEN_SHARE:
            raise DatasetError(f"{path.name}: {bad:,} of {read:,} flows read have empty, infinite or non-numeric "
                               "measurements. Check that the file was written by CICFlowMeter 4.0.")
    empty = pd.DataFrame()
    train = pd.concat(train_parts, ignore_index=True) if train_parts else empty
    test = pd.concat(test_parts, ignore_index=True) if test_parts else empty
    _check_sizes(train, test)
    train.attrs["sample"] = {
        "note": f"a random sample of the training part of your files (70%): up to about "
                f"{TRAINING_NORMAL_FLOWS:,} normal flows and {TRAINING_FLOWS_PER_ATTACK_TYPE:,} of each attack name",
        "normal_cap": TRAINING_NORMAL_FLOWS, "attack_type_cap": TRAINING_FLOWS_PER_ATTACK_TYPE,
    }
    return train, test, broken


def _check_sizes(train: pd.DataFrame, test: pd.DataFrame) -> None:
    def counts(part):
        if part.empty:
            return 0, 0
        attacks = int(part["is_attack"].sum())
        return len(part) - attacks, attacks

    train_normal, train_attacks = counts(train)
    test_normal, test_attacks = counts(test)
    if (train_normal < MIN_TRAINING_NORMAL or train_attacks < MIN_TRAINING_ATTACKS
            or test_normal < MIN_TEST_NORMAL or test_attacks < MIN_TEST_ATTACKS):
        raise DatasetError(
            "Not enough labelled flows to train and test a sensor fairly. Needed at least "
            f"{MIN_TRAINING_NORMAL} normal and {MIN_TRAINING_ATTACKS} attack flows for training and "
            f"{MIN_TEST_NORMAL} normal and {MIN_TEST_ATTACKS} attack flows for the test; found "
            f"{train_normal:,} and {train_attacks:,} for training, {test_normal:,} and {test_attacks:,} for the test.")


def score(model: NetworkSensorModel, test: pd.DataFrame) -> dict:
    """How the new sensor does on the test part (estimated from the weighted sample)."""
    y = test["is_attack"].to_numpy()
    w = test["weight"].to_numpy()
    votes = _votes_in_batches(model, test)
    flagged = model.combine(votes)
    by_label = []
    for label, group in test.groupby("label", sort=True):
        idx = group.index.to_numpy()
        is_attack = bool(group["is_attack"].iat[0])
        by_label.append({"label": label, "family": family_of(label) if is_attack else "normal",
                         "checked": int(len(idx)), "estimated_flows": float(w[idx].sum()),
                         "flagged_share": float((w[idx] * flagged[idx]).sum() / w[idx].sum())})
    return {
        "combined": _weighted(y, flagged, w),
        "by_model": {name: _weighted(y, votes[name].to_numpy(), w) for name in votes.columns},
        "by_label": by_label,
        "flows_checked": int(len(test)),
    }


def install(model: NetworkSensorModel) -> Tuple[Path, Path]:
    """Make the new sensor the one the web app uses (it notices the new file by itself).
    The sensor it replaces is kept next to it. Returns (model file, copy of the old one or None)."""
    path = model_path(DATASET)
    backup = path.with_name(path.stem + ".previous" + path.suffix)
    kept = None
    if path.exists():
        shutil.copy2(path, backup)
        kept = backup
    new = path.with_name(path.name + ".new")
    model.save(new)
    os.replace(new, path)          # all at once: the web app never sees half a file
    return path, kept


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def render_markdown(r: dict) -> str:
    c = r["test"]["combined"]
    outcome = ("Installed: the web app now checks CICFlowMeter files with this sensor."
               if r["installed"] else
               "NOT installed: precision is below the target, so the web app keeps its current sensor. "
               "Add more (and correctly) labelled traffic and train again, or install it anyway with "
               "--accept-below-target.")
    lines = [
        "# Network sensor trained on your own traffic", "",
        f"Trained {r['trained_at']} on {r['training_rows']:,} flows ({r['sample_note']}), "
        f"in {r['training_seconds']:.0f} seconds.", "",
        f"**{outcome}**", "",
        "## Test part (30% of your flows, never used for training)", "",
        "| Measure | Result |", "|---|---|",
        f"| Precision (target {_pct(r['target_precision'])}) | {_pct(c['precision'])} "
        f"({'met' if r['passed'] else 'NOT met'}) |",
        f"| Attacks caught (recall) | {_pct(c['recall'])} |",
        f"| False alarms on normal traffic | {_pct(c['false_alarm_rate'])} |",
        "", f"Estimated from {r['test']['flows_checked']:,} flows of the test part, each counting for the "
            "flows it stands for.", "",
        "| Model | Precision | Caught | False alarms |", "|---|---|---|---|",
    ]
    for name, m in r["test"]["by_model"].items():
        lines.append(f"| {name.replace('_', ' ')} | {_pct(m['precision'])} | {_pct(m['recall'])} | "
                     f"{_pct(m['false_alarm_rate'])} |")
    lines += ["", "| Label | Family | Checked | Flagged |", "|---|---|---|---|"]
    for row in sorted(r["test"]["by_label"], key=lambda x: (x["family"] != "normal", x["label"])):
        lines.append(f"| {row['label']} | {row['family']} | {row['checked']:,} | {_pct(row['flagged_share'])} |")
    lines += ["", "For normal traffic, \"Flagged\" is the false-alarm rate; for attacks, the share caught.", ""]
    if r["labels_without_known_type"]:
        lines += [f"Attack names without a known type (flagged, but their alerts get the closest known type): "
                  f"{', '.join(r['labels_without_known_type'])}.", ""]
    lines += ["## Files it learned from", "",
              "| File | Flows | Skipped (broken measurements) | SHA-256 fingerprint |", "|---|---|---|---|"]
    for f in r["files"]:
        b = r["broken_rows"].get(f["name"], {})
        lines.append(f"| {f['name']} | {f['flows']:,} | {b.get('broken', 0):,} of the {b.get('checked', 0):,} "
                     f"sampled | `{f['sha256']}` |")
    if r["installed"]:
        lines += ["", "## Going back", ""]
        if r["previous_model_file"]:
            lines.append("The sensor this one replaced is kept as `models/sensor_model_cicids2017.previous.joblib`: "
                         "copy it back over `models/sensor_model_cicids2017.joblib` to use it again. Or train on "
                         "the public dataset again: `python -m network_sensor.train --dataset cicids2017`.")
        else:
            lines.append("To use the sensor trained on the public dataset instead: "
                         "`python -m network_sensor.train --dataset cicids2017`.")
    return "\n".join(lines) + "\n"


def run(source, accept_below_target: bool = False, seed: int = 0, log=print) -> dict:
    """Train on the labelled files in `source`, test, and install if good enough.
    Returns the results (also written as a report); raises DatasetError on bad files."""
    paths = csv_files(source)
    log(f"Checking {len(paths)} file(s) and counting their labels ...")
    files, totals = survey(paths)
    for name, n in sorted(totals.items(), key=lambda item: -item[1]):
        log(f"  {name}: {n:,} flows")
    unknown = sorted(name for name in totals if name != NORMAL_LABEL and family_of(name) == "unknown")
    if unknown:
        log(f"Note: attack names without a known type (still learned as attacks): {', '.join(unknown)}")
    log("Splitting into a training part (70%) and a test part (30%), and sampling ...")
    train, test, broken = sample_flows(paths, totals, seed)
    skipped = sum(b["broken"] for b in broken.values())
    if skipped:
        log(f"Skipped {skipped:,} flows with empty, infinite or non-numeric measurements.")
    n_attacks = int(train["is_attack"].sum())
    log(f"Training on {len(train):,} flows ({len(train) - n_attacks:,} normal, {n_attacks:,} attacks) "
        "- this can take several minutes ...")
    started = time.perf_counter()
    model = NetworkSensorModel(dataset=DATASET).fit(train)
    seconds = time.perf_counter() - started
    log(f"Testing on {len(test):,} flows of the test part ...")
    results = score(model, test)
    precision = results["combined"]["precision"]
    passed = precision >= TARGET_PRECISION
    installed = passed or accept_below_target

    model.training_info["sample"] = train.attrs["sample"]
    model.training_info["trained_on"] = TRAINED_ON
    model.training_info["own_data"] = {
        "files": files,
        "broken_rows": broken,
        "labels_without_known_type": unknown,
        "test": {k: results["combined"][k] for k in ("precision", "recall", "false_alarm_rate")}
                | {"flows_checked": results["flows_checked"]},
        "target_precision": TARGET_PRECISION,
        "passed": passed,
        "installed_below_target": installed and not passed,
    }
    report = {
        "trained_at": model.training_info["trained_at"],
        "training_rows": model.training_info["training_rows"],
        "sample_note": train.attrs["sample"]["note"],
        "training_seconds": seconds,
        "files": files, "broken_rows": broken, "labels_without_known_type": unknown,
        "test": results, "target_precision": TARGET_PRECISION, "passed": passed,
        "installed": installed, "model_file": None, "previous_model_file": None,
    }
    if installed:
        path, kept = install(model)
        report["model_file"], report["previous_model_file"] = str(path), (str(kept) if kept else None)
    folder = reports_dir(DATASET)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{REPORT_NAME}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (folder / f"{REPORT_NAME}.md").write_text(render_markdown(report), encoding="utf-8")
    report["report_file"] = str(folder / f"{REPORT_NAME}.md")
    return report


def own_data_evaluation(training_info: dict) -> dict:
    """The test-part result of a sensor trained here, in the shape the web app's status
    shows (like the evaluation report of a public dataset)."""
    own = training_info["own_data"]
    test = own["test"]
    return {"generated_at": training_info.get("trained_at"), "dataset": "test part of your own files",
            "precision": test["precision"], "recall": test["recall"],
            "false_alarm_rate": test["false_alarm_rate"],
            "target_precision": own["target_precision"], "passed": own["passed"]}
