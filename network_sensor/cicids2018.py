"""
CSE-CIC-IDS2018: checking the CIC-IDS2017 sensor on traffic from a DIFFERENT network.

The CIC-IDS2017 test part comes from the same recording as its training part (the same
machines, the same week, the same attack tools), so its score (96.1% precision) is
optimistic. CSE-CIC-IDS2018 is the Canadian Institute for Cybersecurity's next dataset:
recorded a year later (14 February - 2 March 2018) on another network (on Amazon's
cloud), with many of the same kinds of attack, by the next version of the same flow tool
(CICFlowMeter 4.0):
    https://www.unb.ca/cic/datasets/ids-2018.html

CICFlowMeter 4.0 writes the same measurements as the 2017 version, under shorter names
("Dst Port" instead of "Destination Port", "Tot Fwd Pkts" instead of "Total Fwd
Packets", ...). This module

  * renames those columns to the CIC-IDS2017 names. The web app uses this too, so a
    file written by CICFlowMeter 4.0 - for example from a capture of your own network -
    can be scanned by the CIC-IDS2017 sensor;
  * translates the 2018 attack names to the matching CIC-IDS2017 ones
    ("DoS attacks-Hulk" -> "DoS Hulk", "Benign" -> "BENIGN", ...);
  * and, as a command, scores the CIC-IDS2017 sensor on the 2018 files, WITHOUT any
    retraining:

        python -m network_sensor.cicids2018 "C:\\path\\to\\folder with the 2018 CSV files"

The 2018 files are large (about a million flows each), so a random sample is checked:
a share of the normal flows and up to a fixed number of flows of each attack type, and
every sampled flow counts for the flows it stands for (a weight), so the results estimate
what checking every flow would give. The report lists the files, the sample and the
weights. Report: data/network_sensor/reports/cicids2017/cross_dataset_cicids2018.md / .json
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from network_sensor.actions import PRIORITIES, priority_of
from network_sensor.cicids2017 import FAMILIES, FEATURE_COLUMNS, NORMAL_LABEL, NUMERIC_COLUMNS, family_of, to_flows
from network_sensor.datasets import DatasetError
from network_sensor.models import NetworkSensorModel
from network_sensor.paths import model_path, reports_dir

DOWNLOAD_PAGE = "https://www.unb.ca/cic/datasets/ids-2018.html"

# CICFlowMeter 4.0 column name -> CIC-IDS2017 column name. Columns not listed (Flow ID,
# Protocol, ...) are not used by the sensor and are left as they are.
COLUMNS_2018 = {
    "Dst Port": "Destination Port",
    "Src Port": "Source Port",
    "Src IP": "Source IP",
    "Dst IP": "Destination IP",
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}
# Names that tell a CICFlowMeter 4.0 file apart (the 2017 files say "Destination Port").
MARKER_COLUMNS = ("Dst Port", "Tot Fwd Pkts")

# CSE-CIC-IDS2018 attack name -> the CIC-IDS2017 name for the same attack. Matched
# ignoring case, spaces and dashes. The DDoS tools differ (2017: LOIC over HTTP; 2018
# also LOIC over UDP and HOIC), but they belong to the same family.
LABELS_2018 = {
    "Benign": NORMAL_LABEL,
    "FTP-BruteForce": "FTP-Patator",
    "SSH-Bruteforce": "SSH-Patator",
    "DoS attacks-GoldenEye": "DoS GoldenEye",
    "DoS attacks-Slowloris": "DoS slowloris",
    "DoS attacks-SlowHTTPTest": "DoS Slowhttptest",
    "DoS attacks-Hulk": "DoS Hulk",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "Brute Force -Web": "Web Attack - Brute Force",
    "Brute Force -XSS": "Web Attack - XSS",
    "SQL Injection": "Web Attack - Sql Injection",
    "Infilteration": "Infiltration",       # (spelled so in the 2018 files)
    "Infiltration": "Infiltration",
    "Bot": "Bot",
}


def _key(label: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(label).lower())


_LABEL_KEYS = {_key(k): v for k, v in LABELS_2018.items()}


def is_cicflowmeter4(columns) -> bool:
    """Is this the column layout CICFlowMeter 4.0 (and CSE-CIC-IDS2018) writes?"""
    names = {str(c).strip() for c in columns}
    return any(m in names for m in MARKER_COLUMNS)


def rename_columns(df: pd.DataFrame) -> pd.DataFrame:
    """CICFlowMeter 4.0 column names -> CIC-IDS2017 names (other columns unchanged)."""
    df = df.rename(columns=lambda c: str(c).strip())
    return df.rename(columns={k: v for k, v in COLUMNS_2018.items() if k in df.columns})


def is_placeholder_label(label: str) -> bool:
    """CICFlowMeter's own text for 'nobody labelled this flow'."""
    return _key(label) in ("nolabel", "needmanuallabel", "")


def translate_label(label: str) -> str:
    """A 2018 attack name -> the CIC-IDS2017 name (unknown names are kept as they are)."""
    return _LABEL_KEYS.get(_key(label), str(label).strip())


def missing_columns(columns) -> List[str]:
    present = set(columns)
    return [c for c in FEATURE_COLUMNS if c not in present]


# ---------------------------------------------------------------- the cross-dataset check
CHUNK_ROWS = 200_000


def _chunks(path: Path, usecols=None):
    """The file in pieces, as text. The 2018 files repeat their header row in places;
    those rows are dropped."""
    for chunk in pd.read_csv(path, dtype=str, chunksize=CHUNK_ROWS, usecols=usecols, low_memory=False):
        chunk.columns = [str(c).strip() for c in chunk.columns]
        if "Label" in chunk.columns:
            chunk = chunk[chunk["Label"].str.strip() != "Label"]
        yield chunk


def count_labels(path: Path) -> pd.Series:
    """How many flows of each label the file has (reads only the Label column)."""
    counts = pd.Series(dtype="int64")
    for chunk in _chunks(path, usecols=lambda c: str(c).strip() == "Label"):
        counts = counts.add(chunk["Label"].str.strip().value_counts(), fill_value=0)
    return counts.astype("int64")


def sample_file(path: Path, counts: pd.Series, normal_share: float, attack_cap: int,
                rng: np.random.Generator) -> pd.DataFrame:
    """A random sample of one file as sensor flows: each normal flow with probability
    normal_share, and up to about attack_cap flows of each attack type. 'weight' is how
    many flows of the file each sampled flow stands for."""
    keep_share = {label: (normal_share if translate_label(label) == NORMAL_LABEL
                          else min(1.0, attack_cap / n))
                  for label, n in counts.items()}
    parts = []
    for chunk in _chunks(path):
        labels = chunk["Label"].str.strip()
        share = labels.map(keep_share).fillna(0.0).to_numpy()
        chunk = chunk[rng.random(len(chunk)) < share]
        if chunk.empty:
            continue
        chunk = rename_columns(chunk)
        missing = missing_columns(chunk.columns)
        if missing:
            raise DatasetError(f"{path.name} is missing these columns: {', '.join(missing[:8])}"
                               + (" ..." if len(missing) > 8 else ""))
        original = chunk["Label"].str.strip()
        chunk = chunk.assign(Label=original.map(translate_label))
        flows = to_flows(chunk)
        flows["label_2018"] = original.to_numpy()
        flows["weight"] = 1.0 / original.map(keep_share).to_numpy()
        flows["file"] = path.name
        parts.append(flows)
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def _weighted(y: np.ndarray, flagged: np.ndarray, w: np.ndarray) -> Dict[str, float]:
    tp = float(w[(y == 1) & (flagged == 1)].sum())
    fp = float(w[(y == 0) & (flagged == 1)].sum())
    fn = float(w[(y == 1) & (flagged == 0)].sum())
    tn = float(w[(y == 0) & (flagged == 0)].sum())
    return {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_alarm_rate": fp / (fp + tn) if fp + tn else 0.0,
        "estimated_alerts": tp + fp, "estimated_true_alerts": tp, "estimated_false_alarms": fp,
        "estimated_attacks": tp + fn, "estimated_normal": fp + tn,
    }


def _votes_in_batches(model: NetworkSensorModel, flows: pd.DataFrame, batch: int = 100_000) -> pd.DataFrame:
    return pd.concat([model.votes(flows.iloc[i:i + batch]) for i in range(0, len(flows), batch)])


def drift_of_normal_traffic(model: NetworkSensorModel, flows: pd.DataFrame, top: int = 8) -> List[dict]:
    """Which measurements of the 2018 NORMAL flows look least like the 2017 normal
    training flows: the share of 2018 normal flows outside the range that held the
    middle 90% of 2017 normal flows (about 10% if nothing changed)."""
    normal = flows["is_attack"].to_numpy() == 0
    w = flows["weight"].to_numpy()[normal]
    rows = []
    for column in NUMERIC_COLUMNS:
        s = model.normal_profile.numeric[column]
        v = flows[column].to_numpy()[normal]
        outside = (v < s["p5"]) | (v > s["p95"])
        median_2018 = float(np.median(v)) if len(v) else 0.0
        rows.append({"feature": column, "outside_share": float(w[outside].sum() / w.sum()) if w.sum() else 0.0,
                     "median_2017": s["median"], "median_2018": median_2018,
                     "range_2017": [s["p5"], s["p95"]]})
    return sorted(rows, key=lambda r: -r["outside_share"])[:top]


def cross_dataset_check(model: NetworkSensorModel, flows: pd.DataFrame, files: List[dict],
                        normal_share: float, attack_cap: int) -> dict:
    y = flows["is_attack"].to_numpy()
    w = flows["weight"].to_numpy()
    votes = _votes_in_batches(model, flows)
    flagged = model.combine(votes)
    known = votes["random_forest"].to_numpy() == 1

    by_model = {name: _weighted(y, votes[name].to_numpy(), w) for name in votes.columns}
    overall = _weighted(y, flagged, w)

    by_label = []
    for label, group in flows.groupby("label_2018", sort=True):
        idx = group.index.to_numpy()
        is_attack = bool(group["is_attack"].iat[0])
        share = float(flagged[idx].mean())
        # A flow that carries no data either way is a connection attempt that never got an
        # answer (for example to a port where nothing listens), not a conversation.
        no_data = (group["Total Length of Fwd Packets"] == 0) & (group["Total Length of Bwd Packets"] == 0)
        by_label.append({"label_2018": label, "label_2017": group["label"].iat[0],
                         "family": group["attack_category"].iat[0] if is_attack else "normal",
                         "flows_in_files": int(sum(f["labels"].get(label, 0) for f in files)),
                         "checked": int(len(idx)), "flagged_share": share,
                         "no_data_share": float(no_data.mean()),
                         "top_port": str(group["Destination Port"].value_counts().index[0]),
                         "seen_in_training": group["label"].iat[0] in
                                             set(model.training_info.get("attack_types_seen_in_training", []))})

    by_family = []
    for family in FAMILIES:
        mask = flows["attack_category"].to_numpy() == family
        if mask.any():
            by_family.append({"family": family, "checked": int(mask.sum()),
                              "caught": float((w[mask] * flagged[mask]).sum() / w[mask].sum())})

    # Likely type and priority of the alerts (needs the attack-type classifier).
    actionable = None
    if model.has_attack_types and flagged.any():
        rows = np.flatnonzero(flagged == 1)
        _, X = model._checked_matrix(flows.iloc[rows])
        types, _ = model.attack_types_of_matrix(X)
        del X
        truth = flows["attack_category"].to_numpy()[rows]
        real = y[rows] == 1
        wr = w[rows]
        mask = real & known[rows] & (truth != "unknown")
        correct = types == truth
        by_type_family = []
        for family in FAMILIES:
            m = mask & (truth == family)
            if m.any():
                wrong = pd.Series(types[m & ~correct], dtype=object).value_counts()
                by_type_family.append({"family": family, "alerts": int(m.sum()),
                                       "type_correct": float((wr[m] * correct[m]).sum() / wr[m].sum()),
                                       "most_common_wrong_answer": str(wrong.index[0]) if len(wrong) else None})
        priorities = np.array([priority_of(k, t, model.spec)[0] for k, t in zip(known[rows], types)])
        by_priority = []
        for level in PRIORITIES:
            m = priorities == level
            alerts = float(wr[m].sum())
            true_alerts = float(wr[m & real].sum())
            by_priority.append({"priority": level, "estimated_alerts": alerts,
                                "precision": true_alerts / alerts if alerts else 0.0})
        actionable = {
            "type_correct": float((wr[mask] * correct[mask]).sum() / wr[mask].sum()) if mask.any() else 0.0,
            "by_family": by_type_family, "by_priority": by_priority,
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "what": "The CIC-IDS2017 sensor, without retraining, on CSE-CIC-IDS2018 (another network, 2018)",
        "model": {"trained_at": model.training_info.get("trained_at"),
                  "training_rows": model.training_info.get("training_rows")},
        "files": files,
        "sample": {"normal_share": normal_share, "attack_cap_per_type_and_file": attack_cap,
                   "flows_checked": int(len(flows)), "normal_checked": int((y == 0).sum()),
                   "attacks_checked": int((y == 1).sum())},
        "combined": overall,
        "by_model": by_model,
        "by_label": by_label,
        "by_family": by_family,
        "actionable": actionable,
        "normal_traffic_drift": drift_of_normal_traffic(model, flows),
        "target_precision": 0.90,
    }


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def render_markdown(r: dict, same_recording: Optional[dict] = None) -> str:
    c = r["combined"]
    lines = [
        "# Network sensor - CIC-IDS2017 sensor on CSE-CIC-IDS2018 (another network)",
        "",
        f"Generated {r['generated_at']}. {r['what']}. Model trained {r['model']['trained_at']}.",
        "",
        "Why: the CIC-IDS2017 test part comes from the same recording as the training part, so its "
        "score is optimistic. CSE-CIC-IDS2018 was recorded a year later on a different network, with "
        "the next version of the flow tool. Nothing was retrained or adjusted for it.",
        "",
        "## Result",
        "",
        "| | On CIC-IDS2017's test part (same recording) | On CSE-CIC-IDS2018 (another network) |",
        "|---|---|---|",
    ]
    s = same_recording or {}
    lines += [
        f"| Precision (target 90%) | {_pct(s['precision']) if s else '-'} | **{_pct(c['precision'])}** |",
        f"| Attacks caught | {_pct(s['recall']) if s else '-'} | **{_pct(c['recall'])}** |",
        f"| False alarms on normal traffic | {_pct(s['false_alarm_rate']) if s else '-'} | "
        f"**{_pct(c['false_alarm_rate'])}** |",
        "",
        f"Estimated for all {c['estimated_attacks'] + c['estimated_normal']:,.0f} flows of the files "
        f"({c['estimated_attacks']:,.0f} attacks, {c['estimated_normal']:,.0f} normal) from a sample of "
        f"{r['sample']['flows_checked']:,} flows: {_pct(r['sample']['normal_share'])} of the normal flows and up "
        f"to {r['sample']['attack_cap_per_type_and_file']:,} flows of each attack type per file, each counted "
        "for the flows it stands for.",
        "",
        "Each model on its own:",
        "",
        "| Model | Precision | Attacks caught | False alarms on normal traffic |",
        "|---|---|---|---|",
    ]
    for name, m in r["by_model"].items():
        lines.append(f"| {name.replace('_', ' ')} | {_pct(m['precision'])} | {_pct(m['recall'])} | "
                     f"{_pct(m['false_alarm_rate'])} |")
    lines += ["", "## By attack type", "",
              "| 2018 label | Same as 2017 | Family | Flows in the files | Checked | Flagged | No data either way | Usual port |",
              "|---|---|---|---|---|---|---|---|"]
    for row in sorted(r["by_label"], key=lambda x: (x["family"] != "normal", x["family"], x["label_2018"])):
        lines.append(f"| {row['label_2018']} | {row['label_2017']} | {row['family']} | "
                     f"{row['flows_in_files']:,} | {row['checked']:,} | {_pct(row['flagged_share'])} | "
                     f"{_pct(row['no_data_share'])} | {row['top_port']} |")
    lines += ["", "For normal traffic, \"Flagged\" is the false-alarm rate; for attacks, the share caught.",
              "\"No data either way\": flows that carried no data in either direction - connection attempts "
              "that got no conversation going. Where that is 100%, the attack never reached its target "
              "service in that recording, so no flow-based sensor could recognise it as that attack.",
              "", "## By family", "", "| Family | Checked | Caught |", "|---|---|---|"]
    for row in r["by_family"]:
        lines.append(f"| {row['family']} | {row['checked']:,} | {_pct(row['caught'])} |")
    a = r.get("actionable")
    if a:
        lines += ["", "## Likely type and priority of the alerts", "",
                  f"Likely attack family right for {_pct(a['type_correct'])} of known-pattern alerts on real attacks.",
                  "", "| Family | Alerts | Type right | Most common wrong answer |", "|---|---|---|---|"]
        for row in a["by_family"]:
            lines.append(f"| {row['family']} | {row['alerts']:,} | {_pct(row['type_correct'])} | "
                         f"{row['most_common_wrong_answer'] or '-'} |")
        lines += ["", "| Priority | Estimated alerts | Real attacks among them |", "|---|---|---|"]
        for row in a["by_priority"]:
            lines.append(f"| {row['priority']} | {row['estimated_alerts']:,.0f} | {_pct(row['precision'])} |")
    lines += ["", "## How different is the 2018 normal traffic?", "",
              "Share of 2018 normal flows outside the range that held the middle 90% of the 2017 normal "
              "training flows (about 10% if nothing had changed):", "",
              "| Measurement | Outside the 2017 range | 2017 median | 2018 median |", "|---|---|---|---|"]
    for row in r["normal_traffic_drift"]:
        lines.append(f"| {row['feature']} | {_pct(row['outside_share'])} | {row['median_2017']:,.1f} | "
                     f"{row['median_2018']:,.1f} |")
    lines += ["", "## Files", "", "| File | Flows | Attack types |", "|---|---|---|"]
    for f in r["files"]:
        attacks = ", ".join(f"{k} ({v:,})" for k, v in f["labels"].items() if translate_label(k) != NORMAL_LABEL)
        lines.append(f"| {f['name']} | {f['flows']:,} | {attacks or '-'} |")
    return "\n".join(lines) + "\n"


def run(folder: Path, normal_share: float = 0.05, attack_cap: int = 20_000, seed: int = 0,
        log=print) -> Tuple[dict, str]:
    paths = sorted(p for p in Path(folder).glob("*.csv"))
    if not paths:
        raise DatasetError(f"No .csv files in {folder}. Download the CSE-CIC-IDS2018 files from\n    {DOWNLOAD_PAGE}\n"
                           "(\"Processed Traffic Data for ML Algorithms\") into one folder.")
    path = model_path("cicids2017")
    if not path.exists():
        raise DatasetError("The CIC-IDS2017 sensor is not trained yet. Run first:\n"
                           "    python -m network_sensor.train --dataset cicids2017")
    model = NetworkSensorModel.load(path, dataset="cicids2017")
    rng = np.random.default_rng(seed)
    files, parts = [], []
    for p in paths:
        log(f"Reading {p.name} ...")
        counts = count_labels(p)
        files.append({"name": p.name, "flows": int(counts.sum()),
                      "labels": {str(k): int(v) for k, v in counts.sort_values(ascending=False).items()}})
        sample = sample_file(p, counts, normal_share, attack_cap, rng)
        log(f"  {int(counts.sum()):,} flows; {len(sample):,} in the sample")
        parts.append(sample)
    flows = pd.concat(parts, ignore_index=True)
    unknown = sorted(set(flows.loc[flows["attack_category"] == "unknown", "label_2018"]))
    if unknown:
        log(f"Note: labels with no CIC-IDS2017 match (kept as attacks of unknown type): {', '.join(unknown)}")
    log(f"Checking {len(flows):,} flows with the CIC-IDS2017 sensor ...")
    results = cross_dataset_check(model, flows, files, normal_share, attack_cap)
    same = None
    report = reports_dir("cicids2017") / "evaluation_report.json"
    if report.exists():
        same = json.loads(report.read_text(encoding="utf-8")).get("models", {}).get("combined")
    results["same_recording_combined"] = same
    return results, render_markdown(results, same)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Score the CIC-IDS2017 sensor on CSE-CIC-IDS2018 files.")
    parser.add_argument("folder", help="folder with the CSE-CIC-IDS2018 CSV files")
    parser.add_argument("--normal-share", type=float, default=0.05,
                        help="share of the normal flows to check (default 0.05 = 5%%)")
    parser.add_argument("--attack-cap", type=int, default=20_000,
                        help="at most about this many flows of each attack type per file (default 20000)")
    args = parser.parse_args(argv)
    try:
        results, markdown = run(Path(args.folder), args.normal_share, args.attack_cap)
    except DatasetError as e:
        print(f"ERROR: {e}")
        return 1
    folder = reports_dir("cicids2017")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "cross_dataset_cicids2018.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (folder / "cross_dataset_cicids2018.md").write_text(markdown, encoding="utf-8")
    c = results["combined"]
    print(f"\nPrecision {_pct(c['precision'])}, attacks caught {_pct(c['recall'])}, "
          f"false alarms on {_pct(c['false_alarm_rate'])} of normal traffic.")
    print(f"Report: {folder / 'cross_dataset_cicids2018.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
