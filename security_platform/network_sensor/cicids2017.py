"""
Everything about the CIC-IDS2017 dataset: checking the downloaded file, reading it,
splitting it into a training part and a test part, and what its measurements mean.

CIC-IDS2017 is modern network traffic: five working days (3-7 July 2017) in a test
network of the Canadian Institute for Cybersecurity, University of New Brunswick,
with normal user activity and labelled attacks (password guessing on FTP and SSH,
DoS and DDoS floods, web attacks, a botnet, port scans, infiltration, Heartbleed):
    https://www.unb.ca/cic/datasets/ids-2017.html

Each row is one network FLOW: the packets between two machines (and ports) until the
connection ends or times out, described by measurements from the CICFlowMeter tool
(packet sizes, timing, TCP flags, ...). "Source" is the machine that started the flow,
"destination" the one it contacted.

Getting it (once):
  1. On the page above, choose "Download this dataset" and download
     MachineLearningCSV.zip (only that file; the PCAP files are not needed).
  2. In the project folder, with the .venv switched on:
         python -m network_sensor.cicids2017 "C:\\path\\to\\MachineLearningCSV.zip"
     This checks the file and keeps a copy in data/network_sensor/cicids2017/.
  3. python -m network_sensor.train --dataset cicids2017
     python -m network_sensor.evaluate --dataset cicids2017
"""
import hashlib
import re
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd

from network_sensor.datasets import DatasetError
from network_sensor.paths import dataset_dir
from network_sensor.spec import UNDEFINED_VALUE, DatasetSpec

ZIP_NAME = "MachineLearningCSV.zip"
DOWNLOAD_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"

# The eight files inside the zip: SHA-256 fingerprint of each file's contents, and its
# number of flows. Checked before the data is used, so everyone trains and tests on
# exactly the same data. Taken from the official download (its MD5 matched the one
# published next to it, 4f83860afbf29cac8163854095bf6cf7); the 2,830,743 flows and the
# count of every label match the numbers published for CIC-IDS2017.
FILES: Dict[str, Tuple[str, int]] = {
    "Monday-WorkingHours.pcap_ISCX.csv":
        ("852c4beb34eda186f32561fa79df7a0747e92e1a6535b01270820dd9ffe17f34", 529_918),
    "Tuesday-WorkingHours.pcap_ISCX.csv":
        ("52b8692ae8c7d2ed04671fe2b98335693c0a92c7ab157d8c8b534d6523080851", 445_909),
    "Wednesday-workingHours.pcap_ISCX.csv":
        ("893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a", 692_703),
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv":
        ("d67066211fb1689c78406f1506f4c44704ecb92088353d5c96d96d6474eb819d", 170_366),
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv":
        ("6bcda3857c2504676034e3ea57762d38393cc734cb377a726bd5cb153961b1b5", 288_602),
    "Friday-WorkingHours-Morning.pcap_ISCX.csv":
        ("53a41c24d570ea83b7ac55b2e94df94e7a8216aeb80a2af0246b6bc8bb543000", 191_033),
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv":
        ("ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b", 286_467),
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv":
        ("6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee", 225_745),
}

NORMAL_LABEL = "BENIGN"
# Attack label -> family. In the official files the web attack labels contain a broken
# character where a dash was meant ("Web Attack \ufffd Brute Force"); clean_label turns
# it (or a Windows dash) into a normal "-".
FAMILY_OF_LABEL = {
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "Brute Force", "SSH-Patator": "Brute Force",
    "Web Attack - Brute Force": "Web Attack", "Web Attack - XSS": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
}
FAMILIES = ("DoS", "DDoS", "PortScan", "Brute Force", "Web Attack", "Botnet", "Infiltration", "Heartbleed")
FAMILY_MEANINGS = {
    "DoS": "flooding or tying up a web server so real users cannot reach it",
    "DDoS": "the same, from many machines at once",
    "PortScan": "scanning a machine for open ports",
    "Brute Force": "guessing FTP and SSH passwords",
    "Web Attack": "attacks on a website: password guessing, cross-site scripting, SQL injection",
    "Botnet": "infected machines taking orders from an attacker",
    "Infiltration": "an attacker inside the network after a malicious download",
    "Heartbleed": "exploiting the Heartbleed bug to read a server's memory",
}
# What each family could do if it succeeds (see actions.py for how this sets an
# alert's priority), and one suggested first step for an analyst.
FAMILY_IMPACT = {"DoS": "Medium", "DDoS": "Medium", "PortScan": "Low", "Brute Force": "High",
                 "Web Attack": "High", "Botnet": "High", "Infiltration": "High", "Heartbleed": "High"}
FAMILY_ACTIONS = {
    "DoS": "Check whether the web server is slowing down or failing. If it is, rate-limit or block the "
           "source at the firewall or load balancer and tell the team that runs the server.",
    "DDoS": "Many machines may be flooding the server. Check that it is still reachable, turn on rate "
            "limiting, and ask the network provider about filtering upstream if the traffic keeps growing.",
    "PortScan": "Someone is scanning for open ports. Check which ports the scan reached and close any that "
                "should not be open; block the source if it is outside the organisation.",
    "Brute Force": "Someone may be guessing FTP or SSH passwords. Check the server's login log for successful "
                   "logins from this source, lock affected accounts, and block the source or limit login attempts.",
    "Web Attack": "Check the web server's request log for this connection (password guessing, SQL injection "
                  "or cross-site scripting attempts), confirm the site rejects such input, and block the "
                  "source if the attempts continue.",
    "Botnet": "A machine inside the network may be infected and taking orders from an attacker. Isolate it, "
              "scan it for malware, and block the address it is talking to.",
    "Infiltration": "An attacker may already be inside the network. Isolate the internal machine involved, "
                    "check what it downloaded and connected to, and start incident response.",
    "Heartbleed": "Someone may be exploiting the Heartbleed bug. Update OpenSSL on the target server now, "
                  "then replace its certificates and keys and make users log in again, because secrets may "
                  "have leaked.",
}

# Every column of the official files (names without their leading spaces), in order.
ALL_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max",
    "Idle Min", "Label",
]

# Columns the sensor does not use, because in every one of the 2,830,743 flows they
# add nothing (checked on the official files):
UNUSED_COLUMNS = {
    # always zero
    "Bwd PSH Flags", "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    # exact copies of another column
    "Fwd Header Length.1",          # = Fwd Header Length (the file has that column twice)
    "Subflow Fwd Packets",          # = Total Fwd Packets
    "Subflow Bwd Packets",          # = Total Backward Packets
    "Fwd PSH Flags",                # = SYN Flag Count
    "Fwd URG Flags",                # = CWE Flag Count
}
FEATURE_COLUMNS = [c for c in ALL_COLUMNS if c != "Label" and c not in UNUSED_COLUMNS]
CATEGORICAL_COLUMNS = ["Destination Port"]
NUMERIC_COLUMNS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]
# A rate is undefined for a flow that lasted 0 microseconds (division by zero); the
# official files then hold "Infinity" or an empty value.
MAY_BE_UNDEFINED = {"Flow Bytes/s", "Flow Packets/s"}

TIME_COLUMNS = {c for c in NUMERIC_COLUMNS
                if c == "Flow Duration" or " IAT " in f" {c} " or c.startswith(("Active", "Idle"))}
BYTE_COLUMNS = {"Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Header Length",
                "Bwd Header Length", "Subflow Fwd Bytes", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
                "Init_Win_bytes_backward", "min_seg_size_forward", "Average Packet Size",
                "Avg Fwd Segment Size", "Avg Bwd Segment Size"} | {
    c for c in NUMERIC_COLUMNS if "Packet Length" in c and not c.endswith("Variance")}
RATE_COLUMNS = {"Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s"}

_SOURCE, _DESTINATION = "the source", "the destination"


def _size_descriptions(prefix: str, who: str) -> Dict[str, str]:
    return {f"{prefix} Packet Length Max": f"Largest packet from {who}",
            f"{prefix} Packet Length Min": f"Smallest packet from {who}",
            f"{prefix} Packet Length Mean": f"Average packet size from {who}",
            f"{prefix} Packet Length Std": f"Variation in packet size from {who}"}


def _gap_descriptions(prefix: str, who: str) -> Dict[str, str]:
    return {f"{prefix} IAT Total": f"Total time between packets from {who}",
            f"{prefix} IAT Mean": f"Average gap between packets from {who}",
            f"{prefix} IAT Std": f"Variation in the gap between packets from {who}",
            f"{prefix} IAT Max": f"Longest gap between packets from {who}",
            f"{prefix} IAT Min": f"Shortest gap between packets from {who}"}


FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "Destination Port": "Destination port (the service contacted)",
    "Flow Duration": "Length of the flow",
    "Total Fwd Packets": "Packets sent by the source",
    "Total Backward Packets": "Packets sent back by the destination",
    "Total Length of Fwd Packets": "Data sent by the source",
    "Total Length of Bwd Packets": "Data sent back by the destination",
    **_size_descriptions("Fwd", _SOURCE),
    **_size_descriptions("Bwd", _DESTINATION),
    "Flow Bytes/s": "Data rate of the flow",
    "Flow Packets/s": "Packet rate of the flow",
    "Flow IAT Mean": "Average gap between packets",
    "Flow IAT Std": "Variation in the gap between packets",
    "Flow IAT Max": "Longest gap between packets",
    "Flow IAT Min": "Shortest gap between packets",
    **_gap_descriptions("Fwd", _SOURCE),
    **_gap_descriptions("Bwd", _DESTINATION),
    "Fwd Header Length": "Header bytes sent by the source",
    "Bwd Header Length": "Header bytes sent back by the destination",
    "Fwd Packets/s": "Packet rate from the source",
    "Bwd Packets/s": "Packet rate from the destination",
    "Min Packet Length": "Smallest packet in the flow",
    "Max Packet Length": "Largest packet in the flow",
    "Packet Length Mean": "Average packet size in the flow",
    "Packet Length Std": "Variation in packet size in the flow",
    "Packet Length Variance": "Variation in packet size in the flow (squared)",
    # The TCP flag columns of the official files are known to be mislabelled (for example,
    # port-scan flows - which consist of SYN packets - show 0 in "SYN Flag Count" but 1 in
    # "PSH Flag Count"), so they are named only by their column names, not by what the
    # names claim.
    **{f"{flag} Flag Count": f"TCP flag count the dataset calls '{flag}'"
       for flag in ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE")},
    "Down/Up Ratio": "Packets received compared with packets sent (download/upload ratio)",
    "Average Packet Size": "Average packet size",
    "Avg Fwd Segment Size": "Average data per packet from the source",
    "Avg Bwd Segment Size": "Average data per packet from the destination",
    "Subflow Fwd Bytes": "Data per burst from the source",
    "Subflow Bwd Bytes": "Data per burst from the destination",
    "Init_Win_bytes_forward": "Source's starting TCP window (how much data it accepts at once)",
    "Init_Win_bytes_backward": "Destination's starting TCP window (how much data it accepts at once)",
    "act_data_pkt_fwd": "Packets from the source that carried data",
    "min_seg_size_forward": "Smallest header seen from the source",
    "Active Mean": "Average time the flow was active before going quiet",
    "Active Std": "Variation in active time",
    "Active Max": "Longest active period",
    "Active Min": "Shortest active period",
    "Idle Mean": "Average quiet time between active periods",
    "Idle Std": "Variation in quiet time",
    "Idle Max": "Longest quiet period",
    "Idle Min": "Shortest quiet period",
}

# Measurements that tell the same story; only the rarest one of each group is shown.
FEATURE_GROUPS = {
    "source_packet_size": ["Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
                           "Fwd Packet Length Std", "Avg Fwd Segment Size"],
    "destination_packet_size": ["Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
                                "Bwd Packet Length Std", "Avg Bwd Segment Size"],
    "packet_size": ["Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
                    "Packet Length Variance", "Average Packet Size"],
    "source_volume": ["Total Fwd Packets", "Total Length of Fwd Packets", "Subflow Fwd Bytes",
                      "act_data_pkt_fwd", "Fwd Header Length"],
    "destination_volume": ["Total Backward Packets", "Total Length of Bwd Packets", "Subflow Bwd Bytes",
                           "Bwd Header Length"],
    "gaps": ["Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min"],
    "source_gaps": [c for c in FEATURE_DESCRIPTIONS if c.startswith("Fwd IAT")],
    "destination_gaps": [c for c in FEATURE_DESCRIPTIONS if c.startswith("Bwd IAT")],
    "rates": sorted(RATE_COLUMNS),
    "active": ["Active Mean", "Active Std", "Active Max", "Active Min"],
    "idle": ["Idle Mean", "Idle Std", "Idle Max", "Idle Min"],
}

WELL_KNOWN_PORTS = {
    "21": "FTP", "22": "SSH", "23": "Telnet", "25": "email (SMTP)", "53": "DNS", "80": "web (HTTP)",
    "88": "Kerberos", "110": "email (POP3)", "123": "time (NTP)", "135": "Windows RPC",
    "137": "Windows name service", "138": "Windows datagram service", "139": "Windows file sharing",
    "143": "email (IMAP)", "389": "directory (LDAP)", "443": "secure web (HTTPS)",
    "445": "Windows file sharing (SMB)", "465": "email (SMTPS)", "993": "email (IMAPS)",
    "3268": "directory (LDAP)", "3389": "remote desktop", "8080": "web (HTTP, alternative port)",
}


def _format_time(microseconds: float) -> str:
    v = abs(microseconds)
    sign = "-" if microseconds < 0 else ""
    if v < 1_000:
        return f"{sign}{v:,.0f} microseconds"
    if v < 1_000_000:
        return f"{sign}{v / 1_000:,.1f} ms"
    return f"{sign}{v / 1_000_000:,.1f} seconds"


def _count(v: float, unit: str) -> str:
    return f"{v:,.0f} {unit}" + ("" if v == 1 else "s")


def format_value(column: str, value) -> str:
    """How a value of a CIC-IDS2017 measurement is shown in explanations."""
    if column == "Destination Port":
        name = WELL_KNOWN_PORTS.get(str(value))
        return f"{value} = {name}" if name else str(value)
    v = float(value)
    if column in MAY_BE_UNDEFINED and v == UNDEFINED_VALUE:
        return "undefined (the flow lasted 0 microseconds)"
    if column in ("Init_Win_bytes_forward", "Init_Win_bytes_backward") and v == -1:
        return "not seen"
    if column in TIME_COLUMNS:
        return _format_time(v)
    if column in RATE_COLUMNS:
        return _count(v, "byte" if column == "Flow Bytes/s" else "packet") + " per second"
    if column in BYTE_COLUMNS:
        return _count(v, "byte")
    if column == "Down/Up Ratio":
        return f"{v:,.2f}"
    if column.endswith(("Flag Count", "Flags")) or "Packets" in column or column == "act_data_pkt_fwd":
        return _count(v, "packet")
    return f"{v:,.0f}"


def family_of(label: str) -> str:
    """The family of an attack label. A family name itself ("DoS", "Brute Force", ...)
    also counts, so people labelling their own traffic can use it (see own_data.py)."""
    if label == NORMAL_LABEL:
        return "normal"
    return FAMILY_OF_LABEL.get(label, label if label in FAMILIES else "unknown")


CICIDS2017_SPEC = DatasetSpec(
    name="cicids2017",
    title="CIC-IDS2017",
    feature_columns=tuple(FEATURE_COLUMNS),
    categorical_columns=tuple(CATEGORICAL_COLUMNS),
    # Byte counts, packet counts, times and rates all range from 0 to millions or billions.
    skewed_columns=tuple(NUMERIC_COLUMNS),
    descriptions=FEATURE_DESCRIPTIONS,
    groups=FEATURE_GROUPS,
    yes_no_columns=frozenset(),
    families=FAMILIES,
    family_meanings=FAMILY_MEANINGS,
    family_impact=FAMILY_IMPACT,
    family_actions=FAMILY_ACTIONS,
    family_of=family_of,
    normal_label=NORMAL_LABEL,
    format_value=format_value,
    test_description="test part, 30% of the flows",
    # The official files contain a few negative times and window sizes of -1 ("not seen").
    allow_negative=True,
    may_be_undefined=frozenset(MAY_BE_UNDEFINED),
    # Ports: the 39 most common get their own model input, the rest share one.
    max_categories=40,
    explain_per_label=2_000,
    new_attack_check=True,
    # Chosen with  python -m network_sensor.calibrate --dataset cicids2017  on a validation
    # slice of the TRAINING part (394,974 flows): 5% -> 88.9% precision, 2% -> 95.9%,
    # 1% -> 98.0%, 0.5% -> 99.0%, 0.2% -> 99.3%. Rule: the largest share with at least 95%.
    anomaly_share=0.02,
    limitations=(
        "CIC-IDS2017 was recorded in a test network over five working days in July 2017. It is a "
        "widely used modern benchmark, but real UNICC traffic will look different.",
        "Researchers have found labelling and measurement mistakes in this dataset (for example "
        "Engelen, Rimmer and Joosen, 2021). The official files are used as published, so a few "
        "'errors' in this report may really be wrong labels: 698 sets of identical measurements "
        "(7,020 flows) carry different labels, so no sensor can get all of them right. The TCP flag "
        "columns are also mislabelled (port-scan flows show 0 in 'SYN Flag Count' but 1 in 'PSH Flag "
        "Count'), so explanations name flag counts only by their column names.",
        "There is no official training/test split. Each flow goes to the training part (70%) or the "
        "test part (30%) by a fingerprint of its measurements, so identical flows are never on both "
        "sides. Flows from the same attack session are still very similar to each other, so the test "
        "part is easier than truly new traffic; the 'New attack types' section is the harder check.",
        "The sensor was trained on a sample of the training part (see the last line) so that training "
        "takes minutes on a laptop.",
        "The decision rule and the other model settings were fixed on NSL-KDD before this dataset was "
        "used. The anomaly models' false-alarm budget was first taken from NSL-KDD too (5%): on this test "
        "part that gave 89.1% precision, almost all false alarms coming from the anomaly models. It was "
        "then re-chosen (2%) on a validation slice of the training part only (python -m "
        "network_sensor.calibrate --dataset cicids2017: 88.9% at 5%, 95.9% at 2%). Because that change "
        "was made after seeing a test result, treat this report's precision as slightly optimistic.",
        "The measurements come with the dataset. To watch real traffic, the same tool that made them "
        "(CICFlowMeter) would turn captured packets into these measurements.",
    ),
)

# ----------------------------------------------------------------------------- the file

TEST_SHARE = 0.30
# Training uses a random sample of the training part: up to this many flows of each
# label, and more normal flows because normal traffic is the most varied.
TRAINING_NORMAL_FLOWS = 250_000
TRAINING_FLOWS_PER_ATTACK_TYPE = 50_000


def sha256_of_member(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name) as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def csv_members(archive: zipfile.ZipFile):
    """The CSV files in the zip, by file name (without the folder)."""
    return {Path(n).name: n for n in archive.namelist() if n.lower().endswith(".csv")}


def check_zip(path: Path) -> Dict[str, str]:
    """Check that the zip holds exactly the official files (by fingerprint).
    Returns {file name: SHA-256}; raises DatasetError if anything differs."""
    path = Path(path)
    if not path.exists():
        raise DatasetError(f"{path} was not found.")
    try:
        with zipfile.ZipFile(path) as archive:
            members = csv_members(archive)
            found = {name: sha256_of_member(archive, member) for name, member in sorted(members.items())}
    except (zipfile.BadZipFile, OSError) as e:
        raise DatasetError(f"{path} could not be read as a zip file: {e}")
    if FILES:
        expected = {name: sha for name, (sha, _) in FILES.items()}
        if found != expected:
            missing = sorted(set(expected) - set(found))
            extra = sorted(set(found) - set(expected))
            changed = sorted(n for n in set(found) & set(expected) if found[n] != expected[n])
            raise DatasetError(
                f"{path.name} is not the official CIC-IDS2017 MachineLearningCSV.zip, so it was not used."
                + (f"\n  missing files: {', '.join(missing)}" if missing else "")
                + (f"\n  unexpected files: {', '.join(extra)}" if extra else "")
                + (f"\n  files with different contents: {', '.join(changed)}" if changed else ""))
    return found


def clean_label(label: str) -> str:
    """'Web Attack \\x96 Brute Force' (odd dash in the official files) -> 'Web Attack - Brute Force'."""
    return re.sub(r"\s*[^\x20-\x7e]+\s*", " - ", str(label)).strip()


def read_csv_file(source) -> pd.DataFrame:
    """Read one CIC-IDS2017 CSV file (a path or an open file) into a table with the
    official column names (leading spaces removed) and cleaned labels."""
    df = pd.read_csv(source, encoding="latin-1", low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    if list(df.columns) != ALL_COLUMNS:
        raise DatasetError("The file does not have the CIC-IDS2017 columns "
                           f"(found {len(df.columns)} columns, starting {list(df.columns)[:3]}).")
    df["Label"] = df["Label"].map(clean_label)
    return df


def to_flows(df: pd.DataFrame) -> pd.DataFrame:
    """Official columns -> the table the sensor uses: the measurement columns, plus
    label, is_attack (1 = attack, 0 = normal) and attack_category (the family)."""
    flows = df[FEATURE_COLUMNS].copy()
    flows["Destination Port"] = pd.to_numeric(flows["Destination Port"]).astype("int64").astype(str)
    for column in NUMERIC_COLUMNS:
        values = pd.to_numeric(flows[column], errors="coerce")
        if column in MAY_BE_UNDEFINED:
            values = values.replace([np.inf, -np.inf], np.nan).fillna(UNDEFINED_VALUE)
        flows[column] = values.astype(float)
    flows["label"] = df["Label"].to_numpy()
    flows["is_attack"] = (flows["label"] != NORMAL_LABEL).astype(int)
    flows["attack_category"] = flows["label"].map(family_of)
    return flows


def split_of(flows: pd.DataFrame) -> np.ndarray:
    """'train' or 'test' for each flow, from a fingerprint of its measurements. The same
    measurements always land on the same side, on every computer, so identical flows
    are never in both parts."""
    fingerprint = pd.util.hash_pandas_object(flows[FEATURE_COLUMNS], index=False).to_numpy()
    return np.where(fingerprint % 100 < round(TEST_SHARE * 100), "test", "train")


def zip_path() -> Path:
    return dataset_dir("cicids2017") / ZIP_NAME


def read_all(path: Optional[Path] = None, split: Optional[str] = None) -> pd.DataFrame:
    """All flows of the eight files, with a 'split' column ('train' / 'test'). With
    split given, only that part is kept (read file by file, which needs much less memory)."""
    path = Path(path or zip_path())
    if not path.exists():
        raise DatasetError(f"{path} was not found. Download {ZIP_NAME} from\n    {DOWNLOAD_PAGE}\n"
                           "then run:  python -m network_sensor.cicids2017 <path to the zip file>")
    parts = []
    with zipfile.ZipFile(path) as archive:
        for name, member in sorted(csv_members(archive).items()):
            with archive.open(member) as f:
                flows = to_flows(read_csv_file(f))
            flows["split"] = split_of(flows)
            parts.append(flows if split is None else flows[flows["split"] == split])
    return pd.concat(parts, ignore_index=True)


def training_sample(part: pd.DataFrame, seed: int = 0) -> pd.DataFrame:
    """The random sample the sensor trains on: up to TRAINING_NORMAL_FLOWS normal flows
    and up to TRAINING_FLOWS_PER_ATTACK_TYPE flows of each attack type."""
    full_rows = len(part)
    caps = {label: TRAINING_NORMAL_FLOWS if label == NORMAL_LABEL else TRAINING_FLOWS_PER_ATTACK_TYPE
            for label in part["label"].unique()}
    sample = pd.concat([group.sample(n=min(caps[label], len(group)), random_state=seed)
                        for label, group in part.groupby("label", sort=True)]).sort_index().reset_index(drop=True)
    sample.attrs["sample"] = {
        "note": f"a random sample of {full_rows:,} training flows: up to "
                f"{TRAINING_NORMAL_FLOWS:,} normal flows and up to {TRAINING_FLOWS_PER_ATTACK_TYPE:,} "
                "of each attack type",
        "training_part_rows": int(full_rows),
        "normal_cap": TRAINING_NORMAL_FLOWS,
        "attack_type_cap": TRAINING_FLOWS_PER_ATTACK_TYPE,
    }
    sample.attrs["sample_note"] = f"Training on {sample.attrs['sample']['note']}."
    return sample


def load_cicids2017(split: str, path: Optional[Path] = None, sample: bool = True, seed: int = 0) -> pd.DataFrame:
    """The 'train' or 'test' part. For 'train', with sample=True, the random training
    sample (see training_sample); the full part with sample=False."""
    if split not in ("train", "test"):
        raise ValueError(f"split must be 'train' or 'test', not {split!r}")
    part = read_all(path, split).drop(columns="split").reset_index(drop=True)
    if split == "train" and sample:
        return training_sample(part, seed)
    return part


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    target = zip_path()
    source = Path(args[0]) if args else target
    if not source.exists():
        print(f"ERROR: {source} was not found.\n\nDownload {ZIP_NAME} from\n    {DOWNLOAD_PAGE}\n"
              "then run:  python -m network_sensor.cicids2017 <path to the zip file>")
        return 1
    print(f"Checking {source} ...")
    try:
        found = check_zip(source)
    except DatasetError as e:
        print(f"ERROR: {e}")
        return 1
    for name in found:
        print(f"  OK  {name}")
    if source.resolve() != target.resolve():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        print(f"Copied to {target}")
    print("\nDone. Next step:  python -m network_sensor.train --dataset cicids2017")
    return 0


if __name__ == "__main__":
    sys.exit(main())
