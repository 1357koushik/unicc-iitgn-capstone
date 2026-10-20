"""
Everything about the NSL-KDD dataset: reading its files into a table (a pandas
DataFrame), and what its measurements mean in plain English.

Each row is one network connection, described by 41 measurements (how long it lasted,
how many bytes went each way, how many connections the same machine made in the last
two seconds, ...) plus a label: "normal" or the name of the attack, e.g. "neptune".
"""
from pathlib import Path
from typing import Dict, Optional

import pandas as pd

from network_sensor.paths import dataset_dir
from network_sensor.spec import DatasetSpec

# The 41 measurements, in the order they appear in the files.
FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]   # text values, e.g. "tcp", "http"
NUMERIC_COLUMNS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]
# Each file row = 41 measurements + label + a "difficulty" score added by the dataset authors.
FILE_COLUMNS = FEATURE_COLUMNS + ["label", "difficulty"]

# The four standard attack families used with this dataset.
ATTACK_CATEGORIES = {
    # DoS - denial of service: flood a machine so real users cannot reach it
    **dict.fromkeys(["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
                     "mailbomb", "processtable", "udpstorm"], "DoS"),
    # Probe - scanning the network to find machines and open ports
    **dict.fromkeys(["ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"], "Probe"),
    # R2L - remote to local: an outsider trying to get in (e.g. password guessing)
    **dict.fromkeys(["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy",
                     "warezclient", "warezmaster", "sendmail", "named", "snmpgetattack",
                     "snmpguess", "xlock", "xsnoop", "worm"], "R2L"),
    # U2R - user to root: a logged-in user trying to become administrator
    **dict.fromkeys(["buffer_overflow", "loadmodule", "perl", "rootkit", "httptunnel", "ps",
                     "sqlattack", "xterm"], "U2R"),
}

SPLIT_FILES = {"train": "KDDTrain+.txt", "test": "KDDTest+.txt"}

FAMILY_MEANINGS = {"DoS": "flooding a service so real users cannot reach it",
                   "Probe": "scanning for machines and open ports",
                   "R2L": "an outsider trying to get in, e.g. guessing passwords",
                   "U2R": "a logged-in user trying to become administrator"}

# Plain-English meaning of each measurement (definitions from the KDD Cup 1999 /
# NSL-KDD documentation). "Recent" = the 2 seconds before this connection;
# "last 100" = the 100 connections before it that went to the same destination machine.
FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "duration": "Length of the connection",
    "protocol_type": "Protocol",
    "service": "Network service on the destination",
    "flag": "Connection status",
    "src_bytes": "Data sent by the source",
    "dst_bytes": "Data sent back by the destination",
    "land": "Source and destination are the same machine and port",
    "wrong_fragment": "Malformed packet fragments",
    "urgent": "Urgent packets",
    "hot": "'Hot' actions (e.g. entering system folders, running programs)",
    "num_failed_logins": "Failed login attempts",
    "logged_in": "Login succeeded",
    "num_compromised": "'Compromised' conditions",
    "root_shell": "Administrator (root) shell obtained",
    "su_attempted": "'su root' command attempted",
    "num_root": "Administrator (root) accesses",
    "num_file_creations": "Files created",
    "num_shells": "Shell prompts opened",
    "num_access_files": "Operations on access-control files",
    "num_outbound_cmds": "Outbound commands in an FTP session",
    "is_host_login": "Login is on the 'hot' list",
    "is_guest_login": "Guest login",
    "count": "Connections to the same machine in the last 2 seconds",
    "srv_count": "Connections to the same service in the last 2 seconds",
    "serror_rate": "Recent connections to this machine left half-open (SYN errors)",
    "srv_serror_rate": "Recent connections to this service left half-open (SYN errors)",
    "rerror_rate": "Recent connections to this machine rejected",
    "srv_rerror_rate": "Recent connections to this service rejected",
    "same_srv_rate": "Recent connections to this machine using the same service",
    "diff_srv_rate": "Recent connections to this machine using different services",
    "srv_diff_host_rate": "Recent connections to this service going to different machines",
    "dst_host_count": "Of the last 100 connections, number going to this machine",
    "dst_host_srv_count": "Of the last 100 connections, number going to this machine and service",
    "dst_host_same_srv_rate": "Of the last 100 connections to this machine, share using the same service",
    "dst_host_diff_srv_rate": "Of the last 100 connections to this machine, share using different services",
    "dst_host_same_src_port_rate": "Of the last 100 connections to this machine, share from the same source port",
    "dst_host_srv_diff_host_rate": "Of the last 100 connections to this service, share going to different machines",
    "dst_host_serror_rate": "Of the last 100 connections to this machine, share left half-open",
    "dst_host_srv_serror_rate": "Of the last 100 connections to this service, share left half-open",
    "dst_host_rerror_rate": "Of the last 100 connections to this machine, share rejected",
    "dst_host_srv_rerror_rate": "Of the last 100 connections to this service, share rejected",
}

# What the connection-status codes mean (they come from the Bro/Zeek network monitor).
FLAG_MEANINGS = {
    "SF": "normal start and finish",
    "S0": "request sent, never answered - half-open",
    "S1": "connected, not closed",
    "S2": "connected, only the source tried to close",
    "S3": "connected, only the destination tried to close",
    "REJ": "connection refused",
    "RSTO": "source aborted the connection",
    "RSTR": "destination aborted the connection",
    "RSTOS0": "source sent a request and then aborted, no answer",
    "SH": "source sent a request and a close, no answer - a stealth scan pattern",
    "OTH": "no start of the connection was seen",
}

# Measurements that tell the same story; only the rarest one of each group is shown,
# so an analyst does not read "half-open" four times.
FEATURE_GROUPS = {
    "half_open": ["serror_rate", "srv_serror_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate"],
    "rejected": ["rerror_rate", "srv_rerror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"],
    "service_mix": ["same_srv_rate", "diff_srv_rate", "dst_host_same_srv_rate", "dst_host_diff_srv_rate"],
    "recent_volume": ["count", "srv_count"],
    "volume_last_100": ["dst_host_count", "dst_host_srv_count"],
    "spread": ["srv_diff_host_rate", "dst_host_srv_diff_host_rate"],
    "root_activity": ["num_root", "num_compromised"],
}
GROUP_OF = {f: g for g, members in FEATURE_GROUPS.items() for f in members}

YES_NO_COLUMNS = {"land", "logged_in", "root_shell", "is_host_login", "is_guest_login"}


def format_value(column: str, value) -> str:
    if column == "flag":
        return f"{value} = {FLAG_MEANINGS.get(str(value), 'unknown status')}"
    if column in CATEGORICAL_COLUMNS:
        return str(value)
    v = float(value)
    if column.endswith("_rate"):
        return f"{v:.0%}"
    if column in YES_NO_COLUMNS:
        return "yes" if v >= 1 else "no"
    if column in ("src_bytes", "dst_bytes"):
        return f"{v:,.0f} bytes"
    if column == "duration":
        return f"{v:,.0f} seconds"
    return f"{v:,.0f}"


class DatasetError(Exception):
    """The dataset file is missing or not in the expected format."""


def attack_category(label: str) -> str:
    if label == "normal":
        return "normal"
    return ATTACK_CATEGORIES.get(label, "unknown")


def load_nsl_kdd(split: str, folder: Optional[Path] = None) -> pd.DataFrame:
    """Load the 'train' or 'test' file.

    Adds two columns: is_attack (1 = attack, 0 = normal) and attack_category
    (normal / DoS / Probe / R2L / U2R)."""
    if split not in SPLIT_FILES:
        raise ValueError(f"split must be one of {sorted(SPLIT_FILES)}, not {split!r}")
    path = Path(folder or dataset_dir()) / SPLIT_FILES[split]
    if not path.exists():
        raise DatasetError(f"{path} was not found. Download the dataset first:\n"
                           "    python -m network_sensor.download_data")

    df = pd.read_csv(path, header=None)
    if df.shape[1] != len(FILE_COLUMNS):
        raise DatasetError(f"{path.name} has {df.shape[1]} columns per row; "
                           f"NSL-KDD files have {len(FILE_COLUMNS)}.")
    df.columns = FILE_COLUMNS
    df["label"] = df["label"].astype(str).str.strip().str.rstrip(".")
    df["is_attack"] = (df["label"] != "normal").astype(int)
    df["attack_category"] = df["label"].map(attack_category)
    return df


NSL_KDD_SPEC = DatasetSpec(
    name="nsl_kdd",
    title="NSL-KDD",
    feature_columns=tuple(FEATURE_COLUMNS),
    categorical_columns=tuple(CATEGORICAL_COLUMNS),
    skewed_columns=("duration", "src_bytes", "dst_bytes"),
    descriptions=FEATURE_DESCRIPTIONS,
    groups=FEATURE_GROUPS,
    yes_no_columns=frozenset(YES_NO_COLUMNS),
    families=("DoS", "Probe", "R2L", "U2R"),
    family_meanings=FAMILY_MEANINGS,
    family_of=attack_category,
    normal_label="normal",
    format_value=format_value,
    test_description="official test file KDDTest+.txt",
    limitations=(
        "NSL-KDD is built from 1998 network traffic. It is the standard public benchmark, but "
        "modern traffic looks different; the sensor is also tested on CIC-IDS2017 (2017 traffic).",
        "The 41 measurements come with the dataset. The sensor does not yet compute them from "
        "live network traffic itself.",
        "The test file deliberately contains attack types that are not in the training file, "
        "which is why recall is lower than precision.",
        "Settings (anomaly share, tree counts) were fixed in advance and not tuned on the test file. "
        "The decision rule was chosen after an initial comparison of a few combinations on this same "
        "test file, so a fully independent check would use a second dataset.",
    ),
)
