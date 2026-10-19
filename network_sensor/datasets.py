"""
Reads the NSL-KDD files into a table (a pandas DataFrame).

Each row is one network connection, described by 41 measurements (how long it lasted,
how many bytes went each way, how many connections the same machine made in the last
two seconds, ...) plus a label: "normal" or the name of the attack, e.g. "neptune".
"""
from pathlib import Path
from typing import Optional

import pandas as pd

from network_sensor.paths import dataset_dir

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
