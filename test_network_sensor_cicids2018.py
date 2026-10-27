"""
Automatic checks for reading CICFlowMeter 4.0 / CSE-CIC-IDS2018 files and for the
cross-dataset check (network_sensor/cicids2018.py).

They use small made-up files, so they never touch your real database, model or dataset.

Run them in the project folder, with the .venv switched on:
    python -m unittest test_network_sensor_cicids2018 -v
"""
import os

os.environ["LOAD_DOTENV"] = "0"                  # ignore your personal .env settings
os.environ["DATABASE_URL"] = "sqlite://"         # in-memory database (never the real app.db)

import io                                         # noqa: E402
import tempfile                                   # noqa: E402
import unittest                                   # noqa: E402
import warnings                                   # noqa: E402
from pathlib import Path                          # noqa: E402
from unittest import mock                         # noqa: E402

import numpy as np                                # noqa: E402
import pandas as pd                               # noqa: E402

from network_sensor import cicids2018             # noqa: E402
from network_sensor.cicids2017 import read_csv_file, to_flows   # noqa: E402
from network_sensor.cicids2018 import (COLUMNS_2018, LABELS_2018, count_labels, is_cicflowmeter4,  # noqa: E402
                                       missing_columns, rename_columns, translate_label)
from network_sensor.models import NetworkSensorModel           # noqa: E402
from network_sensor.paths import model_path                    # noqa: E402
from test_network_sensor import SMALL                          # noqa: E402
from test_network_sensor_cicids2017 import DASH, made_up_flows, official_csv   # noqa: E402

# The header row of the CSE-CIC-IDS2018 files ("Processed Traffic Data for ML Algorithms"),
# copied from Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv (all files checked had this row).
REAL_2018_HEADER = (
    "Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,"
    "Fwd Pkt Len Max,Fwd Pkt Len Min,Fwd Pkt Len Mean,Fwd Pkt Len Std,Bwd Pkt Len Max,Bwd Pkt Len Min,"
    "Bwd Pkt Len Mean,Bwd Pkt Len Std,Flow Byts/s,Flow Pkts/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,"
    "Flow IAT Min,Fwd IAT Tot,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Tot,Bwd IAT Mean,"
    "Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,"
    "Fwd Header Len,Bwd Header Len,Fwd Pkts/s,Bwd Pkts/s,Pkt Len Min,Pkt Len Max,Pkt Len Mean,Pkt Len Std,"
    "Pkt Len Var,FIN Flag Cnt,SYN Flag Cnt,RST Flag Cnt,PSH Flag Cnt,ACK Flag Cnt,URG Flag Cnt,"
    "CWE Flag Count,ECE Flag Cnt,Down/Up Ratio,Pkt Size Avg,Fwd Seg Size Avg,Bwd Seg Size Avg,"
    "Fwd Byts/b Avg,Fwd Pkts/b Avg,Fwd Blk Rate Avg,Bwd Byts/b Avg,Bwd Pkts/b Avg,Bwd Blk Rate Avg,"
    "Subflow Fwd Pkts,Subflow Fwd Byts,Subflow Bwd Pkts,Subflow Bwd Byts,Init Fwd Win Byts,"
    "Init Bwd Win Byts,Fwd Act Data Pkts,Fwd Seg Size Min,Active Mean,Active Std,Active Max,Active Min,"
    "Idle Mean,Idle Std,Idle Max,Idle Min,Label"
).split(",")
QUIET = lambda *args: None                        # noqa: E731  (no progress lines in the test output)
LABEL_2018_OF = {}
for _name_2018, _name_2017 in LABELS_2018.items():
    LABEL_2018_OF.setdefault(_name_2017, _name_2018)


def as_2018_layout(official: bytes, repeat_header: bool = True, extra_columns: dict = None) -> str:
    """A made-up CIC-IDS2017 file rewritten the way CSE-CIC-IDS2018 lays out its files:
    the 2018 column names and order, the 2018 attack names, and the header row repeated
    in the middle of the file."""
    df = read_csv_file(io.BytesIO(official))
    columns_2017 = [COLUMNS_2018.get(name, name) for name in REAL_2018_HEADER]
    out = pd.DataFrame({name_2018: (df[name_2017] if name_2017 in df.columns else 0)
                        for name_2018, name_2017 in zip(REAL_2018_HEADER, columns_2017)})
    out["Protocol"] = 6
    out["Timestamp"] = "14/02/2018 08:31:01"
    out["Label"] = df["Label"].map(lambda label: LABEL_2018_OF.get(label, label))
    for name, values in (extra_columns or {}).items():
        out.insert(0, name, values)
    lines = out.to_csv(index=False).splitlines()
    if repeat_header:
        lines.insert(len(lines) // 2, lines[0])
    return "\n".join(lines) + "\n"


class LayoutTests(unittest.TestCase):
    def test_the_real_2018_header_has_every_measurement_after_renaming(self):
        self.assertTrue(is_cicflowmeter4(REAL_2018_HEADER))
        self.assertFalse(is_cicflowmeter4(["Destination Port", "Flow Duration"]))
        renamed = rename_columns(pd.DataFrame(columns=REAL_2018_HEADER)).columns
        self.assertEqual(missing_columns(renamed), [])
        # every renaming rule matches a real 2018 column (no typos), apart from the
        # address columns that only CICFlowMeter's full output has
        unused = set(COLUMNS_2018) - set(REAL_2018_HEADER)
        self.assertEqual(unused, {"Src IP", "Dst IP", "Src Port"})

    def test_2018_attack_names_become_the_2017_names(self):
        cases = {"Benign": "BENIGN", "DoS attacks-Hulk": "DoS Hulk", "DDOS attack-HOIC": "DDoS",
                 "DDoS attacks-LOIC-HTTP": "DDoS", "Brute Force -XSS": "Web Attack - XSS",
                 "SQL Injection": "Web Attack - Sql Injection", "Infilteration": "Infiltration",
                 "ssh-bruteforce": "SSH-Patator", " FTP-BruteForce ": "FTP-Patator", "Bot": "Bot",
                 "Something new": "Something new"}
        for name_2018, name_2017 in cases.items():
            self.assertEqual(translate_label(name_2018), name_2017, name_2018)


class CrossDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": cls.tmp.name})
        cls.env.start()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cls.model = NetworkSensorModel(SMALL, dataset="cicids2017").fit(made_up_flows())
        cls.model.save(model_path("cicids2017"))
        cls.folder = Path(cls.tmp.name) / "cic2018"
        cls.folder.mkdir()
        cls.days = {
            "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv":
                [("BENIGN", 400), ("FTP-Patator", 90), ("SSH-Patator", 70)],
            "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv":
                [("BENIGN", 400), (f"Web Attack {DASH} Brute Force", 60), ("DDoS", 120)],
        }
        cls.truth = []
        for k, (name, parts) in enumerate(cls.days.items()):
            official = official_csv(parts, seed=50 + k)
            (cls.folder / name).write_text(as_2018_layout(official), encoding="utf-8")
            cls.truth.append(to_flows(read_csv_file(io.BytesIO(official))))
        cls.truth = pd.concat(cls.truth, ignore_index=True)

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.tmp.cleanup()

    def test_label_counts_skip_the_repeated_header_row(self):
        counts = count_labels(self.folder / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv")
        self.assertEqual(dict(counts), {"Benign": 400, "FTP-BruteForce": 90, "SSH-Bruteforce": 70})

    def test_checking_every_flow_gives_exactly_the_direct_result(self):
        results, markdown = cicids2018.run(self.folder, normal_share=1.0, attack_cap=10 ** 9, log=QUIET)
        y = self.truth["is_attack"].to_numpy()
        flagged = self.model.predict(self.truth)
        tp, fp = int(((y == 1) & (flagged == 1)).sum()), int(((y == 0) & (flagged == 1)).sum())
        c = results["combined"]
        self.assertEqual(results["sample"]["flows_checked"], len(self.truth))
        self.assertAlmostEqual(c["precision"], tp / (tp + fp))
        self.assertAlmostEqual(c["recall"], tp / int((y == 1).sum()))
        self.assertEqual({row["label_2017"] for row in results["by_label"]},
                         {"BENIGN", "FTP-Patator", "SSH-Patator", "Web Attack - Brute Force", "DDoS"})
        self.assertIn("CSE-CIC-IDS2018", markdown)
        self.assertIn("| Precision (target 90%) |", markdown)

    def test_a_sample_counts_each_flow_for_the_flows_it_stands_for(self):
        results, _ = cicids2018.run(self.folder, normal_share=0.5, attack_cap=40, seed=3, log=QUIET)
        checked = results["sample"]["flows_checked"]
        self.assertLess(checked, len(self.truth))
        c = results["combined"]
        # The estimated totals stay close to the real ones (1,140 flows: 800 normal, 340 attacks).
        self.assertTrue(250 < c["estimated_attacks"] < 410, c["estimated_attacks"])
        self.assertTrue(600 < c["estimated_normal"] < 1000, c["estimated_normal"])


if __name__ == "__main__":
    unittest.main()
