"""
Automatic checks for training the CICFlowMeter-format sensor on your own labelled
traffic (python -m network_sensor.train --own-data, network_sensor/own_data.py).

They use small made-up files, so they never touch your real database, model or dataset.

Run them in the project folder, with the .venv switched on:
    python -m unittest discover -s security_platform/tests -p test_network_sensor_own_data.py -v
"""
import os

os.environ["LOAD_DOTENV"] = "0"                  # ignore your personal .env settings
os.environ["DATABASE_URL"] = "sqlite://"         # in-memory database (never the real app.db)

import contextlib                                 # noqa: E402
import hashlib                                    # noqa: E402
import io                                         # noqa: E402
import json                                       # noqa: E402
import tempfile                                   # noqa: E402
import unittest                                   # noqa: E402
import warnings                                   # noqa: E402
from pathlib import Path                          # noqa: E402
from unittest import mock                         # noqa: E402

from network_sensor import own_data, train       # noqa: E402
import pandas as pd                               # noqa: E402

from network_sensor.cicids2017 import FEATURE_COLUMNS, family_of  # noqa: E402
from network_sensor.datasets import DatasetError  # noqa: E402
from network_sensor.models import NetworkSensorModel  # noqa: E402
from network_sensor.paths import model_path, reports_dir  # noqa: E402
from network_sensor.service import SensorService, read_connections  # noqa: E402
from network_sensor.models import SensorSettings  # noqa: E402
from network_sensor.spec import get_spec          # noqa: E402
from test_network_sensor import SMALL             # noqa: E402
from test_network_sensor_cicids2017 import DASH, made_up_flows, official_csv  # noqa: E402
from test_network_sensor_cicids2018 import QUIET, as_2018_layout  # noqa: E402

# Two days of made-up labelled traffic: one written like CICFlowMeter 4.0 (2018 names),
# one like the official CIC-IDS2017 files - both layouts are accepted.
DAY_2018 = [("BENIGN", 600), ("FTP-Patator", 180), ("SSH-Patator", 140)]
DAY_2017 = [("BENIGN", 600), (f"Web Attack {DASH} Brute Force", 120), ("DDoS", 240), ("PortScan", 160)]
ALL_FLOWS = sum(n for _, n in DAY_2018 + DAY_2017)


FAST = SensorSettings(n_trees=SMALL.n_trees, svm_training_rows=SMALL.svm_training_rows,
                      anomaly_share=get_spec("cicids2017").anomaly_share)


def write_own_files(folder: Path, day_2018=DAY_2018, day_2017=DAY_2017) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "monday.csv").write_text(as_2018_layout(official_csv(day_2018, seed=1)), encoding="utf-8")
    (folder / "tuesday.csv").write_bytes(official_csv(day_2017, seed=2))
    return folder


def relabel(text: str, old: str, new: str, every: int = 1) -> str:
    """The file with every `every`-th label `old` replaced by `new`."""
    lines, seen = text.splitlines(), 0
    for i, line in enumerate(lines):
        if line.endswith("," + old):
            seen += 1
            if seen % every == 0:
                lines[i] = line[: -len(old)] + new
    return "\n".join(lines) + "\n"


_run = own_data.run                              # (the command tests replace own_data.run)


def quiet_run(*args, **kwargs):
    return _run(*args, log=QUIET, **kwargs)


class OwnDataTestCase(unittest.TestCase):
    """Each test gets its own empty sensor folder, with the public sensor already in place."""

    @classmethod
    def setUpClass(cls):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cls.public_model = NetworkSensorModel(SMALL, dataset="cicids2017").fit(made_up_flows())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": str(Path(self.tmp.name) / "data")})
        env.start()
        self.addCleanup(env.stop)
        self.public_file = self.public_model.save(model_path("cicids2017"))
        self.public_bytes = self.public_file.read_bytes()
        self.folder = write_own_files(Path(self.tmp.name) / "own")
        # Small and quick models, with the real false-alarm budget of the CIC-IDS2017 sensor.
        small = mock.patch.object(own_data, "NetworkSensorModel",
                                  lambda dataset: NetworkSensorModel(FAST, dataset=dataset))
        small.start()
        self.addCleanup(small.stop)


class LabelTests(unittest.TestCase):
    def test_labels_people_write_become_the_sensors_names(self):
        cases = {"Benign": "BENIGN", "normal": "BENIGN", " BENIGN ": "BENIGN",
                 "DoS attacks-Hulk": "DoS Hulk", "ssh-patator": "SSH-Patator", "brute force": "Brute Force",
                 f"Web Attack {DASH} XSS": "Web Attack - XSS", "portscan": "PortScan",
                 "Ransomware": "Ransomware"}
        for written, name in cases.items():
            self.assertEqual(own_data.own_label(written), name, written)

    def test_a_family_name_is_its_own_family(self):
        self.assertEqual(family_of("Brute Force"), "Brute Force")
        self.assertEqual(family_of("DoS"), "DoS")
        self.assertEqual(family_of("SSH-Patator"), "Brute Force")
        self.assertEqual(family_of("Ransomware"), "unknown")


class TrainingTests(OwnDataTestCase):
    def test_trains_tests_and_installs_keeping_the_old_sensor(self):
        r = quiet_run(self.folder)
        self.assertTrue(r["passed"])
        self.assertTrue(r["installed"])
        self.assertGreaterEqual(r["test"]["combined"]["precision"], 0.90)
        # the old sensor is kept, byte for byte, and the new one is in its place
        backup = model_path("cicids2017").with_name("sensor_model_cicids2017.previous.joblib")
        self.assertEqual(backup.read_bytes(), self.public_bytes)
        model = NetworkSensorModel.load(model_path("cicids2017"), dataset="cicids2017")
        info = model.training_info
        self.assertEqual(info["trained_on"], "own_data")
        self.assertTrue(model.has_attack_types)
        self.assertEqual(set(info["attack_types_seen_in_training"]),
                         {"FTP-Patator", "SSH-Patator", "Web Attack - Brute Force", "DDoS", "PortScan"})
        # what it learned from is recorded, with each file's fingerprint
        recorded = {f["name"]: f["sha256"] for f in info["own_data"]["files"]}
        actual = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.folder.glob("*.csv")}
        self.assertEqual(recorded, actual)
        self.assertEqual(info["own_data"]["test"]["flows_checked"], r["test"]["flows_checked"])
        self.assertLessEqual(info["training_rows"] + r["test"]["flows_checked"], ALL_FLOWS)
        report = reports_dir("cicids2017") / "own_data_training.md"
        self.assertIn("Installed", report.read_text(encoding="utf-8"))
        self.assertTrue(json.loads((reports_dir("cicids2017") / "own_data_training.json").read_text())["installed"])

    def test_the_web_app_uses_it_and_says_so(self):
        service = SensorService()
        before = service._dataset_status("cicids2017")
        self.assertFalse(before["own_data"])
        self.assertEqual(before["trained_on"], "CIC-IDS2017")
        r = quiet_run(self.folder)
        status = service._dataset_status("cicids2017")       # notices the new file by itself
        self.assertTrue(status["own_data"])
        self.assertEqual(status["trained_on"], "your own labelled files")
        self.assertEqual(status["evaluation"]["dataset"], "test part of your own files")
        self.assertAlmostEqual(status["evaluation"]["precision"], r["test"]["combined"]["precision"])
        self.assertTrue(status["evaluation"]["passed"])
        connections = read_connections((self.folder / "monday.csv").read_bytes())
        result = service.scan(connections)
        self.assertEqual(result["trained_on"], "your own labelled files")
        self.assertGreater(result["alerts_total"], 0)
        self.assertGreater(result["label_check"]["precision"], 0.9)

    def test_below_the_target_nothing_is_replaced(self):
        modified = self.public_file.stat().st_mtime_ns
        with mock.patch.object(own_data, "TARGET_PRECISION", 1.01):
            r = quiet_run(self.folder)
        self.assertFalse(r["passed"])
        self.assertFalse(r["installed"])
        self.assertEqual(model_path("cicids2017").read_bytes(), self.public_bytes)
        self.assertEqual(self.public_file.stat().st_mtime_ns, modified)
        self.assertFalse(model_path("cicids2017").with_name("sensor_model_cicids2017.previous.joblib").exists())
        self.assertIn("NOT installed", (reports_dir("cicids2017") / "own_data_training.md").read_text(encoding="utf-8"))

    def test_below_the_target_it_can_be_installed_on_purpose(self):
        with mock.patch.object(own_data, "TARGET_PRECISION", 1.01):
            r = quiet_run(self.folder, accept_below_target=True)
        self.assertTrue(r["installed"])
        info = NetworkSensorModel.load(model_path("cicids2017")).training_info["own_data"]
        self.assertFalse(info["passed"])
        self.assertTrue(info["installed_below_target"])
        status = SensorService()._dataset_status("cicids2017")
        self.assertFalse(status["evaluation"]["passed"])

    def test_training_and_test_parts_never_share_a_flow(self):
        paths = own_data.csv_files(self.folder)
        _, totals = own_data.survey(paths)
        train_part, test_part, _ = own_data.sample_flows(paths, totals)
        fingerprint = lambda part: set(pd.util.hash_pandas_object(part[FEATURE_COLUMNS], index=False))  # noqa: E731
        self.assertFalse(fingerprint(train_part) & fingerprint(test_part))
        for part in (train_part, test_part):
            self.assertEqual(set(part["is_attack"]), {0, 1})
        # every flow is used (the files are far below the sampling caps), once
        self.assertEqual(len(train_part) + len(test_part), ALL_FLOWS)
        self.assertTrue((test_part["weight"] == 1.0).all())

    def test_one_file_can_be_given_instead_of_a_folder(self):
        r = quiet_run(self.folder / "tuesday.csv")
        self.assertEqual([f["name"] for f in r["files"]], ["tuesday.csv"])
        self.assertTrue(r["installed"])

    def test_broken_rows_are_skipped_and_counted(self):
        path = self.folder / "monday.csv"
        lines = path.read_text(encoding="utf-8").splitlines()
        columns = lines[0].split(",")
        duration = columns.index("Flow Duration")
        for i in (5, 50, 500):
            values = lines[i].split(",")
            values[duration] = "abc"
            lines[i] = ",".join(values)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = quiet_run(self.folder)
        self.assertEqual(r["broken_rows"]["monday.csv"]["broken"], 3)
        self.assertTrue(r["installed"])


class RefusalTests(OwnDataTestCase):
    def assertRefused(self, pattern):
        with self.assertRaisesRegex(DatasetError, pattern):
            quiet_run(self.folder)
        # nothing was replaced or written
        self.assertEqual(model_path("cicids2017").read_bytes(), self.public_bytes)
        self.assertFalse((reports_dir("cicids2017") / "own_data_training.md").exists())

    def test_flows_without_a_label_are_refused(self):
        path = self.folder / "monday.csv"
        path.write_text(relabel(path.read_text(encoding="utf-8"), "Benign", "No Label", every=10), encoding="utf-8")
        self.assertRefused(r"no label.*monday\.csv: 60")

    def test_a_file_without_a_label_column_is_refused(self):
        path = self.folder / "monday.csv"
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(line.rsplit(",", 1)[0] for line in lines) + "\n", encoding="utf-8")
        self.assertRefused("no Label column")

    def test_a_file_that_is_not_from_cicflowmeter_is_refused(self):
        (self.folder / "notes.csv").write_text("name,value\na,1\n", encoding="utf-8")
        self.assertRefused(r"notes\.csv is not a CICFlowMeter file")

    def test_without_normal_traffic_it_is_refused(self):
        for p in self.folder.glob("*.csv"):
            p.unlink()
        write_own_files(self.folder, day_2018=[("FTP-Patator", 300)], day_2017=[("DDoS", 300)])
        self.assertRefused("No normal traffic")

    def test_normal_traffic_must_not_be_named_something_else(self):
        # "Normal" is accepted; "Regular" would silently become an attack name, so a file with
        # no Benign/Normal flows at all is refused rather than trained on.
        for p in self.folder.glob("*.csv"):
            p.write_text(relabel(relabel(p.read_text(encoding="cp1252"), "Benign", "Regular"),
                                 "BENIGN", "Regular"), encoding="cp1252")
        self.assertRefused("No normal traffic.*Regular")

    def test_without_any_known_attack_name_it_is_refused(self):
        for p in self.folder.glob("*.csv"):           # (the files are Windows-1252 text)
            text = p.read_text(encoding="cp1252")
            for old in ("FTP-BruteForce", "SSH-Bruteforce", f"Web Attack {DASH} Brute Force", "DDoS", "PortScan"):
                text = relabel(text, old, "Ransomware")
            p.write_text(text, encoding="cp1252")
        self.assertRefused("None of the attack names is one the sensor knows")

    def test_too_few_flows_are_refused(self):
        for p in self.folder.glob("*.csv"):
            p.unlink()
        write_own_files(self.folder, day_2018=[("BENIGN", 60), ("FTP-Patator", 10)], day_2017=[("BENIGN", 60)])
        self.assertRefused("Not enough labelled flows")

    def test_an_empty_folder_is_refused(self):
        for p in self.folder.glob("*.csv"):
            p.unlink()
        self.assertRefused("No .csv files")


class CommandTests(OwnDataTestCase):
    def run_command(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(own_data, "run", quiet_run):
            code = train.main(list(args))
        return code, out.getvalue()

    def test_the_command_installs_and_says_where_the_old_sensor_is(self):
        code, out = self.run_command("--own-data", str(self.folder))
        self.assertEqual(code, 0)
        self.assertIn("Installed", out)
        self.assertIn("sensor_model_cicids2017.previous.joblib", out)

    def test_the_command_fails_when_not_installed(self):
        with mock.patch.object(own_data, "TARGET_PRECISION", 1.01):
            code, out = self.run_command("--own-data", str(self.folder))
        self.assertEqual(code, 1)
        self.assertIn("NOT installed", out)

    def test_the_command_reports_bad_files_without_a_traceback(self):
        code, out = self.run_command("--own-data", str(Path(self.tmp.name) / "missing"))
        self.assertEqual(code, 1)
        self.assertIn("ERROR:", out)

    def test_options_that_do_not_go_together_are_refused(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                train.main(["--own-data", str(self.folder), "--dataset", "nsl_kdd"])
            with self.assertRaises(SystemExit):
                train.main(["--accept-below-target"])


if __name__ == "__main__":
    unittest.main()
