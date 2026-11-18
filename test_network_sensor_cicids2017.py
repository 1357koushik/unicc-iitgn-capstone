"""
Automatic checks for the CIC-IDS2017 part of the network sensor (Task 5.0).

They use small made-up files in the official CIC-IDS2017 layout (leading spaces in the
column names, the repeated column, "Infinity" values, the odd dash in the web attack
labels), so they need no download and take under a minute.

Run them in the project folder, with the .venv switched on:
    python -m unittest test_network_sensor_cicids2017 -v
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
import zipfile                                    # noqa: E402
from pathlib import Path                          # noqa: E402
from unittest import mock                         # noqa: E402

import joblib                                     # noqa: E402
import numpy as np                                # noqa: E402
import pandas as pd                               # noqa: E402
from fastapi.testclient import TestClient         # noqa: E402
from sqlalchemy import create_engine              # noqa: E402
from sqlalchemy.orm import sessionmaker           # noqa: E402
from sqlalchemy.pool import StaticPool            # noqa: E402

from backend.api.main import app, get_db          # noqa: E402
from backend.auth.passwords import get_password_hash   # noqa: E402
from backend.database import Base                 # noqa: E402
from backend.models import User                   # noqa: E402
from network_sensor import cicids2017, service    # noqa: E402
from network_sensor.cicids2017 import (ALL_COLUMNS, FEATURE_COLUMNS, check_zip, format_value,  # noqa: E402
                                       load_cicids2017, read_all, read_csv_file, split_of, to_flows)
from network_sensor.calibrate import VALIDATION_TARGET, validation_mask   # noqa: E402
from network_sensor.calibrate import calibrate as run_calibration         # noqa: E402
from network_sensor.datasets import DatasetError  # noqa: E402
from network_sensor.evaluate import evaluate_model, new_attack_check, render_markdown, write_reports  # noqa: E402
from network_sensor.features import InputError, prepare_features   # noqa: E402
from network_sensor.live import LiveSessions      # noqa: E402
from network_sensor.models import NetworkSensorModel   # noqa: E402
from network_sensor.paths import model_path       # noqa: E402
from network_sensor.spec import dataset_of_columns, get_spec   # noqa: E402
from test_network_sensor import SMALL, make_connections         # noqa: E402

CIC = get_spec("cicids2017")
DASH = "–"          # the dash in the official web attack labels (byte 0x96 in the files)
DAYS = {
    "Monday-WorkingHours.pcap_ISCX.csv": [("BENIGN", 700)],
    "Tuesday-WorkingHours.pcap_ISCX.csv": [("BENIGN", 300), ("FTP-Patator", 80), ("SSH-Patator", 60)],
    "Wednesday-workingHours.pcap_ISCX.csv": [("BENIGN", 300), ("DoS Hulk", 120), ("Heartbleed", 8)],
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": [
        ("BENIGN", 300), (f"Web Attack {DASH} Brute Force", 60), (f"Web Attack {DASH} XSS", 30)],
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": [("BENIGN", 300), ("DDoS", 120), ("PortScan", 100)],
}


def official_rows(label: str, n: int, rng) -> pd.DataFrame:
    """Made-up flows in the official layout. Normal flows: DNS/web requests that take a
    while and exchange data. Attacks: very short flows that send almost nothing."""
    df = pd.DataFrame(0.0, index=range(n), columns=ALL_COLUMNS[:-1])
    if label == "BENIGN":
        df["Destination Port"] = rng.choice([53, 443, 80, 123], n)
        df["Flow Duration"] = rng.integers(1_000, 2_000_000, n)
        df["Total Fwd Packets"] = rng.integers(1, 20, n)
        df["Total Backward Packets"] = rng.integers(1, 20, n)
        df["Total Length of Fwd Packets"] = rng.integers(40, 4_000, n)
        df["Fwd Packet Length Max"] = rng.integers(40, 1_500, n)
        df["Flow IAT Mean"] = rng.integers(500, 100_000, n)
        df["Init_Win_bytes_forward"] = rng.choice([-1, 8192, 29200], n)
        df["Init_Win_bytes_backward"] = rng.choice([-1, 235, 65535], n)
        df["ACK Flag Count"] = rng.integers(0, 2, n)
    else:
        port = {"FTP-Patator": 21, "SSH-Patator": 22, "PortScan": None}.get(label, 80)
        df["Destination Port"] = rng.integers(1, 65_535, n) if port is None else port
        df["Flow Duration"] = rng.integers(0, 100, n)
        df["Total Fwd Packets"] = rng.integers(1, 3, n)
        df["Total Backward Packets"] = rng.integers(0, 2, n)
        df["Total Length of Fwd Packets"] = rng.integers(0, 10, n)
        df["Fwd Packet Length Max"] = rng.integers(0, 10, n)
        df["SYN Flag Count"] = 1
        df["Init_Win_bytes_forward"] = 1024
    duration = df["Flow Duration"].to_numpy(dtype=float)
    with np.errstate(divide="ignore", invalid="ignore"):
        df["Flow Bytes/s"] = df["Total Length of Fwd Packets"] / duration * 1e6
        df["Flow Packets/s"] = (df["Total Fwd Packets"] + df["Total Backward Packets"]) / duration * 1e6
    df["Fwd Header Length"] = df["Fwd Header Length.1"] = df["Total Fwd Packets"] * 20
    df["Label"] = label
    return df


def official_csv(parts, seed: int = 0) -> bytes:
    """One file laid out like the official ones: leading spaces in most column names,
    'Fwd Header Length' twice, 'Infinity' for undefined rates. Written as Windows-1252
    text, like a copy re-saved on Windows (see the label test for the official form)."""
    rng = np.random.default_rng(seed)
    df = pd.concat([official_rows(label, n, rng) for label, n in parts], ignore_index=True)
    header = [" " + ("Fwd Header Length" if c == "Fwd Header Length.1" else c) for c in ALL_COLUMNS]
    header[0] = "Destination Port"                     # the first name has no leading space
    lines = [",".join(header)]
    for row in df.itertuples(index=False):
        values = []
        for column, value in zip(ALL_COLUMNS, row):
            if column == "Label":
                values.append(value)
            elif column in ("Flow Bytes/s", "Flow Packets/s") and not np.isfinite(value):
                values.append("Infinity")
            else:
                values.append(f"{value:g}")
        lines.append(",".join(values))
    return ("\n".join(lines) + "\n").encode("cp1252")


def write_zip(path: Path, days=DAYS, seed: int = 0) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for k, (name, parts) in enumerate(days.items()):
            z.writestr("MachineLearningCVE/" + name, official_csv(parts, seed + k))
    return path


def fingerprints(path: Path) -> dict:
    with zipfile.ZipFile(path) as z:
        return {Path(n).name: (hashlib.sha256(z.read(n)).hexdigest(), 0) for n in z.namelist()}


def made_up_flows(seed: int = 0) -> pd.DataFrame:
    parts = []
    for k, (_, day) in enumerate(DAYS.items()):
        parts.append(to_flows(read_csv_file(io.BytesIO(official_csv(day, seed + k)))))
    return pd.concat(parts, ignore_index=True)


class ReadingTests(unittest.TestCase):
    def test_official_layout_is_read_with_clean_names_and_labels(self):
        df = read_csv_file(io.BytesIO(official_csv(DAYS["Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"])))
        self.assertEqual(list(df.columns), ALL_COLUMNS)
        self.assertEqual(set(df["Label"]), {"BENIGN", "Web Attack - Brute Force", "Web Attack - XSS"})

    def test_undefined_rates_become_minus_one_and_ports_are_names(self):
        flows = to_flows(read_csv_file(io.BytesIO(official_csv([("DoS Hulk", 200)]))))
        zero_length = flows["Flow Duration"] == 0
        self.assertTrue(zero_length.any())
        self.assertTrue((flows.loc[zero_length, "Flow Bytes/s"] == -1).all())
        self.assertTrue(np.isfinite(flows[FEATURE_COLUMNS[1:]].to_numpy(dtype=float)).all())
        self.assertEqual(set(flows["Destination Port"]), {"80"})
        self.assertEqual(set(flows["attack_category"]), {"DoS"})
        self.assertTrue((flows["is_attack"] == 1).all())

    def test_a_file_with_other_columns_is_refused(self):
        with self.assertRaisesRegex(DatasetError, "CIC-IDS2017 columns"):
            read_csv_file(io.BytesIO(b"a,b,c\n1,2,3\n"))

    def test_split_puts_identical_flows_on_the_same_side(self):
        flows = made_up_flows()
        doubled = pd.concat([flows, flows], ignore_index=True)
        sides = split_of(doubled)
        n = len(flows)
        self.assertTrue((sides[:n] == sides[n:]).all())
        self.assertTrue((split_of(flows) == sides[:n]).all())              # same answer every time
        self.assertAlmostEqual((sides[:n] == "test").mean(), 0.30, delta=0.05)


class FileTests(unittest.TestCase):
    official_files = dict(cicids2017.FILES)        # before setUp replaces them

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": str(Path(self.tmp.name) / "data")})
        env.start()
        self.addCleanup(env.stop)
        self.zip = write_zip(Path(self.tmp.name) / "MachineLearningCSV.zip")
        # The made-up files stand in for the official ones in these checks.
        files = mock.patch.object(cicids2017, "FILES", fingerprints(self.zip))
        files.start()
        self.addCleanup(files.stop)

    def test_the_official_fingerprints_are_pinned(self):
        with mock.patch.object(cicids2017, "FILES", self.official_files):
            with self.assertRaisesRegex(DatasetError, "not the official CIC-IDS2017"):
                check_zip(self.zip)
        self.assertEqual(sum(rows for _, rows in self.official_files.values()), 2_830_743)
        self.assertEqual(len(self.official_files), 8)

    def test_only_the_official_files_are_accepted(self):
        self.assertEqual(len(check_zip(self.zip)), len(DAYS))
        changed = write_zip(Path(self.tmp.name) / "changed.zip", seed=99)
        with self.assertRaisesRegex(DatasetError, "different contents: Friday"):
            check_zip(changed)
        fewer = write_zip(Path(self.tmp.name) / "fewer.zip", days=dict(list(DAYS.items())[1:]))
        with self.assertRaisesRegex(DatasetError, "missing files: Monday"):
            check_zip(fewer)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cicids2017.main([str(changed)]), 1)
            self.assertFalse(cicids2017.zip_path().exists())         # a wrong file is never copied
            self.assertEqual(cicids2017.main([str(self.zip)]), 0)
        self.assertTrue(cicids2017.zip_path().exists())

    def test_training_sample_and_test_part(self):
        with contextlib.redirect_stdout(io.StringIO()):
            cicids2017.main([str(self.zip)])
        with mock.patch.object(cicids2017, "TRAINING_NORMAL_FLOWS", 300), \
                mock.patch.object(cicids2017, "TRAINING_FLOWS_PER_ATTACK_TYPE", 40):
            train = load_cicids2017("train")
        test = load_cicids2017("test")
        counts = train["label"].value_counts()
        self.assertEqual(counts["BENIGN"], 300)
        self.assertTrue((counts.drop("BENIGN") <= 40).all())
        self.assertEqual(counts["Heartbleed"], (read_all().query("label == 'Heartbleed' and split == 'train'")).shape[0])
        self.assertIn("up to 300 normal flows", train.attrs["sample"]["note"])
        overlap = set(pd.util.hash_pandas_object(train[FEATURE_COLUMNS], index=False)) & \
            set(pd.util.hash_pandas_object(test[FEATURE_COLUMNS], index=False))
        self.assertEqual(overlap, set())

    def test_missing_file_explains_where_to_get_it(self):
        with self.assertRaisesRegex(DatasetError, "unb.ca"):
            load_cicids2017("test")


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flows = made_up_flows()
        sides = split_of(flows)
        cls.train = flows[sides == "train"].reset_index(drop=True)
        cls.test = flows[sides == "test"].reset_index(drop=True)
        cls.model = NetworkSensorModel(SMALL, dataset="cicids2017").fit(cls.train)

    def test_catches_the_made_up_attacks(self):
        flagged = self.model.predict(self.test)
        attacks = self.test["is_attack"].to_numpy() == 1
        self.assertGreater(flagged[attacks].mean(), 0.9)

    def test_explanations_use_flow_wording(self):
        attack = self.test[self.test["label"] == "DoS Hulk"].head(1)
        e = self.model.explain(attack)[0]
        self.assertEqual(e["verdict"], "attack")
        self.assertTrue(e["reasons"])
        for reason in e["reasons"]:
            self.assertIn(reason["feature"], CIC.feature_columns)
            self.assertEqual(reason["description"], CIC.descriptions[reason["feature"]])
        groups = [CIC.group_of.get(r["feature"], r["feature"]) for r in e["reasons"]]
        self.assertEqual(len(groups), len(set(groups)))

    def test_values_are_shown_in_plain_units(self):
        self.assertEqual(format_value("Destination Port", "22"), "22 = SSH")
        self.assertEqual(format_value("Destination Port", "50123"), "50123")
        self.assertEqual(format_value("Flow Duration", 250), "250 microseconds")
        self.assertEqual(format_value("Flow IAT Max", 2_500_000), "2.5 seconds")
        self.assertEqual(format_value("Flow Bytes/s", -1), "undefined (the flow lasted 0 microseconds)")
        self.assertEqual(format_value("Init_Win_bytes_backward", -1), "not seen")
        self.assertEqual(format_value("Total Length of Fwd Packets", 1), "1 byte")
        self.assertEqual(format_value("Total Fwd Packets", 3), "3 packets")
        self.assertEqual(format_value("Flow Packets/s", 1), "1 packet per second")

    def test_input_rules(self):
        row = self.test.head(3).copy()
        row.loc[0, "Init_Win_bytes_forward"] = -1                 # "not seen" is a real value
        row.loc[1, "Flow Bytes/s"] = np.inf                       # undefined rate -> -1
        clean = prepare_features(row, CIC)
        self.assertEqual(clean.loc[1, "Flow Bytes/s"], -1)
        bad = row.copy()
        bad.loc[2, "Flow Duration"] = np.inf
        with self.assertRaisesRegex(InputError, "'Flow Duration' has infinite values"):
            prepare_features(bad, CIC)
        with self.assertRaisesRegex(InputError, "Missing columns: Flow Duration"):
            prepare_features(row.drop(columns=["Flow Duration"]), CIC)

    def test_model_file_remembers_its_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.model.save(Path(tmp) / "cic.joblib")
            self.assertEqual(NetworkSensorModel.load(path, dataset="cicids2017").spec.name, "cicids2017")
            with self.assertRaisesRegex(ValueError, "is a CIC-IDS2017 model, not a NSL-KDD model"):
                NetworkSensorModel.load(path, dataset="nsl_kdd")

    def test_model_files_from_before_this_change_still_load_as_nsl_kdd(self):
        old = NetworkSensorModel(SMALL).fit(make_connections(200, 100, seed=5))
        del old.dataset, old.normal_profile.dataset              # what version 2 files contain
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.joblib"
            joblib.dump({"file_format_version": 2, "library_versions": {}, "model": old}, path)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                loaded = NetworkSensorModel.load(path, dataset="nsl_kdd")
        self.assertEqual(loaded.spec.name, "nsl_kdd")
        self.assertIn(loaded.explain(make_connections(5, 5, seed=6))[0]["verdict"], ("attack", "normal"))

    def test_report_and_new_attack_check(self):
        r = evaluate_model(self.model, self.test, explain_per_label=20)
        self.assertEqual(r["dataset_name"], "cicids2017")
        self.assertEqual(r["test_rows"], len(self.test))
        self.assertIn("up to 20 connections of each label", r["explanations"]["check"]["sample"])
        self.assertEqual(list(r["by_attack_category"]), list(CIC.families))
        check = new_attack_check("cicids2017", self.train, self.test, normal_sample=200, settings=SMALL)
        families = [f["family"] for f in check["families"]]
        self.assertIn("DoS", families)
        self.assertNotIn("Botnet", families)                       # not in the made-up data
        for f in check["families"]:
            self.assertEqual(f["caught"], f["caught_by_random_forest"] + f["caught_only_by_anomaly_models"])
        r["new_attack_check"] = check
        markdown = render_markdown(r)
        self.assertIn("New attack types (trained without them)", markdown)
        self.assertIn("CIC-IDS2017 was recorded", markdown)
        self.assertNotIn("Never seen during training |", markdown)   # all test types are in training
        with tempfile.TemporaryDirectory() as tmp:
            json_path, _ = write_reports(r, Path(tmp))
            self.assertEqual(json.loads(json_path.read_text())["dataset_name"], "cicids2017")

    def test_calibration_uses_only_training_data_and_follows_its_rule(self):
        result = run_calibration("cicids2017", self.train, candidates=(0.05, 0.01), settings=SMALL)
        self.assertEqual([r["anomaly_share"] for r in result["candidates"]], [0.05, 0.01])
        self.assertAlmostEqual(result["validation_rows"] / len(self.train), 0.2, delta=0.06)
        passing = [r["anomaly_share"] for r in result["candidates"] if r["precision"] >= VALIDATION_TARGET]
        self.assertEqual(result["chosen_anomaly_share"], max(passing) if passing else 0.01)
        # the validation slice never overlaps what the candidates were trained on
        mask = validation_mask(self.train, CIC.feature_columns)
        self.assertTrue(0 < mask.sum() < len(self.train))

    def test_each_dataset_has_its_own_anomaly_share(self):
        self.assertEqual(NetworkSensorModel(dataset="cicids2017").settings.anomaly_share, CIC.anomaly_share)
        self.assertEqual(NetworkSensorModel().settings.anomaly_share, 0.05)       # NSL-KDD: unchanged

    def test_format_of_a_table_is_recognised(self):
        self.assertEqual(dataset_of_columns(self.test.columns), "cicids2017")
        self.assertEqual(dataset_of_columns(make_connections(2, 2, seed=1).columns), "nsl_kdd")
        with self.assertRaisesRegex(ValueError, "Unknown dataset"):
            get_spec("kdd99")


# ------------------------------------------------------------------ the web app
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
PASSWORD = "network-sensor-test-password"


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": cls.tmp.name})
        cls.env.start()
        NetworkSensorModel(SMALL).fit(make_connections(400, 200, seed=11)).save(model_path())
        flows = made_up_flows()
        cls.cic_model = NetworkSensorModel(SMALL, dataset="cicids2017").fit(flows)
        cls.cic_model.save(model_path("cicids2017"))
        cls.cic_file = official_csv([("BENIGN", 40), ("DoS Hulk", 10), (f"Web Attack {DASH} XSS", 5)], seed=7)

        app.dependency_overrides[get_db] = override_get_db
        Base.metadata.create_all(bind=engine)
        db = TestingSession()
        db.add(User(id="c_investigator", username="c_investigator", hashed_password=get_password_hash(PASSWORD),
                    role="investigator", allowed_datasets="ALL"))
        db.commit()
        db.close()
        cls.client = TestClient(app)
        res = cls.client.post("/api/v1/auth/login", json={"username": "c_investigator", "password": PASSWORD})
        assert res.status_code == 200, res.text

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        cls.env.stop()
        cls.tmp.cleanup()

    def scan(self, content: bytes, filename="flows.csv"):
        return self.client.post("/api/v1/network/scan", files={"file": (filename, io.BytesIO(content), "text/csv")})

    def test_a_cic_file_is_checked_by_the_cic_sensor(self):
        res = self.scan(self.cic_file)
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual((data["dataset"], data["dataset_title"], data["connections"]), ("cicids2017", "CIC-IDS2017", 55))
        self.assertEqual(data["label_check"]["unknown_labels"], [])          # "Web Attack - XSS" was cleaned
        self.assertEqual(data["label_check"]["true_positives"] + data["label_check"]["false_negatives"], 15)
        reason_features = {r["feature"] for a in data["alerts"] for r in a["reasons"]}
        self.assertTrue(reason_features and reason_features <= set(CIC.feature_columns))

    def test_nsl_kdd_files_still_use_the_nsl_kdd_sensor(self):
        content = make_connections(10, 5, seed=3).drop(columns=["is_attack", "attack_category"]).to_csv(index=False)
        data = self.scan(content.encode()).json()
        self.assertEqual(data["dataset"], "nsl_kdd")

    def test_status_lists_both_sensors(self):
        status = self.client.get("/api/v1/network/status").json()
        self.assertTrue(status["ready"])
        self.assertEqual([(d["dataset"], d["ready"]) for d in status["datasets"]],
                         [("nsl_kdd", True), ("cicids2017", True)])

    def test_without_a_cic_sensor_the_answer_says_how_to_train_it(self):
        path = model_path("cicids2017")
        hidden = path.with_name("hidden.joblib")
        path.rename(hidden)
        try:
            res = self.scan(self.cic_file)
            self.assertEqual(res.status_code, 503)
            self.assertIn("python -m network_sensor.train --dataset cicids2017", res.json()["detail"])
            status = self.client.get("/api/v1/network/status").json()
            self.assertEqual([d["ready"] for d in status["datasets"]], [True, False])
        finally:
            hidden.rename(path)

    def test_cic_header_with_missing_columns_is_refused(self):
        text = self.cic_file.decode("cp1252").splitlines()
        header = text[0].split(",")
        keep = [i for i, name in enumerate(header) if name.strip() != "Flow IAT Max"]
        cut = "\n".join(",".join(line.split(",")[i] for i in keep) for line in text)
        res = self.scan(cut.encode("cp1252"))
        self.assertEqual(res.status_code, 400)
        self.assertIn("looks like CIC-IDS2017 but is missing these columns: Flow IAT Max", res.json()["detail"])

    def test_labels_as_written_in_the_official_files_are_cleaned(self):
        # The official files hold a broken character (UTF-8 "replacement character") where
        # the dash should be; copies re-saved on Windows hold a Windows dash instead.
        official = self.cic_file.decode("cp1252").replace(DASH, "\ufffd").encode("utf-8")
        labels = set(service.read_connections(official)["label"])
        self.assertIn("Web Attack - XSS", labels)
        self.assertEqual(labels, set(service.read_connections(self.cic_file)["label"]))

    def test_binary_files_are_still_refused(self):
        res = self.scan(bytes(range(256)) * 10)
        self.assertEqual(res.status_code, 400)
        self.assertIn("UTF-8", res.json()["detail"])

    def test_live_replay_of_a_cic_file(self):
        connections = service.read_connections(self.cic_file)
        clock = [1000.0]
        live = LiveSessions(clock=lambda: clock[0])
        session, _ = live.start("u1", connections, 100, {"filename": "f.csv"})
        self.assertEqual((session.dataset, session.dataset_title), ("cicids2017", "CIC-IDS2017"))
        clock[0] += 5
        result = live.step(session.id, "u1", service.sensor.model)     # picks the CIC-IDS2017 sensor
        self.assertTrue(result["done"])
        self.assertEqual(result["summary"]["dataset"], "cicids2017")
        self.assertGreaterEqual(result["totals"]["label_check"]["true_positives"], 1)



@unittest.skipUnless(cicids2017.zip_path().exists(),
                     "CIC-IDS2017 not prepared (python -m network_sensor.cicids2017 <zip>)")
class RealDatasetTest(unittest.TestCase):
    def test_official_file_and_split(self):
        self.assertEqual(sorted(check_zip(cicids2017.zip_path())), sorted(cicids2017.FILES))
        test = load_cicids2017("test")
        self.assertEqual(len(test), REAL_TEST_FLOWS)
        self.assertEqual(test["label"].value_counts().to_dict(), REAL_TEST_LABELS)


# The test part of the official files (the split is the same on every computer).
REAL_TEST_FLOWS = 836_398
REAL_TEST_LABELS = {
    "BENIGN": 679_316, "DoS Hulk": 58_855, "PortScan": 47_221, "DDoS": 38_636, "DoS GoldenEye": 3_015,
    "FTP-Patator": 2_881, "SSH-Patator": 1_789, "DoS slowloris": 1_751, "DoS Slowhttptest": 1_718,
    "Bot": 588, "Web Attack - Brute Force": 439, "Web Attack - XSS": 174, "Infiltration": 7,
    "Web Attack - Sql Injection": 4, "Heartbleed": 4,
}


if __name__ == "__main__":
    unittest.main()
