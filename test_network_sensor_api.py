"""
Automatic checks for the network sensor's web endpoints (Task 5.0):
    POST /api/v1/network/scan     GET /api/v1/network/status

They run the real app with a throwaway in-memory database and a small sensor trained
on made-up data, so they never touch your real database, model or dataset.

Run them in the project folder, with the .venv switched on:
    python -m unittest test_network_sensor_api -v
"""
import os

os.environ["LOAD_DOTENV"] = "0"                  # ignore your personal .env settings
os.environ["DATABASE_URL"] = "sqlite://"         # in-memory database (never the real app.db)

import io                                         # noqa: E402
import json                                       # noqa: E402
import sys                                        # noqa: E402
import tempfile                                   # noqa: E402
import unittest                                   # noqa: E402
from unittest import mock                         # noqa: E402

from fastapi.testclient import TestClient         # noqa: E402
from sqlalchemy import create_engine              # noqa: E402
from sqlalchemy.orm import sessionmaker           # noqa: E402
from sqlalchemy.pool import StaticPool            # noqa: E402

from backend.api import main                      # noqa: E402
from backend.api.main import app, get_db          # noqa: E402
from backend.auth.passwords import get_password_hash   # noqa: E402
from backend.database import Base                 # noqa: E402
from backend.models import AuditLog, User         # noqa: E402
from network_sensor import service                # noqa: E402
from network_sensor.datasets import FEATURE_COLUMNS, FILE_COLUMNS   # noqa: E402
from network_sensor.models import NetworkSensorModel                # noqa: E402
from network_sensor.paths import model_path       # noqa: E402
from test_network_sensor import SMALL, make_connections             # noqa: E402

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
PASSWORD = "network-sensor-test-password"
SCAN = "/api/v1/network/scan"
STATUS = "/api/v1/network/status"


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


def csv_with_header(df, columns=None) -> bytes:
    return df[columns or FEATURE_COLUMNS + ["label"]].to_csv(index=False).encode("utf-8")


def raw_nsl_kdd(df, n_columns=43) -> bytes:
    rows = df.assign(difficulty=20)[FILE_COLUMNS[:n_columns]]
    return rows.to_csv(header=False, index=False).encode("utf-8")


class NetworkSensorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": cls.tmp.name})
        cls.env.start()
        cls.model = NetworkSensorModel(SMALL).fit(make_connections(400, 200, seed=11))
        cls.model.save(model_path())
        cls.connections = make_connections(40, 20, seed=12)
        # Rows (1-based) the sensor flags. Includes all 20 made-up attacks, and can include a
        # normal row both anomaly models find unusual (a false alarm, as in real life).
        cls.flagged_rows = {i + 1 for i, v in enumerate(cls.model.predict(cls.connections)) if v == 1}
        cls.attack_rows = {i + 1 for i, a in enumerate(cls.connections["is_attack"]) if a == 1}
        assert cls.attack_rows <= cls.flagged_rows

        app.dependency_overrides[get_db] = override_get_db
        Base.metadata.create_all(bind=engine)
        db = TestingSession()
        for username, role in [("t_investigator", "investigator"), ("t_auditor", "auditor"), ("t_admin", "admin")]:
            db.add(User(id=username, username=username, hashed_password=get_password_hash(PASSWORD),
                        role=role, allowed_datasets="ALL"))
        db.commit()
        db.close()
        cls.clients = {}
        for role in ("investigator", "auditor", "admin"):
            client = TestClient(app)
            res = client.post("/api/v1/auth/login", json={"username": f"t_{role}", "password": PASSWORD})
            assert res.status_code == 200, res.text
            cls.clients[role] = client

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        cls.env.stop()
        cls.tmp.cleanup()

    def scan(self, content: bytes, filename="connections.csv", role="investigator"):
        files = {"file": (filename, io.BytesIO(content), "text/csv")}
        return self.clients[role].post(SCAN, files=files)

    def last_audit(self) -> dict:
        db = TestingSession()
        try:
            entry = db.query(AuditLog).filter(AuditLog.action == "network_scan").order_by(AuditLog.id.desc()).first()
            return {"user": entry.user, "correlation_id": entry.correlation_id, **json.loads(entry.details)}
        finally:
            db.close()

    # ------------------------------------------------------------ who may use it
    def test_not_logged_in_is_refused(self):
        anonymous = TestClient(app)
        self.assertEqual(anonymous.get(STATUS).status_code, 401)
        files = {"file": ("c.csv", io.BytesIO(csv_with_header(self.connections)), "text/csv")}
        self.assertEqual(anonymous.post(SCAN, files=files).status_code, 401)

    def test_auditor_is_refused(self):
        self.assertEqual(self.clients["auditor"].get(STATUS).status_code, 403)
        self.assertEqual(self.scan(csv_with_header(self.connections), role="auditor").status_code, 403)

    # ------------------------------------------------------------ normal use
    def test_investigator_scan_returns_ranked_explained_alerts_and_is_audited(self):
        content = csv_with_header(self.connections)
        res = self.scan(content)
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertEqual(body["connections"], 60)
        self.assertEqual(body["alerts_total"], len(self.flagged_rows))
        self.assertEqual({a["row"] for a in body["alerts"]}, self.flagged_rows)   # right row numbers
        check = body["label_check"]
        self.assertEqual(check["true_positives"], 20)
        self.assertEqual(check["false_positives"], len(self.flagged_rows) - 20)
        for alert in body["alerts"]:
            self.assertEqual(alert["verdict"], "attack")
            self.assertTrue(alert["summary"])
            expected_label = "neptune" if alert["row"] in self.attack_rows else "normal"
            self.assertEqual(alert["label_in_file"], expected_label)
        strength = [(sum(a["votes"].values()), a["random_forest_score"]) for a in body["alerts"]]
        self.assertEqual(strength, sorted(strength, reverse=True))      # most serious first
        self.assertEqual(res.headers.get("cache-control"), "no-store")  # never kept by the browser

        audit = self.last_audit()
        self.assertEqual((audit["outcome"], audit["user"]), ("success", "t_investigator"))
        self.assertEqual(audit["correlation_id"], body["correlation_id"])
        self.assertEqual(audit["alerts"], len(self.flagged_rows))
        self.assertEqual(audit["file_sha256"], main._sha256(content))

    def test_a_big_scan_still_shows_possible_new_attacks(self):
        # Known patterns usually outnumber and outrank possible new attacks, so a single
        # shared cap would hide the new ones. Each kind (at each priority) gets its own cap.
        new_rows = {a["row"] for a in self.scan(csv_with_header(self.connections)).json()["alerts"]
                    if a["votes"]["random_forest"] == 0}
        self.assertTrue(new_rows, "the test data should contain at least one possible new attack")
        with mock.patch.object(service, "MAX_ALERTS_PER_FILTER", 2):
            body = self.scan(csv_with_header(self.connections)).json()
        kinds = [a["votes"]["random_forest"] for a in body["alerts"]]
        self.assertEqual(kinds.count(1), 2)                          # 2 of the known patterns
        self.assertEqual(kinds.count(0), min(2, len(new_rows)))      # and the possible new attacks
        self.assertEqual(body["alerts_shown"], len(body["alerts"]))
        self.assertEqual(body["known_pattern_alerts"] + body["possible_new_attacks"], body["alerts_total"])

    def test_admin_can_scan_a_raw_nsl_kdd_file(self):
        res = self.scan(raw_nsl_kdd(self.connections), filename="KDDTest+.txt", role="admin")
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["connections"], 60)
        self.assertIn("label_check", res.json())

    def test_file_without_labels_gives_no_label_check(self):
        res = self.scan(raw_nsl_kdd(self.connections, n_columns=41))
        self.assertEqual(res.status_code, 200, res.text)
        self.assertNotIn("label_check", res.json())
        self.assertEqual({a["row"] for a in res.json()["alerts"]}, self.flagged_rows)

    def test_status_reports_a_ready_sensor(self):
        res = self.clients["investigator"].get(STATUS)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["ready"])
        self.assertEqual(res.json()["max_file_mb"], 5)

    def test_retrained_sensor_is_picked_up_without_restarting(self):
        before = self.clients["admin"].get(STATUS).json()["trained_at"]
        newer = NetworkSensorModel(SMALL).fit(make_connections(400, 200, seed=13))
        newer.training_info["trained_at"] = "2099-01-01T00:00:00+00:00"
        newer.save(model_path())
        os.utime(model_path(), ns=(1, 4_102_444_800_000_000_000))     # make sure the file time changes
        self.assertNotEqual(before, "2099-01-01T00:00:00+00:00")
        self.assertEqual(self.clients["admin"].get(STATUS).json()["trained_at"], "2099-01-01T00:00:00+00:00")

    # ------------------------------------------------------------ refused files
    def assert_refused(self, res, status, words):
        self.assertEqual(res.status_code, status, res.text)
        self.assertIn(words, res.json()["detail"])
        audit = self.last_audit()
        self.assertEqual(audit["outcome"], "failure")
        self.assertIn(words, audit["reason"])

    def test_wrong_file_type_is_refused_and_audited(self):
        self.assert_refused(self.scan(b"MZ...", filename="tool.exe"), 415, "can't be scanned")

    def test_file_over_5_mb_is_refused(self):
        res = self.scan(b"0" * (5 * 1024 * 1024 + 10))
        self.assertEqual(res.status_code, 413)

    def test_too_many_connections_is_refused(self):
        many = make_connections(25_001, 0, seed=14)
        self.assert_refused(self.scan(raw_nsl_kdd(many, n_columns=41)), 413, "Too many connections")

    def test_missing_column_is_refused(self):
        columns = [c for c in FEATURE_COLUMNS if c != "src_bytes"]
        self.assert_refused(self.scan(csv_with_header(self.connections, columns)), 400, "src_bytes")

    def test_impossible_values_are_refused(self):
        bad = self.connections.copy()
        bad.loc[3, "dst_bytes"] = -5
        self.assert_refused(self.scan(csv_with_header(bad)), 400, "negative")

    def test_binary_file_is_refused(self):
        self.assert_refused(self.scan(bytes(range(256)) * 10), 400, "UTF-8")

    def test_wrong_number_of_values_is_refused(self):
        self.assert_refused(self.scan(b"1,2,3\n4,5,6\n"), 400, "Expected a header row")

    def test_empty_file_is_refused(self):
        self.assert_refused(self.scan(b"\n\n"), 400, "empty")

    def test_overlong_text_value_is_refused(self):
        bad = self.connections.copy()
        bad.loc[0, "service"] = "x" * 500
        self.assert_refused(self.scan(csv_with_header(bad)), 400, "longer than")

    # ------------------------------------------------------------ server-side problems
    def test_untrained_sensor_says_how_to_train(self):
        with tempfile.TemporaryDirectory() as empty, mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": empty}):
            status = self.clients["investigator"].get(STATUS).json()
            self.assertFalse(status["ready"])
            self.assertIn("network_sensor.train", status["message"])
            self.assert_refused(self.scan(csv_with_header(self.connections)), 503, "network_sensor.train")

    def test_only_one_scan_at_a_time(self):
        with service.sensor._scan_lock:
            self.assert_refused(self.scan(csv_with_header(self.connections)), 429, "Another network scan")

    def test_unexpected_error_hides_internal_details(self):
        with mock.patch.object(service.sensor, "scan", side_effect=RuntimeError("C:\\secret\\path leaked")), \
                self.assertLogs("uvicorn.error", level="ERROR") as server_log:
            res = self.scan(csv_with_header(self.connections))
        self.assertEqual(res.status_code, 500)
        self.assertIn("Reference", res.json()["detail"])
        self.assertNotIn("secret", res.json()["detail"])                 # the user sees only a reference...
        self.assertIn("secret", "\n".join(server_log.output))            # ...the details go to the server log
        self.assertEqual(self.last_audit()["outcome"], "failure")

    def test_rest_of_app_works_when_sensor_is_not_installed(self):
        with mock.patch.dict(sys.modules, {"network_sensor": None}), \
                self.assertLogs("uvicorn.error", level="ERROR") as server_log:    # pretend it cannot be imported
            self.assertIsNone(main._network_sensor())
            self.assertIn("could not be loaded", "\n".join(server_log.output))
            status = self.clients["investigator"].get(STATUS)
            self.assertEqual(status.status_code, 200)
            self.assertFalse(status.json()["ready"])
            self.assert_refused(self.scan(csv_with_header(self.connections)), 503, "not installed")
            self.assertEqual(self.clients["investigator"].get("/api/v1/auth/me").status_code, 200)


if __name__ == "__main__":
    unittest.main()
