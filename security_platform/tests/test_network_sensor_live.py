"""
Automatic checks for the network sensor's live mode (Task 5.0, "real-time").

A fake clock makes time pass instantly, so the checks are exact and quick. The second
group runs the real app (in-memory database, small sensor trained on made-up data).

Run them in the project folder, with the .venv switched on:
    python -m unittest discover -s security_platform/tests -p test_network_sensor_live.py -v
"""
import os

os.environ["LOAD_DOTENV"] = "0"                  # ignore your personal .env settings
os.environ["DATABASE_URL"] = "sqlite://"         # in-memory database (never the real app.db)

import io                                         # noqa: E402
import json                                       # noqa: E402
import tempfile                                   # noqa: E402
import unittest                                   # noqa: E402
from unittest import mock                         # noqa: E402

from fastapi.testclient import TestClient         # noqa: E402
from sqlalchemy import create_engine              # noqa: E402
from sqlalchemy.orm import sessionmaker           # noqa: E402
from sqlalchemy.pool import StaticPool            # noqa: E402

from backend.api.main import app, get_db          # noqa: E402
from backend.auth.passwords import get_password_hash   # noqa: E402
from backend.database import Base                 # noqa: E402
from backend.models import AuditLog, User         # noqa: E402
from network_sensor import live, service          # noqa: E402
from network_sensor.datasets import FEATURE_COLUMNS   # noqa: E402
from network_sensor.errors import ScanError       # noqa: E402
from network_sensor.live import LiveSessions      # noqa: E402
from network_sensor.models import NetworkSensorModel  # noqa: E402
from network_sensor.paths import model_path       # noqa: E402
from test_network_sensor import SMALL, make_connections   # noqa: E402

MODEL = NetworkSensorModel(SMALL).fit(make_connections(400, 200, seed=31))
CONNECTIONS = make_connections(40, 20, seed=32)          # 60 connections, 20 attacks
FLAGGED_ROWS = [i + 1 for i, v in enumerate(MODEL.predict(CONNECTIONS)) if v == 1]


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def details():
    return {"filename": "c.csv", "file_bytes": 1, "file_sha256": "0" * 64}


class LiveSessionTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.live = LiveSessions(clock=self.clock)

    def start(self, user="u1", speed=10, connections=CONNECTIONS):
        session, replaced = self.live.start(user, connections, speed, details())
        return session

    def test_nothing_is_checked_before_time_passes(self):
        s = self.start()
        result = self.live.step(s.id, "u1", MODEL)
        self.assertEqual((result["checked"], result["batch_size"], result["done"]), (0, 0, False))

    def test_connections_arrive_at_the_chosen_speed(self):
        s = self.start(speed=10)
        self.clock.advance(1.5)
        self.assertEqual(self.live.step(s.id, "u1", MODEL)["checked"], 15)
        self.clock.advance(1.0)
        result = self.live.step(s.id, "u1", MODEL)
        self.assertEqual((result["checked"], result["batch_size"]), (25, 10))

    def test_alerts_point_at_the_right_rows_and_match_a_full_scan(self):
        s = self.start(speed=10)
        rows, steps, done = [], 0, False
        while not done:
            self.clock.advance(1.0)
            result = self.live.step(s.id, "u1", MODEL)
            rows += [a["row"] for a in result["alerts"]]
            done, steps = result["done"], steps + 1
        self.assertEqual(steps, 6)                                 # 60 connections at 10 per second
        self.assertEqual(sorted(rows), FLAGGED_ROWS)

    def test_finished_replay_reports_a_summary_and_disappears(self):
        s = self.start(speed=100)
        self.clock.advance(5)
        result = self.live.step(s.id, "u1", MODEL)
        self.assertTrue(result["done"])
        summary = result["summary"]
        self.assertEqual(summary["outcome"], "completed")
        self.assertEqual((summary["connections_checked"], summary["alerts"]), (60, len(FLAGGED_ROWS)))
        self.assertIn("precision_against_labels", summary)
        with self.assertRaises(ScanError) as e:
            self.live.step(s.id, "u1", MODEL)
        self.assertEqual(e.exception.status_code, 404)

    def test_a_big_backlog_is_checked_in_capped_batches(self):
        s = self.start(speed=1000)
        self.clock.advance(10)                       # 60 connections have arrived
        with mock.patch.object(live, "MAX_BATCH", 25):
            first = self.live.step(s.id, "u1", MODEL)
            self.assertEqual((first["checked"], first["behind_by"]), (25, 35))
            self.live.step(s.id, "u1", MODEL)
            last = self.live.step(s.id, "u1", MODEL)
        self.assertEqual((last["checked"], last["behind_by"], last["done"]), (60, 0, True))

    def test_only_the_owner_can_use_or_stop_a_replay(self):
        s = self.start(user="u1")
        for action in (lambda: self.live.step(s.id, "u2", MODEL), lambda: self.live.stop(s.id, "u2")):
            with self.assertRaises(ScanError) as e:
                action()
            self.assertEqual(e.exception.status_code, 404)

    def test_a_new_replay_replaces_the_users_old_one(self):
        old = self.start(user="u1")
        new, replaced = self.live.start("u1", CONNECTIONS, 10, details())
        self.assertEqual(replaced["session_id"], old.id)
        self.assertIn("replaced", replaced["outcome"])
        with self.assertRaises(ScanError):
            self.live.step(old.id, "u1", MODEL)
        self.live.step(new.id, "u1", MODEL)

    def test_server_wide_limit_on_running_replays(self):
        with mock.patch.object(live, "MAX_SESSIONS", 2):
            self.start(user="a")
            self.start(user="b")
            with self.assertRaises(ScanError) as e:
                self.start(user="c")
            self.assertEqual(e.exception.status_code, 429)
            self.start(user="a")                     # replacing your own replay is always allowed

    def test_idle_replays_are_dropped(self):
        s = self.start()
        self.clock.advance(live.IDLE_SECONDS + 1)
        with self.assertRaises(ScanError) as e:
            self.live.step(s.id, "u1", MODEL)
        self.assertEqual(e.exception.status_code, 404)

    def test_only_the_offered_speeds_are_allowed(self):
        with self.assertRaises(ScanError) as e:
            self.start(speed=50)
        self.assertEqual(e.exception.status_code, 400)

    def test_bad_values_are_refused_at_the_start_not_halfway(self):
        bad = CONNECTIONS.copy()
        bad.loc[55, "src_bytes"] = -1
        with self.assertRaises(ScanError) as e:
            self.start(connections=bad)
        self.assertIn("negative", e.exception.message)

    def test_stopping_early_reports_how_far_it_got(self):
        s = self.start(speed=10)
        self.clock.advance(2)
        self.live.step(s.id, "u1", MODEL)
        summary = self.live.stop(s.id, "u1")
        self.assertEqual((summary["outcome"], summary["connections_checked"]), ("stopped by the user", 20))


# ---------------------------------------------------------------- through the app
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
PASSWORD = "network-sensor-live-test-password"


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


class LiveApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": cls.tmp.name})
        cls.env.start()
        MODEL.save(model_path())
        cls.file = CONNECTIONS[FEATURE_COLUMNS + ["label"]].to_csv(index=False).encode("utf-8")
        app.dependency_overrides[get_db] = override_get_db
        Base.metadata.create_all(bind=engine)
        db = TestingSession()
        for role in ("investigator", "auditor", "admin"):
            db.add(User(id=f"l_{role}", username=f"l_{role}", hashed_password=get_password_hash(PASSWORD),
                        role=role, allowed_datasets="ALL"))
        db.commit()
        db.close()
        cls.clients = {}
        for role in ("investigator", "auditor", "admin"):
            client = TestClient(app)
            assert client.post("/api/v1/auth/login", json={"username": f"l_{role}", "password": PASSWORD}).status_code == 200
            cls.clients[role] = client

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        cls.env.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.clock = FakeClock()
        self.patch = mock.patch.object(service, "live", LiveSessions(clock=self.clock))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def start(self, role="investigator", speed=100, content=None, filename="c.csv"):
        files = {"file": (filename, io.BytesIO(content or self.file), "text/csv")}
        return self.clients[role].post(f"/api/v1/network/live/start?speed={speed}", files=files)

    def audit(self, action):
        db = TestingSession()
        try:
            rows = db.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.id).all()
            return [{"correlation_id": r.correlation_id, **json.loads(r.details)} for r in rows]
        finally:
            db.close()

    def test_auditor_cannot_start_a_replay(self):
        self.assertEqual(self.start(role="auditor").status_code, 403)

    def test_a_whole_replay_through_the_app_is_audited_at_start_and_end(self):
        res = self.start(speed=100)
        self.assertEqual(res.status_code, 200, res.text)
        session_id = res.json()["session_id"]
        self.assertEqual(self.audit("network_live_start")[-1]["correlation_id"], session_id)

        self.clock.advance(1.0)                                   # all 60 have arrived
        step = self.clients["investigator"].post(f"/api/v1/network/live/{session_id}/next").json()
        self.assertTrue(step["done"])
        self.assertEqual(sorted(a["row"] for a in step["alerts"]), FLAGGED_ROWS)

        end = self.audit("network_live_end")[-1]
        self.assertEqual((end["correlation_id"], end["outcome"]), (session_id, "completed"))
        self.assertEqual(end["alerts"], len(FLAGGED_ROWS))
        again = self.clients["investigator"].post(f"/api/v1/network/live/{session_id}/next")
        self.assertEqual(again.status_code, 404)

    def test_stopping_early_is_audited(self):
        session_id = self.start(speed=10).json()["session_id"]
        self.clock.advance(2)
        self.clients["investigator"].post(f"/api/v1/network/live/{session_id}/next")
        res = self.clients["investigator"].post(f"/api/v1/network/live/{session_id}/stop")
        self.assertEqual(res.json()["connections_checked"], 20)
        self.assertEqual(self.audit("network_live_end")[-1]["outcome"], "stopped by the user")

    def test_someone_elses_replay_does_not_exist_for_you(self):
        session_id = self.start(role="investigator").json()["session_id"]
        for path in ("next", "stop"):
            res = self.clients["admin"].post(f"/api/v1/network/live/{session_id}/{path}")
            self.assertEqual(res.status_code, 404)

    def test_bad_requests_are_refused_and_audited(self):
        for kwargs, status in [({"filename": "tool.exe"}, 415), ({"speed": 50}, 400),
                               ({"content": b"1,2,3\n"}, 400)]:
            res = self.start(**kwargs)
            self.assertEqual(res.status_code, status, res.text)
            self.assertEqual(self.audit("network_live_start")[-1]["outcome"], "failure")

    def test_untrained_sensor_is_refused_at_the_start(self):
        with tempfile.TemporaryDirectory() as empty, mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": empty}):
            res = self.start()
        self.assertEqual(res.status_code, 503)
        self.assertIn("network_sensor.train", res.json()["detail"])


if __name__ == "__main__":
    unittest.main()
