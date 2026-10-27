"""
Automatic checks for the actionable part of the network sensor's alerts (Task 5.0):
the likely attack type, the priority, the certainty and the suggested next step.

They use small made-up datasets, so they never touch your real database, model or dataset.

Run them in the project folder, with the .venv switched on:
    python -m unittest test_network_sensor_actions -v
"""
import os

os.environ["LOAD_DOTENV"] = "0"                  # ignore your personal .env settings
os.environ["DATABASE_URL"] = "sqlite://"         # in-memory database (never the real app.db)

import io                                         # noqa: E402
import re                                         # noqa: E402
import tempfile                                   # noqa: E402
import unittest                                   # noqa: E402
import warnings                                   # noqa: E402
from pathlib import Path                          # noqa: E402
from unittest import mock                         # noqa: E402

import joblib                                     # noqa: E402
import numpy as np                                # noqa: E402
import pandas as pd                               # noqa: E402

from network_sensor import actions                # noqa: E402
from network_sensor import service                # noqa: E402
from network_sensor.actions import (IDENTITY_COLUMNS, PRIORITIES, certainty_of, priority_of,  # noqa: E402
                                    summarise, where_of)
from network_sensor.datasets import NUMERIC_COLUMNS, attack_category   # noqa: E402
from network_sensor.evaluate import evaluate_model, render_markdown    # noqa: E402
from network_sensor.live import LiveSessions      # noqa: E402
from network_sensor.models import NetworkSensorModel                   # noqa: E402
from network_sensor.paths import model_path       # noqa: E402
from network_sensor.spec import DATASETS, get_spec                     # noqa: E402
from test_network_sensor import SMALL, make_connections                # noqa: E402
from test_network_sensor_cicids2017 import DASH, made_up_flows, official_csv   # noqa: E402

NSL = get_spec("nsl_kdd")
CIC = get_spec("cicids2017")
VOTES_ALL = {"isolation_forest": 1, "one_class_svm": 1, "random_forest": 1}
VOTES_RF = {"isolation_forest": 0, "one_class_svm": 0, "random_forest": 1}
VOTES_NEW = {"isolation_forest": 1, "one_class_svm": 1, "random_forest": 0}


def make_mixed(n_normal: int, n_each: int, seed: int) -> pd.DataFrame:
    """Made-up NSL-KDD connections with three attack families: SYN floods (DoS, from
    make_connections), port sweeps (Probe: refused connections to many services) and
    password guessing (R2L: failed logins to telnet/ftp)."""
    rng = np.random.default_rng(seed)
    base = make_connections(n_normal, n_each, seed)
    rows = []
    for _ in range(n_each):
        row = dict.fromkeys(NUMERIC_COLUMNS, 0.0)
        row.update(protocol_type="tcp", service=rng.choice(["private", "ftp_data", "smtp", "finger"]), flag="REJ",
                   count=float(rng.integers(1, 5)), srv_count=float(rng.integers(1, 5)), rerror_rate=1.0,
                   srv_rerror_rate=1.0, same_srv_rate=0.1, diff_srv_rate=0.9, dst_host_count=255.0,
                   dst_host_srv_count=float(rng.integers(1, 5)), dst_host_diff_srv_rate=0.9,
                   dst_host_rerror_rate=1.0, dst_host_srv_rerror_rate=1.0, label="portsweep", is_attack=1)
        rows.append(row)
    for _ in range(n_each):
        row = dict.fromkeys(NUMERIC_COLUMNS, 0.0)
        row.update(protocol_type="tcp", service=rng.choice(["telnet", "ftp"]), flag="RSTO",
                   duration=float(rng.integers(1, 10)), src_bytes=float(rng.integers(100, 300)),
                   dst_bytes=float(rng.integers(100, 400)), num_failed_logins=1.0, count=1.0, srv_count=1.0,
                   same_srv_rate=1.0, dst_host_count=float(rng.integers(1, 10)),
                   dst_host_srv_count=float(rng.integers(1, 10)), dst_host_same_srv_rate=1.0,
                   label="guess_passwd", is_attack=1)
        rows.append(row)
    extra = pd.DataFrame(rows)
    extra["attack_category"] = extra["label"].map(attack_category)
    return pd.concat([base, extra], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)


class RuleTests(unittest.TestCase):
    def test_every_family_has_an_impact_and_a_next_step(self):
        for name in DATASETS:
            spec = get_spec(name)
            for family in spec.families:
                self.assertIn(spec.family_impact.get(family), PRIORITIES, (name, family))
                self.assertGreater(len(spec.family_actions.get(family, "")), 40, (name, family))
            self.assertEqual(set(spec.family_impact), set(spec.families), name)
            self.assertEqual(set(spec.family_actions), set(spec.families), name)

    def test_priority_is_the_impact_of_the_likely_type(self):
        self.assertEqual(priority_of(True, "U2R", NSL)[0], "High")
        self.assertEqual(priority_of(True, "R2L", NSL)[0], "High")
        self.assertEqual(priority_of(True, "DoS", NSL)[0], "Medium")
        self.assertEqual(priority_of(True, "Probe", NSL)[0], "Low")
        self.assertEqual(priority_of(True, "Heartbleed", CIC)[0], "High")
        self.assertEqual(priority_of(True, "PortScan", CIC)[0], "Low")
        level, reason = priority_of(True, "Web Attack", CIC)
        self.assertEqual(level, "High")
        self.assertIn("likely Web Attack", reason)

    def test_a_possible_new_attack_is_medium_whatever_its_closest_type(self):
        for family in NSL.families:
            level, reason = priority_of(False, family, NSL)
            self.assertEqual(level, "Medium")
            self.assertIn("does not match a known attack pattern", reason)

    def test_certainty_says_which_models_flagged_it(self):
        self.assertTrue(certainty_of(VOTES_ALL, 1.0).startswith("High: all three models"))
        self.assertTrue(certainty_of(VOTES_RF, 0.62).startswith("Medium: the Random Forest"))
        self.assertIn("62%", certainty_of(VOTES_RF, 0.62))
        self.assertIn("one anomaly model", certainty_of({**VOTES_RF, "one_class_svm": 1}, 0.9))
        self.assertTrue(certainty_of(VOTES_NEW, 0.1).startswith("Low: only the two anomaly models"))

    def test_summary_counts_every_alert(self):
        alerts = [{"priority": "High", "attack_type": {"likely": "R2L", "matches_known_pattern": True}},
                  {"priority": "Medium", "attack_type": {"likely": "DoS", "matches_known_pattern": True}},
                  {"priority": "Medium", "attack_type": {"likely": "DoS", "matches_known_pattern": False}},
                  {"priority": "Medium", "attack_type": {"likely": "DoS", "matches_known_pattern": True}}]
        s = summarise(alerts)
        self.assertEqual(s["by_priority"], [{"name": "High", "alerts": 1}, {"name": "Medium", "alerts": 3},
                                            {"name": "Low", "alerts": 0}])
        self.assertEqual(s["by_type"], [{"name": "DoS", "alerts": 2}, {"name": "Possible new attack", "alerts": 1},
                                        {"name": "R2L", "alerts": 1}])

    def test_where_shows_only_identity_columns_the_file_has(self):
        df = pd.DataFrame({"Source IP": [" 192.168.10.5 "], "Destination Port": ["80"], "Flow Duration": ["5"]})
        self.assertEqual(where_of(df, 0), {"Source IP": "192.168.10.5", "Destination Port": "80"})
        self.assertIsNone(where_of(pd.DataFrame({"duration": [1]}), 0))
        self.assertNotIn("Flow Duration", IDENTITY_COLUMNS)


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.train = make_mixed(400, 120, seed=21)
        cls.model = NetworkSensorModel(SMALL).fit(cls.train)
        cls.test = make_mixed(200, 40, seed=22)

    def test_the_type_classifier_learns_the_attack_families(self):
        self.assertEqual(self.model.training_info["attack_type_classifier"]["families"], ["DoS", "Probe", "R2L"])
        alerts = [(e, self.test["attack_category"].iat[i]) for i, e in enumerate(self.model.explain(self.test))
                  if e["verdict"] == "attack" and self.test["is_attack"].iat[i] == 1]
        self.assertGreater(len(alerts), 100)
        right = sum(e["attack_type"]["likely"] == truth for e, truth in alerts)
        self.assertGreaterEqual(right / len(alerts), 0.95)

    def test_alerts_get_priority_certainty_and_next_step_by_type(self):
        expected = {"DoS": "Medium", "Probe": "Low", "R2L": "High"}
        for e in self.model.explain(self.test):
            if e["verdict"] != "attack":
                self.assertNotIn("priority", e)
                continue
            t = e["attack_type"]
            self.assertEqual(t["matches_known_pattern"], e["votes"]["random_forest"] == 1)
            self.assertTrue(0 < t["confidence"] <= 1)
            self.assertTrue(e["certainty"])
            if t["matches_known_pattern"]:
                self.assertEqual(e["priority"], expected[t["likely"]])
                self.assertEqual(e["next_step"], NSL.family_actions[t["likely"]])
            else:
                self.assertEqual((e["priority"], e["next_step"]), ("Medium", actions.NEW_ATTACK_STEP))

    def test_the_type_classifier_does_not_change_which_connections_are_flagged(self):
        without_labels = self.train.drop(columns=["label"])
        plain = NetworkSensorModel(SMALL).fit(without_labels)
        self.assertIsNone(plain.type_classifier)
        self.assertEqual(plain.predict(self.test).tolist(), self.model.predict(self.test).tolist())
        alert = next(e for e in plain.explain(self.test) if e["verdict"] == "attack")
        self.assertIsNone(alert["priority"])
        self.assertIn("Retrain", alert["priority_reason"])

    def test_a_sensor_saved_before_attack_types_still_works_and_says_to_retrain(self):
        old = NetworkSensorModel(SMALL).fit(self.train)
        del old.type_classifier                       # what a version 3 file holds
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.joblib"
            joblib.dump({"file_format_version": 3, "library_versions": {}, "model": old}, path)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                loaded = NetworkSensorModel.load(path, dataset="nsl_kdd")
        self.assertFalse(loaded.has_attack_types)
        self.assertEqual(loaded.predict(self.test).tolist(), self.model.predict(self.test).tolist())
        alerts = [e for e in loaded.explain(self.test) if e["verdict"] == "attack"]
        self.assertTrue(alerts)
        for e in alerts:
            self.assertIsNone(e["attack_type"])
            self.assertIsNone(e["priority"])
            self.assertIn("python -m network_sensor.train", e["priority_reason"])

    def test_the_report_measures_types_and_priorities(self):
        r = evaluate_model(self.model, self.test)
        act = r["actionable"]
        t = act["type_of_known_pattern_alerts"]
        self.assertGreaterEqual(t["rate"], 0.95)
        self.assertEqual(sum(p["alerts"] for p in act["by_priority"]),
                         r["models"]["combined"]["true_positives"] + r["models"]["combined"]["false_positives"])
        self.assertEqual([p["priority"] for p in act["by_priority"]], list(PRIORITIES))
        text = render_markdown(r)
        self.assertIn("## Actionable alerts", text)
        self.assertIn("| Priority | Alerts | Real attacks | False alarms | Precision |", text)


class LiveTests(unittest.TestCase):
    def test_live_totals_count_alerts_by_priority(self):
        model = NetworkSensorModel(SMALL).fit(make_mixed(300, 80, seed=31))
        test = make_mixed(60, 15, seed=32).drop(columns=["is_attack", "attack_category"])
        clock = [0.0]
        live = LiveSessions(clock=lambda: clock[0])
        session, _ = live.start("u1", test, 100, {})
        clock[0] = 10.0
        step = live.step(session.id, "u1", model)
        self.assertTrue(step["done"])
        by_priority = {p["name"]: p["alerts"] for p in step["totals"]["by_priority"]}
        self.assertEqual(sum(by_priority.values()), step["totals"]["alerts"])
        self.assertEqual(step["summary"]["alerts_by_priority"], by_priority)
        self.assertTrue(all("next_step" in a for a in step["alerts"]))


class CicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = NetworkSensorModel(SMALL, dataset="cicids2017").fit(made_up_flows())

    def test_cic_families_are_learned(self):
        families = set(self.model.training_info["attack_type_classifier"]["families"])
        self.assertEqual(families, {"Brute Force", "DoS", "Heartbleed", "Web Attack", "DDoS", "PortScan"})


class AppTests(unittest.TestCase):
    """The scan endpoint returns the actionable fields, ranks by priority, and shows
    where a connection came from when the file has those columns."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from backend.api.main import app, get_db
        from backend.auth.passwords import get_password_hash
        from backend.database import Base
        from backend.models import User

        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"NETWORK_SENSOR_DATA_DIR": cls.tmp.name})
        cls.env.start()
        NetworkSensorModel(SMALL).fit(make_mixed(400, 120, seed=41)).save(model_path())
        NetworkSensorModel(SMALL, dataset="cicids2017").fit(made_up_flows()).save(model_path("cicids2017"))

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        def override_get_db():
            db = session()
            try:
                yield db
            finally:
                db.close()

        cls.app, cls.get_db, cls.base, cls.engine = app, get_db, Base, engine
        app.dependency_overrides[get_db] = override_get_db
        Base.metadata.create_all(bind=engine)
        db = session()
        db.add(User(id="a_investigator", username="a_investigator", hashed_password=get_password_hash("pw-actions"),
                    role="investigator", allowed_datasets="ALL"))
        db.commit()
        db.close()
        cls.client = TestClient(app)
        res = cls.client.post("/api/v1/auth/login", json={"username": "a_investigator", "password": "pw-actions"})
        assert res.status_code == 200, res.text

    @classmethod
    def tearDownClass(cls):
        cls.app.dependency_overrides.pop(cls.get_db, None)
        cls.base.metadata.drop_all(bind=cls.engine)
        cls.env.stop()
        cls.tmp.cleanup()

    def scan(self, content: bytes):
        return self.client.post("/api/v1/network/scan", files={"file": ("c.csv", io.BytesIO(content), "text/csv")})

    def test_scan_returns_actionable_alerts_ranked_by_priority(self):
        content = make_mixed(40, 15, seed=42).drop(columns=["is_attack", "attack_category"]).to_csv(index=False)
        res = self.scan(content.encode())
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertTrue(data["attack_types"])
        self.assertEqual(sum(p["alerts"] for p in data["by_priority"]), data["alerts_total"])
        self.assertEqual(sum(t["alerts"] for t in data["by_type"]), data["alerts_total"])
        ranks = [PRIORITIES.index(a["priority"]) for a in data["alerts"]]
        self.assertEqual(ranks, sorted(ranks))
        self.assertIn("High", {a["priority"] for a in data["alerts"]})
        for a in data["alerts"]:
            self.assertTrue(a["next_step"] and a["certainty"] and a["attack_type"]["likely"])
            self.assertNotIn("where", a)                    # NSL-KDD files have no addresses

    def test_every_filter_shows_its_most_serious_alerts(self):
        # The dashboard can show all alerts, known patterns, possible new attacks or one
        # priority, each limited to its most serious alerts. With one cap per kind, a file
        # with many High alerts sent back only High ones, so the Medium and Low filters
        # found nothing. Now every filter's most serious alerts are sent back.
        connections = make_mixed(40, 15, seed=42).drop(columns=["is_attack", "attack_category"])
        # A few normal connections made very unusual, so that some alerts are possible new
        # attacks (only the two anomaly models flag them).
        unusual = connections[connections["label"] == "normal"].head(3).copy()
        unusual[["count", "srv_count", "dst_host_count", "dst_host_srv_count"]] = [300.0, 300.0, 255.0, 255.0]
        unusual[["src_bytes", "num_compromised", "root_shell"]] = [1e6, 5.0, 1.0]
        content = pd.concat([connections, unusual], ignore_index=True).to_csv(index=False)
        everything = self.scan(content.encode()).json()
        self.assertEqual(everything["alerts_shown"], everything["alerts_total"])   # small file: all sent
        with mock.patch.object(service, "MAX_ALERTS_PER_FILTER", 2):
            capped = self.scan(content.encode()).json()

        def matches(a, view):
            if view == "all":
                return True
            if view in ("known", "new"):
                return a["votes"]["random_forest"] == (1 if view == "known" else 0)
            return a["priority"] == view

        views = ("all", "known", "new", "High", "Medium", "Low")
        for view in views:
            full = [a["row"] for a in everything["alerts"] if matches(a, view)]
            cut = [a["row"] for a in capped["alerts"] if matches(a, view)]
            self.assertTrue(full, f"the test data should have alerts for '{view}'")
            self.assertEqual(cut[:2], full[:2], f"the 2 most serious alerts for '{view}'")
        self.assertEqual(capped["max_alerts_per_filter"], 2)
        self.assertEqual(capped["alerts_shown"], len(capped["alerts"]))
        self.assertLess(capped["alerts_shown"], capped["alerts_total"])
        self.assertEqual(capped["by_priority"], everything["by_priority"])     # totals are of ALL alerts
        ranks = [PRIORITIES.index(a["priority"]) for a in capped["alerts"]]
        self.assertEqual(ranks, sorted(ranks))                                # still High first

    def test_cic_alerts_show_where_the_connection_came_from(self):
        text = official_csv([("BENIGN", 30), ("DoS Hulk", 10), (f"Web Attack {DASH} XSS", 5)], seed=43).decode("cp1252")
        lines = text.splitlines()
        lines[0] = "Source IP, Destination IP," + lines[0]
        lines[1:] = [f"192.168.10.{k % 250 + 1},205.174.165.73," + line for k, line in enumerate(lines[1:])]
        res = self.scan(("\n".join(lines) + "\n").encode("cp1252"))
        self.assertEqual(res.status_code, 200, res.text)
        alerts = res.json()["alerts"]
        self.assertTrue(alerts)
        for a in alerts:
            self.assertEqual(set(a["where"]), {"Source IP", "Destination IP", "Destination Port"})
            self.assertEqual(a["where"]["Destination IP"], "205.174.165.73")
            self.assertEqual(a["where"]["Source IP"], f"192.168.10.{(a['row'] - 1) % 250 + 1}")

    def test_an_overlong_address_is_refused(self):
        text = official_csv([("BENIGN", 5)], seed=44).decode("cp1252").splitlines()
        text[0] = "Source IP," + text[0]
        text[1:] = ["x" * 41 + "," + line for line in text[1:]]
        res = self.scan(("\n".join(text) + "\n").encode("cp1252"))
        self.assertEqual(res.status_code, 400)
        self.assertIn("Source IP", res.json()["detail"])

    def test_status_says_whether_attack_types_are_available(self):
        status = self.client.get("/api/v1/network/status").json()
        self.assertEqual([d["attack_types"] for d in status["datasets"]], [True, True])


class DashboardTests(unittest.TestCase):
    def test_network_tab_markup_follows_the_security_policy(self):
        """The app's Content-Security-Policy blocks styles and scripts written into the
        page, so the Network Sensor tab must not use style="..." or onclick="..."."""
        html = Path("frontend/index.html").read_text(encoding="utf-8")
        start = html.index('<div id="network-tab"')
        end = html.index("<!-- Audit Logs Tab -->")
        tab = html[start:end]
        self.assertNotRegex(tab, r"\sstyle\s*=")
        self.assertNotRegex(tab, r"\son[a-z]+\s*=")
        for element_id in ("live-chart", "live-chart-box", "alert-filter", "alert-filter-note"):
            self.assertIn(f'id="{element_id}"', tab)

    def test_page_asks_for_the_new_script_and_style_versions(self):
        html = Path("frontend/index.html").read_text(encoding="utf-8")
        self.assertRegex(html, r'src="app\.js\?v=9"')
        self.assertRegex(html, r'href="style\.css\?v=9"')
        script = Path("frontend/app.js").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"setAttribute\(\s*['\"]style['\"]", script))

    def test_user_table_is_built_as_plain_text(self):
        """System Config's user table must not put stored text (usernames, roles, dataset
        names) into the page as HTML, so a crafted username can never run as code."""
        script = Path("frontend/app.js").read_text(encoding="utf-8")
        start = script.index("const DATASET_CHOICES")
        end = script.index('getElementById("refresh-users-btn")')
        user_table = script[start:end]
        self.assertIsNone(re.search(r"\.(innerHTML|outerHTML)\s*\+?=|insertAdjacentHTML", user_table))
        self.assertIn('textElement("td", u.username)', user_table)
        self.assertIn("encodeURIComponent(userId)", user_table)


if __name__ == "__main__":
    unittest.main()
