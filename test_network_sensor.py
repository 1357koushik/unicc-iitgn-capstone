"""
Automatic checks for the network sensor (Task 5.0).

Run them in the project folder, with the .venv switched on:
    python -m unittest test_network_sensor -v

They use small made-up data, so they need no download and take a few seconds.
The last check also runs the real NSL-KDD evaluation if the dataset has been
downloaded (python -m network_sensor.download_data); it takes about a minute.
"""
import tempfile
import unittest
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from network_sensor import download_data
from network_sensor.explain import GROUP_OF, NormalProfile
from network_sensor.datasets import (FEATURE_COLUMNS, NUMERIC_COLUMNS, DatasetError,
                                     attack_category, load_nsl_kdd)
from network_sensor.evaluate import compute_metrics, evaluate_model, measure_speed, render_markdown, write_reports
from network_sensor.features import InputError, prepare_features
from network_sensor.models import NetworkSensorModel, SensorSettings
from network_sensor.paths import dataset_dir


def make_connections(n_normal: int, n_attack: int, seed: int) -> pd.DataFrame:
    """Made-up connections: normal web/DNS traffic, and SYN-flood style attacks
    (half-open connections, hundreds per second, nothing sent)."""
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n_normal):
        row = dict.fromkeys(NUMERIC_COLUMNS, 0.0)
        row.update(protocol_type=rng.choice(["tcp", "udp"]), service=rng.choice(["http", "domain_u"]),
                   flag="SF", duration=float(rng.integers(0, 5)), src_bytes=float(rng.integers(150, 2000)),
                   dst_bytes=float(rng.integers(500, 9000)), logged_in=1.0, count=float(rng.integers(1, 10)),
                   srv_count=float(rng.integers(1, 10)), same_srv_rate=1.0, dst_host_count=float(rng.integers(5, 60)),
                   dst_host_srv_count=float(rng.integers(5, 60)), dst_host_same_srv_rate=1.0,
                   label="normal", is_attack=0)
        rows.append(row)
    for _ in range(n_attack):
        row = dict.fromkeys(NUMERIC_COLUMNS, 0.0)
        row.update(protocol_type="tcp", service=rng.choice(["private", "http"]), flag="S0",
                   count=float(rng.integers(150, 500)), srv_count=float(rng.integers(1, 20)),
                   serror_rate=1.0, srv_serror_rate=1.0, same_srv_rate=0.05, diff_srv_rate=0.07,
                   dst_host_count=255.0, dst_host_srv_count=float(rng.integers(1, 20)),
                   dst_host_serror_rate=1.0, dst_host_srv_serror_rate=1.0, label="neptune", is_attack=1)
        rows.append(row)
    df = pd.DataFrame(rows)
    df["attack_category"] = df["label"].map(attack_category)
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


SMALL = SensorSettings(n_trees=30, svm_training_rows=300)


class DecisionRuleTests(unittest.TestCase):
    def test_rule_is_random_forest_or_both_anomaly_models(self):
        votes = pd.DataFrame({
            "isolation_forest": [0, 1, 0, 1, 0, 1],
            "one_class_svm":    [0, 0, 1, 1, 0, 1],
            "random_forest":    [0, 0, 0, 0, 1, 1],
        })
        self.assertEqual(NetworkSensorModel.combine(votes).tolist(), [0, 0, 0, 1, 1, 1])


class MetricsTests(unittest.TestCase):
    def test_counts_and_rates(self):
        m = compute_metrics([1, 1, 1, 0, 0], [1, 1, 0, 1, 0])
        self.assertEqual((m["true_positives"], m["false_positives"], m["false_negatives"], m["true_negatives"]),
                         (2, 1, 1, 1))
        self.assertAlmostEqual(m["precision"], 2 / 3)
        self.assertAlmostEqual(m["recall"], 2 / 3)
        self.assertAlmostEqual(m["false_alarm_rate"], 1 / 2)

    def test_nothing_flagged_gives_zero_not_a_crash(self):
        m = compute_metrics([1, 0], [0, 0])
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["f1"], 0.0)


class InputCheckTests(unittest.TestCase):
    def setUp(self):
        self.df = make_connections(5, 5, seed=1)

    def test_missing_column_is_refused(self):
        with self.assertRaisesRegex(InputError, "src_bytes"):
            prepare_features(self.df.drop(columns=["src_bytes"]))

    def test_text_in_a_number_column_is_refused(self):
        bad = self.df.astype({"count": object})
        bad.loc[0, "count"] = "lots"
        with self.assertRaisesRegex(InputError, "count"):
            prepare_features(bad)

    def test_negative_number_is_refused(self):
        bad = self.df.copy()
        bad.loc[0, "dst_bytes"] = -5
        with self.assertRaisesRegex(InputError, "dst_bytes"):
            prepare_features(bad)

    def test_empty_table_is_refused(self):
        with self.assertRaises(InputError):
            prepare_features(self.df.iloc[0:0])


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.train = make_connections(400, 200, seed=2)
        cls.test = make_connections(200, 100, seed=3)
        cls.model = NetworkSensorModel(SMALL).fit(cls.train)

    def test_detects_obvious_attacks(self):
        m = compute_metrics(self.test["is_attack"], self.model.predict(self.test))
        self.assertGreaterEqual(m["precision"], 0.95)
        self.assertGreaterEqual(m["recall"], 0.95)

    def test_votes_have_one_column_per_model_and_one_row_per_connection(self):
        votes = self.model.votes(self.test)
        self.assertEqual(list(votes.columns), ["isolation_forest", "one_class_svm", "random_forest"])
        self.assertEqual(len(votes), len(self.test))
        self.assertTrue(set(np.unique(votes.to_numpy())) <= {0, 1})

    def test_unknown_service_name_does_not_crash(self):
        odd = self.test.head(3).copy()
        odd["service"] = "service_never_seen_before"
        self.assertEqual(len(self.model.predict(odd)), 3)

    def test_save_and_load_give_identical_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.model.save(Path(tmp) / "m.joblib")
            with warnings.catch_warnings():
                warnings.simplefilter("error")      # same versions: there must be no warning
                loaded = NetworkSensorModel.load(path)
        np.testing.assert_array_equal(loaded.predict(self.test), self.model.predict(self.test))

    def test_loading_a_missing_file_explains_what_to_do(self):
        with self.assertRaisesRegex(FileNotFoundError, "network_sensor.train"):
            NetworkSensorModel.load(Path(tempfile.gettempdir()) / "no_such_model.joblib")

    def test_training_needs_both_normal_and_attack_examples(self):
        with self.assertRaises(InputError):
            NetworkSensorModel(SMALL).fit(self.train[self.train["is_attack"] == 0])

    def test_untrained_model_refuses_to_answer(self):
        with self.assertRaises(RuntimeError):
            NetworkSensorModel(SMALL).predict(self.test)

    def test_report_numbers_add_up(self):
        r = evaluate_model(self.model, self.test)
        combined = r["models"]["combined"]
        self.assertEqual(combined["true_positives"] + combined["false_negatives"], r["test_attacks"])
        self.assertEqual(sum(d["attacks"] for d in r["by_attack_category"].values()), r["test_attacks"])
        self.assertEqual(r["explanations"]["check"]["alerts"], combined["true_positives"] + combined["false_positives"])
        markdown = render_markdown(r)
        self.assertIn("Evaluation Report", markdown)
        self.assertIn("Are the explanations true?", markdown)
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = write_reports(r, Path(tmp))     # JSON must be writable (no odd types)
            self.assertTrue(json_path.exists() and md_path.exists())

    def test_speed_measurement_is_reported(self):
        speed = measure_speed(self.model, self.test, batch_sizes=(1, 50), repeats=2)
        self.assertEqual([m["batch_size"] for m in speed["measurements"]], [1, 50])
        self.assertTrue(all(m["batch_ms"] > 0 and m["connections_per_second"] > 0 for m in speed["measurements"]))
        report = render_markdown({**evaluate_model(self.model, self.test), "speed": speed})
        self.assertIn("Speed (real-time capacity)", report)

    def test_old_model_file_format_is_refused_with_advice(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.joblib"
            joblib.dump({"file_format_version": 1, "model": self.model}, path)
            with self.assertRaisesRegex(ValueError, "Train again"):
                NetworkSensorModel.load(path)


class ExplanationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.train = make_connections(400, 200, seed=5)
        cls.test = make_connections(60, 30, seed=6)
        cls.model = NetworkSensorModel(SMALL).fit(cls.train)
        cls.explanations = cls.model.explain(cls.test)

    def test_one_explanation_per_connection_matching_the_verdict(self):
        self.assertEqual(len(self.explanations), len(self.test))
        verdicts = self.model.predict(self.test)
        for e, v in zip(self.explanations, verdicts):
            self.assertEqual(e["verdict"], "attack" if v == 1 else "normal")
            self.assertEqual(len(e["flagged_by"]), sum(e["votes"].values()))
            self.assertTrue(0.0 <= e["random_forest_score"] <= 1.0)

    def test_syn_flood_is_explained_by_flood_measurements(self):
        flood_signs = {"flag", "count", "srv_count", "serror_rate", "srv_serror_rate", "dst_host_serror_rate",
                       "dst_host_srv_serror_rate", "same_srv_rate", "diff_srv_rate", "dst_host_same_srv_rate",
                       "dst_host_diff_srv_rate", "dst_host_count", "dst_host_srv_count", "service",
                       "src_bytes", "dst_bytes", "logged_in"}
        attacks = [e for e, a in zip(self.explanations, self.test["is_attack"]) if a == 1]
        self.assertTrue(attacks)
        for e in attacks:
            self.assertEqual(e["verdict"], "attack")
            self.assertTrue(e["reasons"], "every flood alert should name at least one reason")
            self.assertTrue({r["feature"] for r in e["reasons"]} <= flood_signs, e["reasons"])

    def test_at_most_three_reasons_by_default(self):
        self.assertTrue(all(len(e["reasons"]) <= 3 for e in self.explanations))

    def test_same_story_is_not_repeated(self):
        # Ask for up to 10 reasons: a flood makes all four 'half-open' rates rare at once,
        # so without the grouping several of them would be listed.
        explanations = self.model.explain(self.test, top_n=10)
        self.assertTrue(any(len(e["reasons"]) > 3 for e in explanations))
        for e in explanations:
            groups = [GROUP_OF.get(r["feature"], r["feature"]) for r in e["reasons"]]
            self.assertEqual(len(groups), len(set(groups)), [r["feature"] for r in e["reasons"]])

    def test_service_never_seen_in_normal_traffic_is_called_out(self):
        odd = self.test[self.test["is_attack"] == 0].head(1).copy()
        odd["service"] = "service_never_seen_before"
        reasons = self.model.explain(odd)[0]["reasons"]
        self.assertIn("Never seen in normal traffic", " ".join(r["text"] for r in reasons))

    def test_rarity_is_counted_exactly(self):
        normal = make_connections(5, 0, seed=7)
        normal["count"] = [1.0, 1.0, 2.0, 3.0, 10.0]
        profile = NormalProfile(normal, importance={})
        shares, directions = profile.rarity("count", np.array([10.0, 1.0, 11.0, 2.5]))
        np.testing.assert_allclose(shares, [0.2, 0.4, 0.0, 0.4])    # 10: 1 of 5 >= 10; 1: 2 of 5 <= 1; ...
        self.assertEqual(list(directions), ["high", "low", "high", "high"])


class DatasetFileTests(unittest.TestCase):
    def test_reads_rows_and_adds_attack_columns(self):
        rows = make_connections(1, 1, seed=4)
        rows["difficulty"] = 20
        with tempfile.TemporaryDirectory() as tmp:
            rows[FEATURE_COLUMNS + ["label", "difficulty"]].to_csv(
                Path(tmp) / "KDDTrain+.txt", header=False, index=False)
            df = load_nsl_kdd("train", folder=Path(tmp))
        self.assertEqual(sorted(df["attack_category"]), ["DoS", "normal"])
        self.assertEqual(int(df["is_attack"].sum()), 1)

    def test_wrong_number_of_columns_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "KDDTest+.txt").write_text("1,2,3\n4,5,6\n")
            with self.assertRaisesRegex(DatasetError, "columns"):
                load_nsl_kdd("test", folder=Path(tmp))

    def test_missing_file_explains_how_to_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(DatasetError, "download_data"):
                load_nsl_kdd("test", folder=Path(tmp))


class DownloadTests(unittest.TestCase):
    """Uses a local folder as a pretend download site - no internet needed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = Path(self.tmp.name) / "site"
        self.site.mkdir()
        (self.site / "data.txt").write_bytes(b"0,tcp,http,SF,normal\n")
        self.real_sha = download_data.sha256_of(self.site / "data.txt")
        self.base_url = self.site.as_uri() + "/"
        self.target_dir = Path(self.tmp.name) / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def test_correct_file_is_saved(self):
        files = {"data.txt": ("data.txt", self.real_sha, 1)}
        saved = download_data.download_file("data.txt", self.target_dir, self.base_url, files)
        self.assertEqual(saved.read_bytes(), b"0,tcp,http,SF,normal\n")

    def test_file_with_wrong_fingerprint_is_refused_and_not_kept(self):
        files = {"data.txt": ("data.txt", "0" * 64, 1)}
        with self.assertRaisesRegex(download_data.DownloadError, "fingerprint"):
            download_data.download_file("data.txt", self.target_dir, self.base_url, files)
        self.assertEqual(list(self.target_dir.iterdir()), [])     # no file, no leftover .part

    def test_unreachable_site_gives_a_clear_error(self):
        files = {"data.txt": ("missing.txt", self.real_sha, 1)}
        with self.assertRaisesRegex(download_data.DownloadError, "Could not download"):
            download_data.download_file("data.txt", self.target_dir, self.base_url, files)


@unittest.skipUnless((dataset_dir() / "KDDTrain+.txt").exists() and (dataset_dir() / "KDDTest+.txt").exists(),
                     "NSL-KDD not downloaded (python -m network_sensor.download_data)")
class RealDatasetTest(unittest.TestCase):
    def test_meets_task_5_precision_target_on_official_test_file(self):
        model = NetworkSensorModel().fit(load_nsl_kdd("train"))
        r = evaluate_model(model, load_nsl_kdd("test"))
        self.assertEqual(r["test_rows"], 22_544)
        self.assertGreaterEqual(r["models"]["combined"]["precision"], 0.90)
        # The explanations must point at what really drives the alerts: resetting the named
        # reasons has to clear far more alerts than resetting random other measurements.
        check = r["explanations"]["check"]
        self.assertGreater(check["cleared_when_reasons_reset"], 5 * check["cleared_when_random_reset"])


if __name__ == "__main__":
    unittest.main()
