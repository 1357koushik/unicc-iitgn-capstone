"""
The sensor itself: three models plus the rule that combines their answers.

  * Isolation Forest - trained on NORMAL connections only. It flags connections that
    are easy to "isolate" from the rest, i.e. unusual ones.
  * One-Class SVM    - also trained on normal connections only, but built very
    differently, so it makes different mistakes. Asking both to agree cuts false alarms.
  * Random Forest    - trained on labelled normal AND attack connections, so it is
    very good at attack types it has seen, but cannot know brand-new ones.

Decision rule:  attack  =  Random Forest says attack
                           OR (Isolation Forest AND One-Class SVM both say abnormal)
"""
import platform
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM

from network_sensor.datasets import CATEGORICAL_COLUMNS
from network_sensor.explain import NormalProfile, explain_rows
from network_sensor.features import InputError, build_preprocessor, prepare_features

MODEL_NAMES = ("isolation_forest", "one_class_svm", "random_forest")
DECISION_RULE = "random_forest OR (isolation_forest AND one_class_svm)"
FILE_FORMAT_VERSION = 2     # 2 = also stores the normal-traffic profile used for explanations


@dataclass
class SensorSettings:
    # Share of NORMAL training traffic the two normal-only models are allowed to call
    # unusual. Higher = catches more attacks but raises more false alarms.
    anomaly_share: float = 0.05
    # The One-Class SVM gets very slow on large data, so it learns from a random sample
    # of this many normal connections (all of them if there are fewer).
    svm_training_rows: int = 15_000
    n_trees: int = 200          # trees in the Isolation Forest and in the Random Forest
    random_seed: int = 0        # fixed, so training twice gives the same model


class NetworkSensorModel:
    def __init__(self, settings: SensorSettings = None):
        self.settings = settings or SensorSettings()
        self.preprocessor = build_preprocessor()
        self.isolation_forest = None
        self.one_class_svm = None
        self.random_forest = None
        self.normal_profile = None
        self.training_info: dict = {}

    # ---------------------------------------------------------------- training
    def fit(self, train_df: pd.DataFrame) -> "NetworkSensorModel":
        """Train all three models. train_df needs the 41 measurement columns and
        is_attack (1 = attack, 0 = normal); 'label' (the attack name) is optional."""
        if "is_attack" not in train_df.columns:
            raise InputError("Training data needs an 'is_attack' column (1 = attack, 0 = normal).")
        features = prepare_features(train_df)
        y = train_df["is_attack"].astype(int).to_numpy()
        if set(np.unique(y)) != {0, 1}:
            raise InputError("Training data must contain both normal (0) and attack (1) connections.")

        s = self.settings
        X = self.preprocessor.fit_transform(features)
        normal = X[y == 0]

        self.isolation_forest = IsolationForest(
            n_estimators=s.n_trees, contamination=s.anomaly_share, random_state=s.random_seed
        ).fit(normal)

        rng = np.random.default_rng(s.random_seed)
        n_svm = min(s.svm_training_rows, len(normal))
        svm_rows = rng.choice(len(normal), n_svm, replace=False)
        self.one_class_svm = OneClassSVM(nu=s.anomaly_share, gamma="scale").fit(normal[svm_rows])

        self.random_forest = RandomForestClassifier(
            n_estimators=s.n_trees, class_weight="balanced", n_jobs=-1, random_state=s.random_seed
        ).fit(X, y)

        self.normal_profile = NormalProfile(features[y == 0], self._importance_per_measurement())

        attack_labels =(sorted(train_df.loc[train_df["is_attack"] == 1, "label"].astype(str).unique())
                         if "label" in train_df.columns else [])
        self.training_info = {
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "training_rows": int(len(y)),
            "normal_rows": int((y == 0).sum()),
            "attack_rows": int((y == 1).sum()),
            "svm_training_rows": int(n_svm),
            "attack_types_seen_in_training": attack_labels,
            "settings": asdict(s),
            "decision_rule": DECISION_RULE,
        }
        return self

    def _importance_per_measurement(self) -> dict:
        """How much the Random Forest relies on each of the 41 measurements (the yes/no
        columns made from one text column are added back together)."""
        importance = {}
        names = self.preprocessor.get_feature_names_out()
        for name, value in zip(names, self.random_forest.feature_importances_):
            part, column = name.split("__", 1)
            if part == "categories":
                column = next(c for c in CATEGORICAL_COLUMNS if column.startswith(c + "_"))
            importance[column] = importance.get(column, 0.0) + float(value)
        return importance

    # ---------------------------------------------------------------- answers
    def _checked_matrix(self, df: pd.DataFrame):
        if self.random_forest is None:
            raise RuntimeError("The sensor has not been trained yet.")
        features = prepare_features(df)
        return features, self.preprocessor.transform(features)

    def _votes_from_matrix(self, X, index) -> pd.DataFrame:
        return pd.DataFrame({
            "isolation_forest": (self.isolation_forest.predict(X) == -1).astype(int),
            "one_class_svm": (self.one_class_svm.predict(X) == -1).astype(int),
            "random_forest": self.random_forest.predict(X).astype(int),
        }, index=index)

    def votes(self, df: pd.DataFrame) -> pd.DataFrame:
        """One column per model, one row per connection: 1 = 'this looks like an attack'."""
        _, X = self._checked_matrix(df)
        return self._votes_from_matrix(X, df.index)

    def explain(self, df: pd.DataFrame, top_n: int = 3) -> list:
        """For each connection: the verdict, which models raised the alarm, the Random
        Forest's score, and up to top_n measurements that are rare in normal traffic.
        See network_sensor/explain.py."""
        features, X = self._checked_matrix(df)
        votes = self._votes_from_matrix(X, df.index)
        rf_scores = self.random_forest.predict_proba(X)[:, 1]
        return explain_rows(self.normal_profile, features, votes, self.combine(votes),
                            rf_scores, top_n=top_n)

    @staticmethod
    def combine(votes: pd.DataFrame) -> np.ndarray:
        """Apply DECISION_RULE to the three votes."""
        rf = votes["random_forest"].to_numpy().astype(bool)
        both_anomaly_models = (votes["isolation_forest"].to_numpy().astype(bool)
                               & votes["one_class_svm"].to_numpy().astype(bool))
        return (rf | both_anomaly_models).astype(int)

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """1 = attack, 0 = normal, for each connection."""
        return self.combine(self.votes(df))

    # ---------------------------------------------------------------- files
    def save(self, path: Union[str, Path]) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "file_format_version": FILE_FORMAT_VERSION,
            "library_versions": _library_versions(),
            "model": self,
        }, path)
        return path

    @classmethod
    def load(cls, path: Union[str, Path]) -> "NetworkSensorModel":
        """Load a saved sensor.

        SECURITY: model files are Python "pickles" - opening one can run code hidden
        inside it. Only load files you trained yourself (python -m network_sensor.train),
        never ones downloaded or received from someone else."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"{path} was not found. Train the sensor first:\n"
                                    "    python -m network_sensor.train")
        bundle = joblib.load(path)
        if not isinstance(bundle, dict) or bundle.get("file_format_version") != FILE_FORMAT_VERSION \
                or not isinstance(bundle.get("model"), cls):
            raise ValueError(f"{path} is not a network sensor model file from this version. Train again.")
        saved_with = bundle.get("library_versions", {}).get("scikit-learn")
        if saved_with != sklearn.__version__:
            warnings.warn(f"This model was trained with scikit-learn {saved_with}, but {sklearn.__version__} "
                          "is installed. Retrain it to be safe: python -m network_sensor.train")
        return bundle["model"]


def _library_versions() -> dict:
    return {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
            "numpy": np.__version__, "pandas": pd.__version__, "joblib": joblib.__version__}
