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

A fourth model, the attack-type classifier (another Random Forest, trained on the
labelled ATTACKS only), names the attack family each alert most resembles. It never
decides whether a connection is flagged; it only makes the alert actionable (likely
type, priority and suggested next step - see actions.py).
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

from network_sensor.actions import add_actions
from network_sensor.explain import NormalProfile, explain_rows
from network_sensor.features import InputError, build_preprocessor, prepare_features
from network_sensor.spec import DEFAULT_DATASET, DatasetSpec, get_spec

MODEL_NAMES = ("isolation_forest", "one_class_svm", "random_forest")
DECISION_RULE = "random_forest OR (isolation_forest AND one_class_svm)"
# 2 = also stores the normal-traffic profile; 3 = also the dataset name; 4 = also the
# attack-type classifier
FILE_FORMAT_VERSION = 4
# Version 2 files are NSL-KDD models. Versions 2 and 3 still work, but their alerts have
# no attack type, priority or next step until the sensor is retrained.
READABLE_FILE_VERSIONS = (2, 3, 4)


@dataclass
class SensorSettings:
    # Share of NORMAL training traffic the two normal-only models are allowed to call
    # unusual. Higher = catches more attacks but raises more false alarms.
    anomaly_share: float = 0.05
    # The One-Class SVM gets very slow on large data, so it learns from a random sample
    # of this many normal connections (all of them if there are fewer).
    svm_training_rows: int = 15_000
    n_trees: int = 200          # trees in the Isolation Forest and in the Random Forest
    type_trees: int = 100       # trees in the attack-type classifier
    random_seed: int = 0        # fixed, so training twice gives the same model


class NetworkSensorModel:
    def __init__(self, settings: SensorSettings = None, dataset: str = DEFAULT_DATASET):
        self.dataset = get_spec(dataset).name      # refuses unknown dataset names
        # Without settings, the dataset's own anomaly share is used (see spec.py).
        self.settings = settings or SensorSettings(anomaly_share=self.spec.anomaly_share)
        self.preprocessor = build_preprocessor(self.spec)
        self.isolation_forest = None
        self.one_class_svm = None
        self.random_forest = None
        self.type_classifier = None      # attack family of an alert (None: no labels to learn from)
        self.normal_profile = None
        self.training_info: dict = {}

    @property
    def spec(self) -> DatasetSpec:
        """What this model's dataset looks like (models saved before there was more
        than one dataset are NSL-KDD models)."""
        return get_spec(getattr(self, "dataset", DEFAULT_DATASET))

    # ---------------------------------------------------------------- training
    def fit(self, train_df: pd.DataFrame) -> "NetworkSensorModel":
        """Train the three models and the attack-type classifier. train_df needs the
        dataset's measurement columns and is_attack (1 = attack, 0 = normal); 'label'
        (the attack name) is optional, but without it there is no attack-type classifier."""
        if "is_attack" not in train_df.columns:
            raise InputError("Training data needs an 'is_attack' column (1 = attack, 0 = normal).")
        features = prepare_features(train_df, self.spec)
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

        # Attack-type classifier: learns, from the labelled attacks only, which family an
        # attack belongs to. Trained after (and independently of) the three models above,
        # so it cannot change which connections are flagged.
        type_info = None
        if "label" in train_df.columns:
            families = train_df["label"].astype(str).map(self.spec.family_of).to_numpy()
            known = (y == 1) & (families != "unknown")
            if known.any():
                self.type_classifier = RandomForestClassifier(
                    n_estimators=s.type_trees, class_weight="balanced", n_jobs=-1, random_state=s.random_seed
                ).fit(X[known], families[known])
                type_info = {"families": [str(f) for f in self.type_classifier.classes_],
                             "training_attacks": int(known.sum())}
        _answer_with_one_thread(self)

        self.normal_profile = NormalProfile(features[y == 0], self._importance_per_measurement(), self.spec)

        attack_labels =(sorted(train_df.loc[train_df["is_attack"] == 1, "label"].astype(str).unique())
                         if "label" in train_df.columns else [])
        self.training_info = {
            "dataset": self.dataset,
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "training_rows": int(len(y)),
            "normal_rows": int((y == 0).sum()),
            "attack_rows": int((y == 1).sum()),
            "svm_training_rows": int(n_svm),
            "attack_types_seen_in_training": attack_labels,
            "settings": asdict(s),
            "decision_rule": DECISION_RULE,
            "attack_type_classifier": type_info,
        }
        return self

    def _importance_per_measurement(self) -> dict:
        """How much the Random Forest relies on each measurement (the yes/no columns
        made from one text column are added back together)."""
        importance = {}
        names = self.preprocessor.get_feature_names_out()
        for name, value in zip(names, self.random_forest.feature_importances_):
            part, column = name.split("__", 1)
            if part == "categories":
                column = next(c for c in self.spec.categorical_columns if column.startswith(c + "_"))
            importance[column] = importance.get(column, 0.0) + float(value)
        return importance

    # ---------------------------------------------------------------- answers
    def _checked_matrix(self, df: pd.DataFrame):
        if self.random_forest is None:
            raise RuntimeError("The sensor has not been trained yet.")
        features = prepare_features(df, self.spec)
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
        Forest's score, and up to top_n measurements that are rare in normal traffic
        (see explain.py). Alerts also get their likely attack type, priority and a
        suggested next step (see actions.py)."""
        features, X = self._checked_matrix(df)
        votes = self._votes_from_matrix(X, df.index)
        rf_scores = self.random_forest.predict_proba(X)[:, 1]
        verdicts = self.combine(votes)
        explanations = explain_rows(self.normal_profile, features, votes, verdicts, rf_scores, top_n=top_n)
        types, confidences = self.attack_types_of_matrix(X[verdicts == 1])
        add_actions(explanations, types, confidences, self.spec)
        return explanations

    @property
    def has_attack_types(self) -> bool:
        """False for sensors trained before the attack-type classifier existed."""
        return getattr(self, "type_classifier", None) is not None

    def attack_types_of_matrix(self, X):
        """(likely attack family, share of the type classifier's trees that agree) for
        each row of an already-prepared matrix; (None, None) without a type classifier."""
        if not self.has_attack_types:
            return None, None
        if X.shape[0] == 0:
            return np.array([], dtype=object), np.array([])
        proba = self.type_classifier.predict_proba(X)
        best = proba.argmax(axis=1)
        return self.type_classifier.classes_[best], proba[np.arange(len(best)), best]

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
    def load(cls, path: Union[str, Path], dataset: str = None) -> "NetworkSensorModel":
        """Load a saved sensor. If `dataset` is given, the file must be a model of that
        dataset.

        SECURITY: model files are Python "pickles" - opening one can run code hidden
        inside it. Only load files you trained yourself (python -m network_sensor.train),
        never ones downloaded or received from someone else."""
        path = Path(path)
        train_command = "python -m network_sensor.train" + (
            f" --dataset {dataset}" if dataset and dataset != DEFAULT_DATASET else "")
        if not path.exists():
            raise FileNotFoundError(f"{path} was not found. Train the sensor first:\n"
                                    f"    {train_command}")
        bundle = joblib.load(path)
        if not isinstance(bundle, dict) or bundle.get("file_format_version") not in READABLE_FILE_VERSIONS \
                or not isinstance(bundle.get("model"), cls):
            raise ValueError(f"{path} is not a network sensor model file from this version. Train again.")
        model = bundle["model"]
        if dataset and model.spec.name != dataset:
            raise ValueError(f"{path} is a {model.spec.title} model, not a {get_spec(dataset).title} model. "
                             f"Train again: {train_command}")
        saved_with = bundle.get("library_versions", {}).get("scikit-learn")
        if saved_with != sklearn.__version__:
            warnings.warn(f"This model was trained with scikit-learn {saved_with}, but {sklearn.__version__} "
                          f"is installed. Retrain it to be safe: {train_command}")
        _answer_with_one_thread(model)       # also for files saved before this setting existed
        return model


def _answer_with_one_thread(model: "NetworkSensorModel") -> None:
    """Training uses every processor core, but answering uses one. Starting the extra
    worker threads costs ~40 ms each time, which dominated the small batches a live
    sensor checks (measured: 1 connection 122 ms -> 48 ms; 1,000 connections 365 ms ->
    271 ms). The answers are exactly the same either way. Trade-off: one very large file
    (22,544 connections) took 6.4 s instead of 5.4 s on a 2-core machine."""
    model.random_forest.set_params(n_jobs=1)
    if getattr(model, "type_classifier", None) is not None:
        model.type_classifier.set_params(n_jobs=1)


def _library_versions() -> dict:
    return {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
            "numpy": np.__version__, "pandas": pd.__version__, "joblib": joblib.__version__}
