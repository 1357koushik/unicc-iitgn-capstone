"""
Everything the sensor needs to know about one dataset, in one place.

The models, the explanations and the evaluation report work the same way for every
dataset. What differs is described here: which measurement columns there are, which
of them hold text, what each one means in plain English, which attack families exist
(what each can do, and what an analyst should do first), and how to show a value
("1,234 bytes", "2.5 seconds").

Two datasets are supported:
    nsl_kdd     - NSL-KDD (network_sensor/datasets.py), the first benchmark
    cicids2017  - CIC-IDS2017 (network_sensor/cicids2017.py), modern traffic from 2017
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

DATASETS = ("nsl_kdd", "cicids2017")
DEFAULT_DATASET = "nsl_kdd"


@dataclass(frozen=True)
class DatasetSpec:
    name: str                                   # "nsl_kdd" / "cicids2017"
    title: str                                  # shown in reports
    feature_columns: Tuple[str, ...]            # the measurements the models use, in order
    categorical_columns: Tuple[str, ...]        # measurements that are names, not numbers
    skewed_columns: Tuple[str, ...]             # numbers spanning 0 to billions: log-scaled
    descriptions: Dict[str, str]                # plain-English meaning of each measurement
    groups: Dict[str, List[str]]                # measurements that tell the same story
    yes_no_columns: FrozenSet[str]              # measurements that are 0/1
    families: Tuple[str, ...]                   # attack families, in report order
    family_meanings: Dict[str, str]             # what each family is
    family_of: Callable[[str], str]             # attack label -> family ("normal" for normal)
    normal_label: str                           # the label of normal traffic
    format_value: Callable[[str, object], str]  # how to show a value of a measurement
    test_description: str = "test part"         # e.g. "official test file KDDTest+.txt"
    limitations: Tuple[str, ...] = ()           # stated in the evaluation report
    # The evaluation keeps every explanation in memory; for very large test parts only
    # this many connections of each label are explained (None = all of them).
    explain_per_label: Optional[int] = None
    # Also retrain without each attack family to see how never-seen attacks are caught.
    new_attack_check: bool = False
    # Share of NORMAL training traffic the two anomaly models may call unusual (their
    # false-alarm budget). See SensorSettings.anomaly_share and calibrate.py.
    anomaly_share: float = 0.05
    allow_negative: bool = False                # may measurements be below zero?
    # Numbers that cannot be worked out for some connections (e.g. "bytes per second"
    # of a connection that lasted 0 microseconds). Empty or infinite values there are
    # replaced by UNDEFINED_VALUE instead of being refused.
    may_be_undefined: FrozenSet[str] = frozenset()
    # Text measurements with many possible values (e.g. port numbers): only the most
    # common ones get their own model input; the rest share one "other" input.
    max_categories: Optional[int] = None
    # What each attack family could do if it succeeds: "High" (control of a machine, an
    # account or data), "Medium" (a service made unavailable) or "Low" (information
    # gathering only). Used for an alert's priority (see actions.py).
    family_impact: Dict[str, str] = field(default_factory=dict)
    # One suggested first step for an analyst, per attack family (see actions.py).
    family_actions: Dict[str, str] = field(default_factory=dict)
    numeric_columns: Tuple[str, ...] = field(init=False)
    group_of: Dict[str, str] = field(init=False)

    def __post_init__(self):
        numeric = tuple(c for c in self.feature_columns if c not in self.categorical_columns)
        object.__setattr__(self, "numeric_columns", numeric)
        object.__setattr__(self, "group_of", {f: g for g, members in self.groups.items() for f in members})


UNDEFINED_VALUE = -1.0


def get_spec(name: Optional[str] = None) -> DatasetSpec:
    """The description of the named dataset (NSL-KDD if no name is given)."""
    name = name or DEFAULT_DATASET
    if name == "nsl_kdd":
        from network_sensor.datasets import NSL_KDD_SPEC
        return NSL_KDD_SPEC
    if name == "cicids2017":
        from network_sensor.cicids2017 import CICIDS2017_SPEC
        return CICIDS2017_SPEC
    raise ValueError(f"Unknown dataset {name!r}. Choose one of: {', '.join(DATASETS)}.")


def load_split(name: str, split: str):
    """The 'train' or 'test' part of the named dataset, as a table with the measurement
    columns plus label, is_attack (1 = attack, 0 = normal) and attack_category."""
    if get_spec(name).name == "nsl_kdd":
        from network_sensor.datasets import load_nsl_kdd
        return load_nsl_kdd(split)
    from network_sensor.cicids2017 import load_cicids2017
    return load_cicids2017(split)


def dataset_of_columns(columns) -> str:
    """Which dataset's format a table of connection records is in: CIC-IDS2017 if it has
    every CIC-IDS2017 measurement column, otherwise NSL-KDD."""
    present = set(columns)
    if all(c in present for c in get_spec("cicids2017").feature_columns):
        return "cicids2017"
    return DEFAULT_DATASET
