"""
Turns connection records into the numbers the models work with, and refuses bad input.

Which columns there are, and what values are allowed, comes from the dataset's
description (network_sensor/spec.py). Without one, NSL-KDD is assumed.
"""
from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from network_sensor.spec import UNDEFINED_VALUE, DatasetSpec, get_spec


class InputError(ValueError):
    """The connection records are missing columns or contain impossible values."""


def prepare_features(df: pd.DataFrame, spec: Optional[DatasetSpec] = None) -> pd.DataFrame:
    """Check the measurement columns and return a clean copy of just those columns.

    Refuses (with a clear message) missing columns, empty cells, text where a number
    should be, infinite numbers, and - where the dataset has none - negative numbers.
    In the few columns the dataset marks as "may be undefined", empty or infinite
    values become UNDEFINED_VALUE (-1) instead (see spec.py)."""
    spec = spec or get_spec()
    missing = [c for c in spec.feature_columns if c not in df.columns]
    if missing:
        raise InputError(f"Missing columns: {', '.join(missing)}")
    if len(df) == 0:
        raise InputError("There are no connection records to check.")

    clean = df[list(spec.feature_columns)].copy()
    for column in spec.categorical_columns:
        if clean[column].isna().any():
            raise InputError(f"Column '{column}' has empty cells.")
        clean[column] = clean[column].astype(str).str.strip()

    problems: List[str] = []
    for column in spec.numeric_columns:
        values = pd.to_numeric(clean[column], errors="coerce")
        if column in spec.may_be_undefined:
            values = values.replace([np.inf, -np.inf], np.nan).fillna(UNDEFINED_VALUE)
        if values.isna().any():
            problems.append(f"'{column}' has empty or non-numeric values")
        elif np.isinf(values.to_numpy(dtype=float)).any():
            problems.append(f"'{column}' has infinite values")
        elif not spec.allow_negative and (values < 0).any():
            problems.append(f"'{column}' has negative values")
        clean[column] = values.astype(float)
    if problems:
        raise InputError("Invalid values: " + "; ".join(problems))
    return clean


def signed_log1p(x):
    """log(1 + x) that also works below zero: -log(1 + |x|) for negative x."""
    return np.sign(x) * np.log1p(np.abs(x))


def build_preprocessor(spec: Optional[DatasetSpec] = None) -> ColumnTransformer:
    """The recipe that converts a checked table into model inputs:

      * text columns (e.g. protocol, service) become one yes/no column per value
        ("one-hot"); a value never seen in training is ignored instead of crashing.
        If the dataset sets max_categories, rare values share one "other" column.
      * numbers spanning 0 to billions (durations, byte counts) are log-scaled, so a
        few giant values do not drown out everything else (1 GB and 10 GB are both "huge")
      * every number is then rescaled to a common range (average 0, spread 1)
    """
    spec = spec or get_spec()
    skewed_columns = list(spec.skewed_columns)
    other_numeric = [c for c in spec.numeric_columns if c not in skewed_columns]
    log = signed_log1p if spec.allow_negative else np.log1p
    skewed = Pipeline([
        ("log", FunctionTransformer(log, feature_names_out="one-to-one")),
        ("scale", StandardScaler()),
    ])
    if spec.max_categories:
        encoder = OneHotEncoder(handle_unknown="infrequent_if_exist", max_categories=spec.max_categories,
                                sparse_output=False)
    else:
        encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    parts = []
    if spec.categorical_columns:
        parts.append(("categories", encoder, list(spec.categorical_columns)))
    if skewed_columns:
        parts.append(("skewed", skewed, skewed_columns))
    if other_numeric:
        parts.append(("numeric", StandardScaler(), other_numeric))
    return ColumnTransformer(parts)
