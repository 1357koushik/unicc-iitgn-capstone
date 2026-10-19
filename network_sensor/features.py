"""
Turns connection records into the numbers the models work with, and refuses bad input.
"""
from typing import List

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from network_sensor.datasets import CATEGORICAL_COLUMNS, FEATURE_COLUMNS, NUMERIC_COLUMNS

# Durations and byte counts range from 0 to billions. Taking the logarithm keeps a few
# giant values from drowning out everything else (1 GB and 10 GB are both "huge").
SKEWED_COLUMNS = ["duration", "src_bytes", "dst_bytes"]


class InputError(ValueError):
    """The connection records are missing columns or contain impossible values."""


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """Check the 41 measurement columns and return a clean copy of just those columns.

    Refuses (with a clear message) missing columns, empty cells, text where a number
    should be, and negative numbers - none of these can come from a real connection."""
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise InputError(f"Missing columns: {', '.join(missing)}")
    if len(df) == 0:
        raise InputError("There are no connection records to check.")

    clean = df[FEATURE_COLUMNS].copy()
    for column in CATEGORICAL_COLUMNS:
        if clean[column].isna().any():
            raise InputError(f"Column '{column}' has empty cells.")
        clean[column] = clean[column].astype(str).str.strip()

    problems: List[str] = []
    for column in NUMERIC_COLUMNS:
        values = pd.to_numeric(clean[column], errors="coerce")
        if values.isna().any():
            problems.append(f"'{column}' has empty or non-numeric values")
        elif (values < 0).any():
            problems.append(f"'{column}' has negative values")
        clean[column] = values.astype(float)
    if problems:
        raise InputError("Invalid values: " + "; ".join(problems))
    return clean


def build_preprocessor() -> ColumnTransformer:
    """The recipe that converts a checked table into model inputs:

      * text columns (protocol, service, flag) become one yes/no column per value
        ("one-hot"); a value never seen in training is ignored instead of crashing
      * durations and byte counts are log-scaled (see SKEWED_COLUMNS)
      * every number is then rescaled to a common range (average 0, spread 1)
    """
    other_numeric = [c for c in NUMERIC_COLUMNS if c not in SKEWED_COLUMNS]
    skewed = Pipeline([
        ("log", FunctionTransformer(np.log1p, feature_names_out="one-to-one")),
        ("scale", StandardScaler()),
    ])
    return ColumnTransformer([
        ("categories", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_COLUMNS),
        ("skewed", skewed, SKEWED_COLUMNS),
        ("numeric", StandardScaler(), other_numeric),
    ])
