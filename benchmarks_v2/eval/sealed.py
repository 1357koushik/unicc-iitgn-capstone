"""Sealed test split protection (docs/benchmark_format.md, "Sealed test split").

Every tool in this package refuses to evaluate, run, pool or print the test split unless the environment
variable ``TRE_OPEN_SEALED`` is exactly ``E1``. Standard library only.
"""
from __future__ import annotations

import os

SEALED_ENV = "TRE_OPEN_SEALED"
SEALED_VALUE = "E1"
SEALED_SPLIT = "test"


class SealedError(RuntimeError):
    """Raised when the sealed test split is requested without TRE_OPEN_SEALED=E1."""


def sealed_open() -> bool:
    return os.environ.get(SEALED_ENV) == SEALED_VALUE


def require_open(what: str) -> None:
    if not sealed_open():
        raise SealedError(
            f"refused: {what} touches the sealed test split; only work package E1 may open it "
            f"(set {SEALED_ENV}={SEALED_VALUE})"
        )


def check_split(split: str | None, what: str) -> None:
    if split == SEALED_SPLIT:
        require_open(what)


def check_query_splits(splits, what: str) -> None:
    """Refuse if any of the given split names is the sealed split."""
    if SEALED_SPLIT in set(splits):
        require_open(what)
