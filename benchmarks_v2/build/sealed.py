"""Sealed test split protection (docs/benchmark_format.md, "Sealed test split").

* The test split is written only under ``<version>/sealed/``; the non-sealed files never hold a test qid.
* Sealed files are marked read-only after the build.
* ``open_sealed`` refuses unless ``TRE_OPEN_SEALED=E1`` (only work package E1 sets it).
* ``audit_sealed`` gives automated checks (leakage tests, format validation, the B2 acceptance script)
  the records they must verify; callers must never print query text or per-query results from it.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

SEALED_DIR = "sealed"
ENV = "TRE_OPEN_SEALED"
VALUE = "E1"
AUDIT_PURPOSES = ("leakage_test", "format_validation", "b2_acceptance")
README = (
    "SEALED TEST SPLIT - do not open, print, evaluate or tune on these files.\n"
    "Plan rule 1: no tuning on the sealed test and no reading its per-query results before work package E1.\n"
    "Evaluation tools refuse this directory unless TRE_OPEN_SEALED=E1 is set, which only E1 does.\n"
    "Automated audits (leakage tests, format checks) read it without printing its contents.\n"
)


class SealedAccessError(PermissionError):
    pass


def _read(bench_dir: Path) -> tuple[list[dict], list[dict]]:
    d = Path(bench_dir) / SEALED_DIR
    qs = [json.loads(x) for x in (d / "queries.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    qr = [json.loads(x) for x in (d / "qrels.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    return qs, qr


def open_sealed(bench_dir: Path) -> tuple[list[dict], list[dict]]:
    if os.environ.get(ENV) != VALUE:
        raise SealedAccessError(f"sealed test split is closed; only work package E1 sets {ENV}={VALUE}")
    return _read(bench_dir)


def audit_sealed(bench_dir: Path, purpose: str) -> tuple[list[dict], list[dict]]:
    if purpose not in AUDIT_PURPOSES:
        raise SealedAccessError(f"audit purpose {purpose!r} not allowed; use open_sealed for evaluation")
    return _read(bench_dir)


def protect(bench_dir: Path) -> None:
    d = Path(bench_dir) / SEALED_DIR
    for p in sorted(d.iterdir()):
        os.chmod(p, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def unprotect_tree(root: Path) -> None:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            try:
                os.chmod(p, stat.S_IREAD | stat.S_IWRITE)
            except OSError:
                pass


def is_read_only(p: Path) -> bool:
    return not os.access(p, os.W_OK)
