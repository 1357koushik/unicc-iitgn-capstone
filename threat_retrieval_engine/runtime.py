"""
threat_retrieval_engine/runtime.py
==================================
CPU thread configuration.

``TRE_NUM_THREADS`` (default 16, the value measured best for the reranker on the
IITGN server) sets the thread count of torch and of the OpenMP / MKL / OpenBLAS
runtimes. The environment variables must be in place *before* those libraries
load, so :func:`apply_thread_env` is called from ``threat_retrieval_engine/__init__``
(i.e. on first import of the package). Torch itself is configured by
:func:`apply_torch_threads`, called at service start-up and, when torch is already
imported, immediately.

When ``TRE_NUM_THREADS`` is set explicitly it wins over pre-existing
``OMP_NUM_THREADS`` etc.; when it is unset the pre-existing variables are left
untouched (the default only fills in what is missing).
"""

from __future__ import annotations

import logging
import os
import sys

DEFAULT_NUM_THREADS = 16
THREAD_ENV_VARS = (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
)

logger = logging.getLogger(__name__)


def get_num_threads() -> int:
    raw = os.environ.get("TRE_NUM_THREADS", "").strip()
    if raw:
        try:
            value = int(raw)
            if value >= 1:
                return value
        except ValueError:
            pass
        logger.warning("Invalid TRE_NUM_THREADS=%r; using default %d", raw, DEFAULT_NUM_THREADS)
    return DEFAULT_NUM_THREADS


def apply_thread_env() -> int:
    """Export the thread count to OMP/MKL/OpenBLAS env vars. Safe to call repeatedly."""
    n = get_num_threads()
    explicit = bool(os.environ.get("TRE_NUM_THREADS", "").strip())
    for var in THREAD_ENV_VARS:
        if explicit:
            os.environ[var] = str(n)
        else:
            os.environ.setdefault(var, str(n))
    torch = sys.modules.get("torch")
    if torch is not None:
        _set_torch(torch, n)
    return n


def _set_torch(torch_module, n: int) -> None:
    try:
        torch_module.set_num_threads(n)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("torch.set_num_threads(%d) failed: %s", n, exc)


def apply_torch_threads() -> int:
    """Apply the thread count to torch (imports it if available) and return it."""
    n = apply_thread_env()
    try:
        import torch  # type: ignore
    except ImportError:
        return n
    _set_torch(torch, n)
    return n


def effective_threads() -> dict[str, object]:
    """Report the values currently in effect (for logs and health output)."""
    info: dict[str, object] = {"TRE_NUM_THREADS": get_num_threads()}
    for var in THREAD_ENV_VARS:
        info[var] = os.environ.get(var)
    torch = sys.modules.get("torch")
    if torch is not None:
        try:
            info["torch_num_threads"] = torch.get_num_threads()
        except Exception:  # pragma: no cover - defensive
            info["torch_num_threads"] = None
    return info
