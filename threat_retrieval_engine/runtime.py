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


# ---------------------------------------------------------------------------------------------- PoC credentials
POC_CREDENTIAL_KEYS = ("BLUESKY_HANDLE", "BLUESKY_APP_PASSWORD", "GITHUB_TOKEN", "GITHUB_PAT",
                       "MASTODON_ACCESS_TOKEN", "MASTODON_INSTANCE_URL")


def _env_files() -> list:
    from pathlib import Path
    files = []
    if os.environ.get("TRE_ENV_FILE", "").strip():
        files.append(Path(os.path.expanduser(os.environ["TRE_ENV_FILE"].strip())))
    files.append(Path(__file__).resolve().parents[1] / ".env")
    return files


def load_poc_credentials(files=None) -> list:
    """Read the PoC source credentials (Bluesky, GitHub, Mastodon) from an env file into ``os.environ``.

    Only the keys in ``POC_CREDENTIAL_KEYS`` are read; a variable already set in the environment is never
    replaced. Files: ``$TRE_ENV_FILE`` if set, then ``.env`` at the repository root. Values are never logged.
    Returns the names that were set."""
    done = []
    for path in files or _env_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            if key not in POC_CREDENTIAL_KEYS or os.environ.get(key):
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                os.environ[key] = value
                done.append(key)
    if done:
        logger.info("PoC credentials loaded from env file: %s", ", ".join(sorted(set(done))))
    return done
