"""
threat_retrieval_engine
=======================
Team 2: Threat Retrieval & Matching Subsystem.
"""

from __future__ import annotations

import sys
import types
import unicodedata

# Ensure ftfy compatibility across all runtime environments
try:
    import ftfy  # noqa: F401
except ImportError:
    ftfy_mock = types.ModuleType("ftfy")
    ftfy_mock.fix_text = lambda s, **kwargs: unicodedata.normalize("NFKC", str(s))
    sys.modules["ftfy"] = ftfy_mock

# CPU thread settings must be exported before torch / numpy load (TRE_NUM_THREADS)
from threat_retrieval_engine.runtime import apply_thread_env as _apply_thread_env  # noqa: E402

_apply_thread_env()

# PoC source credentials (Bluesky, GitHub, Mastodon) from $TRE_ENV_FILE or the repository's .env
from threat_retrieval_engine.runtime import load_poc_credentials as _load_poc_credentials  # noqa: E402

_load_poc_credentials()
