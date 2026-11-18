import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import os

# These suites exercise the v1 orchestrator with mocks; v2 API tests set TRE_PIPELINE themselves (test_v2_api.py).
os.environ.setdefault("TRE_PIPELINE", "v1")
