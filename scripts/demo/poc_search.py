"""Live PoC search without the retrieval indexes (works on any machine with internet).

    python scripts/demo/poc_search.py CVE-2021-4034 [max_results]

Prints the same response the /api/v1/pocs/find endpoint returns.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from threat_retrieval_engine.poc_intelligence import get_poc_finder  # noqa: E402

cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-4034"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
res = get_poc_finder().find_pocs_sync(cve, max_results=n, bypass_cache=True)
out = res.model_dump() if hasattr(res, "model_dump") else res
sys.stdout.reconfigure(encoding="utf-8")
print(json.dumps(out, indent=1, default=str, ensure_ascii=False))
