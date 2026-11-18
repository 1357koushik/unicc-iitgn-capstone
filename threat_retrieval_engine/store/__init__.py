"""C1 document store: one row per CVE, built from the raw NVD, CVE List V5, CISA KEV and EPSS feeds.

Build:  python -m threat_retrieval_engine.store.build --feeds <dir> --sources <dir> --out <dir>
Check:  python -m threat_retrieval_engine.store.check_c1 [--store <build dir or store root>]
Read:   from threat_retrieval_engine.store import Store

Plan reference: docs/RETRIEVAL_V2_PLAN.md sections 4.2 (store and duplicate handling) and 4.3 (aliases).
This package replaces v1's ingestion for v2; v1 (`search_engine/validator.py`, `duplicate_checker.py`,
`ingestion_pipeline.py`) keeps running unchanged until the pipeline rewrite (C6).
"""
from .reader import Store, resolve_build
from .schema import STORE_VERSION

__all__ = ["Store", "resolve_build", "STORE_VERSION"]
