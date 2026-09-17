"""
Team 2 Live Bootstrap — dependency injection for real retrieval.

Constructs real Koushik/Suhani dependencies and wires UpstreamRetrievalBackend.
No hardcoded personal paths; uses configurable UPSTREAM_MODULE_PATH or PYTHONPATH.
Fails clearly when required teammate objects are unavailable.
"""
from __future__ import annotations

import sys
import sqlite3
import importlib.util
import os
from typing import Any

from src.core.interfaces import RetrievalBackend, MockRetrievalBackend, set_backend, MissingUpstreamDependency
from src.core.config import get_settings
from src.adapters.upstream_adapter import UpstreamRetrievalBackend


def _import_upstream(mod_name: str, module_path: str | None = None):
    """Try to import upstream module from PYTHONPATH or configurable path."""
    try:
        return __import__(mod_name)
    except ImportError:
        pass
    if module_path and os.path.isdir(module_path):
        for root, _, files in os.walk(module_path):
            for f in files:
                if f == f"{mod_name}.py":
                    full = os.path.join(root, f)
                    spec = importlib.util.spec_from_file_location(mod_name, full)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        sys.modules[mod_name] = mod
                        spec.loader.exec_module(mod)
                        return mod
    return None


TEAMMATE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "unicc-iitgn-capstone-main")
)
DEFAULT_SQLITE_PATH = os.path.join(TEAMMATE_DIR, "data", "sqlite", "corpus_store.db")


def _sqlite_fetch_chunk_metadata(chunk_id: str, sqlite: sqlite3.Connection) -> dict[str, Any] | None:
    """Fetch chunk metadata directly from teammate SQLite corpus_store.db."""
    import json
    row = sqlite.execute(
        "SELECT chunk_id, doc_id, doc_title, source_org, published_date, "
        "char_start, char_end, text, enriched_text, entities_json "
        "FROM corpus WHERE chunk_id = ?",
        (chunk_id,),
    ).fetchone()
    if not row:
        return None
    entities_dict = {}
    if row[9]:
        try:
            entities_dict = json.loads(row[9])
        except Exception:
            entities_dict = {}
    return {
        "chunk_id": row[0],
        "doc_id": row[1],
        "doc_title": row[2],
        "source_org": row[3],
        "published_date": row[4],
        "char_start": row[5],
        "char_end": row[6],
        "text": row[7],
        "enriched_text": row[8],
        "entities_json": row[9],
        "entities": entities_dict,
    }


def build_live_bm25_backend(sqlite_path: str | Path | None = None) -> UpstreamRetrievalBackend:
    """
    Constructs an UpstreamRetrievalBackend wrapping the teammate's ACTUAL Okapi BM25 index
    from unicc-iitgn-capstone-main/bm25_index.py over their corpus_store.db.
    """
    db_path = str(sqlite_path) if sqlite_path else DEFAULT_SQLITE_PATH
    if not os.path.isfile(db_path):
        raise MissingUpstreamDependency(
            f"Teammate SQLite corpus not found at {db_path}. "
            "Ensure unicc-iitgn-capstone-main/data/sqlite/corpus_store.db exists."
        )

    # Ensure teammate directory is in sys.path
    if TEAMMATE_DIR not in sys.path:
        sys.path.insert(0, TEAMMATE_DIR)

    try:
        from bm25_index import build_from_sqlite
    except ImportError as exc:
        raise MissingUpstreamDependency(
            f"Failed to import teammate bm25_index module from {TEAMMATE_DIR}: {exc}"
        ) from exc

    conn = sqlite3.connect(db_path)
    bm25 = build_from_sqlite(conn)

    return UpstreamRetrievalBackend(
        hybrid_searcher=bm25,
        sqlite_connection=conn,
        fetch_chunk_metadata=_sqlite_fetch_chunk_metadata,
        exact_lookup=None,
        qdrant_client=None,
    )


def build_live_backend() -> Any:
    settings = get_settings()
    upstream_path = settings.UPSTREAM_MODULE_PATH or os.environ.get("UPSTREAM_MODULE_PATH", "") or TEAMMATE_DIR

    if upstream_path and os.path.isdir(upstream_path) and upstream_path not in sys.path:
        sys.path.insert(0, upstream_path)

    # Check for specific known dependencies before attempting hybrid_search import
    missing_deps: list[str] = []
    for pkg in ("ftfy", "torch", "FlagEmbedding", "qdrant_client"):
        try:
            __import__(pkg)
        except ImportError:
            missing_deps.append(pkg)

    if missing_deps:
        raise MissingUpstreamDependency(
            f"Upstream teammate HybridSearcher requires dependencies that are not installed: {missing_deps}. "
            f"Please install teammate dependencies declared in {os.path.join(upstream_path, 'pyproject.toml')}. "
            "To evaluate using teammate's keyword BM25 retrieval without neural models, use mode='bm25'."
        )

    upstream_hybrid = _import_upstream("hybrid_search", upstream_path)
    if upstream_hybrid is None:
        raise MissingUpstreamDependency(
            "Upstream hybrid_search module not available. "
            "Set UPSTREAM_MODULE_PATH env/config to teammate repo, or use RETRIEVAL_BACKEND=mock."
        )

    # Try upstream setup_databases (vector_database)
    try:
        vd = _import_upstream("vector_database", upstream_path)
        if vd is not None and hasattr(vd, "setup_databases"):
            qdrant, sqlite = vd.setup_databases()
        else:
            raise MissingUpstreamDependency(
                "Upstream setup_databases not available; Qdrant + SQLite not initialized. "
                "Provide actual teammate storage or inject qdrant/sqlite objects manually."
            )
    except MissingUpstreamDependency:
        raise
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to initialize upstream Qdrant/SQLite: {exc}. "
            "Confirm teammate storage is accessible at configured UPSTREAM_MODULE_PATH."
        ) from exc

    # BM25 index from upstream bm25_index
    try:
        bm25_mod = _import_upstream("bm25_index", upstream_path)
        if bm25_mod is None or not hasattr(bm25_mod, "build_from_sqlite"):
            raise MissingUpstreamDependency("Upstream BM25Index module unavailable.")
        bm25 = bm25_mod.build_from_sqlite(sqlite)
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to build BM25 index: {exc}. "
            "Confirm teammate BM25 index is available or inject bm25_index directly."
        ) from exc

    # Encoder from upstream vectorizer or default
    try:
        vectorizer = _import_upstream("vectorizer", upstream_path)
        if vectorizer is not None and hasattr(vectorizer, "default_query_encoder"):
            query_encoder = vectorizer.default_query_encoder
        else:
            raise MissingUpstreamDependency("Upstream query_encoder missing: provide BGE-M3 encoder or inject query_encoder.")
    except MissingUpstreamDependency:
        raise
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to load query encoder: {exc}."
        ) from exc

    # Assemble real HybridSearcher
    try:
        HybridSearcher = getattr(upstream_hybrid, "HybridSearcher", None)
        if HybridSearcher is None:
            raise MissingUpstreamDependency("HybridSearcher class not found in upstream module.")
        hybrid_searcher = HybridSearcher(
            qdrant=qdrant,
            sqlite=sqlite,
            bm25=bm25,
            query_encoder=query_encoder,
        )
    except Exception as exc:
        raise MissingUpstreamDependency(
            f"Failed to construct HybridSearcher: {exc}. "
            "Injectable dependencies: qdrant_client, sqlite_connection, bm25_index, query_encoder."
        ) from exc

    # Build adapter with real instances (inject qdrant for exact_lookup path)
    exact_lookup_mod = _import_upstream("exact_lookup", upstream_path)
    exact_lookup_fn = getattr(exact_lookup_mod, "exact_lookup", None) if exact_lookup_mod else None
    return UpstreamRetrievalBackend(
        hybrid_searcher=hybrid_searcher,
        sqlite_connection=sqlite,
        fetch_chunk_metadata=getattr(vd, "fetch_chunk_metadata", None) or _sqlite_fetch_chunk_metadata,
        exact_lookup=exact_lookup_fn,
        qdrant_client=qdrant,
    )


def bootstrap_retrieval(settings) -> Any:
    """Factory called by main.py lifespan for RETRIEVAL_BACKEND."""
    mode = getattr(settings, "RETRIEVAL_BACKEND", "mock")
    if mode == "mock":
        from src.core.interfaces import MockRetrievalBackend
        return MockRetrievalBackend()
    if mode in ("live", "hybrid"):
        return build_live_backend()
    if mode == "bm25":
        return build_live_bm25_backend()
    if mode == "auto":
        try:
            return build_live_backend()
        except MissingUpstreamDependency as exc:
            import logging
            logging.getLogger(__name__).warning(
                "Live hybrid backend unavailable (%s); using teammate Okapi BM25 backend.", exc
            )
            return build_live_bm25_backend()
    raise ValueError(f"Unknown RETRIEVAL_BACKEND: {mode}")
