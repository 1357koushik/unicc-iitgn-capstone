"""v1's lexical retriever (pure-Python BM25 over the v1 corpus), run in-process at document level.

Variant ``v1_lexical`` in variants.yaml. Used by C2 for the gate "lexical Recall@50 at or above v1 on every
slice". The scoring code is v1's own: ``threat_retrieval_engine.search_engine.bm25_index`` and
``tokenizer``, which differ from the ``v1-baseline`` tag only in import statements (A2 removed the
try/except import fallback); the index is v1's pickled index, copied read-only from the server's
``~/data/sqlite`` and loaded through v1's ``build_from_sqlite``, which refuses the file unless its SHA-256
matches the sidecar written with it and its document count matches the corpus.

Document level: v1 ranks corpus rows (chunks); each chunk maps to its corpus ``doc_id`` and then to the CVE
ID before any ``_KEV``/``_EPSS`` suffix (the harness's ``cve_prefix`` rule); the first occurrence of a CVE
keeps its rank. v1's own pipeline takes only the top 50 chunks; here the BM25 ranking is read as deep as
needed to find ``k`` distinct documents, the most favourable reading of v1 for the comparison.

Loading the pickle runs v1 code on a file v1 itself wrote; this is offline baseline tooling only and never
part of the v2 service (plan 5.1: no pickle loading in v2).
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from .adapters import transform_doc_id

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = REPO_ROOT / "data" / "v1_server" / "sqlite"


def default_dir() -> Path:
    env = os.environ.get("TRE_V1_SQLITE_DIR")
    return Path(env) if env else DEFAULT_DIR


class V1Lexical:
    def __init__(self, sqlite_dir: str | None = None, k: int = 100):
        from threat_retrieval_engine.search_engine.bm25_index import build_from_sqlite
        d = Path(os.path.expanduser(sqlite_dir)) if sqlite_dir else default_dir()
        db_path = d / "corpus_store.db"
        pkl = d / "bm25_index.pkl"
        if not db_path.is_file() or not pkl.is_file():
            raise FileNotFoundError(f"v1 corpus or BM25 pickle missing under {d}")
        self.dir = d
        self.db = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, check_same_thread=False)
        self.bm25 = build_from_sqlite(self.db, cache_path=pkl)
        self.sidecar = (d / "bm25_index.sha256").read_text(encoding="utf-8").split()
        if self.bm25.size != int(self.sidecar[1]):
            raise RuntimeError("v1 BM25 cache did not load (build_from_sqlite rebuilt instead of loading it)")
        self.chunk_doc = dict(self.db.execute("SELECT chunk_id, doc_id FROM corpus"))
        self.k = int(k)

    def search(self, text: str) -> list[tuple[str, float]]:
        depth = max(4 * self.k, 200)
        while True:
            hits = self.bm25.search(text, top_k=depth)
            out, seen = [], set()
            for h in hits:
                doc = transform_doc_id(self.chunk_doc[h.chunk_id], "cve_prefix")
                if doc is None or doc in seen:
                    continue
                seen.add(doc)
                out.append((doc, h.score))
                if len(out) >= self.k:
                    return out
            if len(hits) < depth:
                return out
            depth *= 4

    def info(self) -> dict:
        return {"component": "v1 BM25 (search_engine/bm25_index.py)", "documents": self.bm25.size,
                "k1": self.bm25.k1, "b": self.bm25.b, "pickle_sha256": self.sidecar[0], "dir": str(self.dir)}


def make(sqlite_dir: str | None = None, k: int = 100) -> V1Lexical:
    return V1Lexical(sqlite_dir=sqlite_dir, k=k)
