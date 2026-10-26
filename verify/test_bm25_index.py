from __future__ import annotations

import tempfile
import sqlite3
from pathlib import Path
import pytest

from threat_retrieval_engine.search_engine.bm25_index import (
    BM25Index,
    BM25Result,
    build_from_sqlite,
)


def test_bm25_empty_index_returns_empty():
    index = BM25Index()
    index.finalize()
    results = index.search("CVE-2021-44228", top_k=5)
    assert results == []


def test_bm25_add_documents_and_search():
    index = BM25Index()
    docs = [
        ("doc1", "Apache Log4j2 remote code execution vulnerability CVE-2021-44228"),
        ("doc2", "Microsoft Exchange Server remote code execution CVE-2021-26855"),
        ("doc3", "Unrelated general networking documentation"),
    ]
    for doc_id, text in docs:
        index.add(doc_id, text)
    index.finalize()

    assert len(index._doc_len) == 3
    assert index._avgdl > 0

    results = index.search("CVE-2021-44228", top_k=2)
    assert len(results) >= 1
    assert results[0].chunk_id == "doc1"
    assert results[0].score > 0.0

    # Searching with allowed_ids filter
    filtered = index.search("CVE-2021-44228", top_k=2, allowed_ids={"doc2", "doc3"})
    assert all(r.chunk_id != "doc1" for r in filtered)


def test_bm25_build_from_sqlite_and_cache_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_corpus.db"
        cache_path = Path(tmpdir) / "bm25_cache.pkl"

        conn = sqlite3.connect(str(db_path))
        with conn:
            conn.execute(
                """
                CREATE TABLE corpus (
                    chunk_id TEXT PRIMARY KEY,
                    doc_id TEXT,
                    enriched_text TEXT
                )
                """
            )
            conn.execute(
                "INSERT INTO corpus VALUES ('c1', 'CVE-2024-3400_NVD', 'Palo Alto PAN-OS command injection CVE-2024-3400')"
            )
            conn.execute(
                "INSERT INTO corpus VALUES ('c2', 'CVE-2024-21887_NVD', 'Ivanti Connect Secure command injection CVE-2024-21887')"
            )
        conn.close()

        index1 = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(index1._doc_len) == 2

        # Second load should load from cache_path
        index2 = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(index2._doc_len) == 2
        res = index2.search("PAN-OS", top_k=1)
        assert len(res) == 1
        assert res[0].chunk_id == "c1"
