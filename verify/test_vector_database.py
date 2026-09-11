"""
test_vector_database.py
=======================
Tests for src/vector_database.py (Qdrant + SQLite storage)

Uses a temporary directory for Qdrant and a temporary SQLite file —
no real database files are left behind after tests.

Run with: pytest verify/test_vector_database.py -v
"""

import json
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from validator import CyberEntities, ThreatChunk
from vectorizer import VectorResult
from vector_database import (
    COLLECTION_NAME,
    fetch_chunk_metadata,
    fetch_text,
    search_vectors,
    setup_databases,
    setup_qdrant,
    setup_sqlite,
    store_chunks,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_dirs(tmp_path):
    qdrant_path = str(tmp_path / "qdrant")
    sqlite_path = str(tmp_path / "sqlite" / "corpus.db")
    return qdrant_path, sqlite_path


@pytest.fixture
def db(tmp_dirs):
    qdrant_path, sqlite_path = tmp_dirs
    qdrant, sqlite = setup_databases(qdrant_path, sqlite_path)
    yield qdrant, sqlite
    sqlite.close()


def _make_chunk(chunk_id: str = "test_chunk_001", text: str = None) -> ThreatChunk:
    return ThreatChunk(
        chunk_id=chunk_id,
        doc_id="CVE-2024-1234",
        doc_title="Test CVE Advisory",
        source_org="NVD",
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        section_header="Description",
        text=text or "This vulnerability allows remote code execution via a crafted network packet.",
        entities=CyberEntities(cves=["CVE-2024-1234"], severity="HIGH"),
    )


def _make_vector_result(chunk_id: str = "test_chunk_001", enriched_text: str = "context") -> VectorResult:
    dense = np.random.rand(1024).tolist()
    norm = float(np.linalg.norm(dense))
    dense = [v / norm for v in dense]
    return VectorResult(
        chunk_id=chunk_id,
        dense_vector=dense,
        sparse_vector={101: 0.5, 202: 0.3, 303: 0.1},
        enriched_text=enriched_text,
    )


# ---------------------------------------------------------------------------
# Qdrant setup
# ---------------------------------------------------------------------------


def test_qdrant_collection_created(db):
    qdrant, _ = db
    collections = {col.name for col in qdrant.get_collections().collections}
    assert COLLECTION_NAME in collections


def test_qdrant_collection_not_duplicated(tmp_dirs):
    """Calling setup_qdrant twice should not crash."""
    qdrant_path, _ = tmp_dirs
    setup_qdrant(qdrant_path)
    setup_qdrant(qdrant_path)   # second call should be safe


# ---------------------------------------------------------------------------
# SQLite setup
# ---------------------------------------------------------------------------


def test_sqlite_table_created(db):
    _, sqlite = db
    tables = sqlite.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    table_names = {row[0] for row in tables}
    assert "corpus" in table_names


def test_sqlite_has_correct_columns(db):
    _, sqlite = db
    columns = sqlite.execute("PRAGMA table_info(corpus)").fetchall()
    col_names = {col[1] for col in columns}
    expected = {"chunk_id", "doc_id", "doc_title", "source_org", "published_date", "text", "enriched_text", "entities_json"}
    assert expected.issubset(col_names)


# ---------------------------------------------------------------------------
# store_chunks + fetch_text
# ---------------------------------------------------------------------------


def test_store_and_fetch_text(db):
    qdrant, sqlite = db
    chunk = _make_chunk()
    vr = _make_vector_result()

    store_chunks([vr], [chunk], qdrant, sqlite)

    result = fetch_text(chunk.chunk_id, sqlite)
    assert result == chunk.text


def test_fetch_nonexistent_returns_none(db):
    _, sqlite = db
    result = fetch_text("does_not_exist_abc", sqlite)
    assert result is None


def test_store_ignores_duplicates(db):
    """Storing the same chunk twice should not create duplicate rows."""
    qdrant, sqlite = db
    chunk = _make_chunk()
    vr = _make_vector_result()

    store_chunks([vr], [chunk], qdrant, sqlite)
    store_chunks([vr], [chunk], qdrant, sqlite)   # second time

    count = sqlite.execute(
        "SELECT COUNT(*) FROM corpus WHERE chunk_id = ?", (chunk.chunk_id,)
    ).fetchone()[0]
    assert count == 1


def test_store_multiple_chunks(db):
    qdrant, sqlite = db
    chunks = [
        _make_chunk(chunk_id=f"chunk_{i:04d}", text=f"Vulnerability number {i} allows attackers to compromise the system remotely.")
        for i in range(5)
    ]
    vrs = [_make_vector_result(chunk_id=c.chunk_id, enriched_text=f"context {i}") for i, c in enumerate(chunks)]

    store_chunks(vrs, chunks, qdrant, sqlite)

    count = sqlite.execute("SELECT COUNT(*) FROM corpus").fetchone()[0]
    assert count == 5


# ---------------------------------------------------------------------------
# fetch_chunk_metadata
# ---------------------------------------------------------------------------


def test_fetch_chunk_metadata(db):
    qdrant, sqlite = db
    chunk = _make_chunk()
    vr = _make_vector_result(enriched_text="Document: Test | Content: RCE vulnerability.")

    store_chunks([vr], [chunk], qdrant, sqlite)

    meta = fetch_chunk_metadata(chunk.chunk_id, sqlite)
    assert meta is not None
    assert meta["doc_id"] == "CVE-2024-1234"
    assert meta["source_org"] == "NVD"
    assert meta["enriched_text"] == "Document: Test | Content: RCE vulnerability."
    assert isinstance(meta["entities"], dict)


def test_fetch_chunk_metadata_nonexistent(db):
    _, sqlite = db
    meta = fetch_chunk_metadata("ghost_chunk_xyz", sqlite)
    assert meta is None


def test_search_vectors_returns_hits(db):
    """Verify search_vectors returns matching points for Suhani's query layer."""
    qdrant, sqlite = db
    chunk = _make_chunk(chunk_id="search_test_01")
    chunk.char_start = 100
    chunk.char_end = 250
    vr = _make_vector_result(chunk_id="search_test_01")

    store_chunks([vr], [chunk], qdrant, sqlite)

    hits = search_vectors(qdrant, vr.dense_vector, top_k=5)
    assert len(hits) >= 1
    assert hits[0]["chunk_id"] == "search_test_01"
    assert "severity" in hits[0]["payload"]


def test_fetch_chunk_metadata_preserves_char_offsets(db):
    """Verify char_start and char_end are retrieved for Harshith's citation engine."""
    qdrant, sqlite = db
    chunk = _make_chunk(chunk_id="offset_chunk_01")
    chunk.char_start = 120
    chunk.char_end = 450
    vr = _make_vector_result(chunk_id="offset_chunk_01")

    store_chunks([vr], [chunk], qdrant, sqlite)

    meta = fetch_chunk_metadata("offset_chunk_01", sqlite)
    assert meta is not None
    assert meta["char_start"] == 120
    assert meta["char_end"] == 450

