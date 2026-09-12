"""
test_exact_lookup.py
====================
Tests for exact_lookup.py — deterministic IOC/CVE lookup.

Uses a real embedded Qdrant + SQLite in a temp dir (no mocks needed for storage).

Run with: pytest verify/test_exact_lookup.py -v
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from exact_lookup import exact_lookup
from validator import CyberEntities, IOCEntities, ThreatChunk
from vector_database import setup_databases, store_chunks
from vectorizer import VectorResult


@pytest.fixture
def db(tmp_path):
    qdrant, sqlite = setup_databases(
        str(tmp_path / "qdrant"), str(tmp_path / "sqlite" / "corpus.db")
    )
    yield qdrant, sqlite
    sqlite.close()


def _vr(chunk_id: str) -> VectorResult:
    dense = np.random.rand(1024)
    dense = (dense / np.linalg.norm(dense)).tolist()
    return VectorResult(chunk_id, dense, {101: 0.5}, "enriched")


def _store(db, chunk):
    qdrant, sqlite = db
    store_chunks([_vr(chunk.chunk_id)], [chunk], qdrant, sqlite)


def _chunk(chunk_id, entities, text="A malicious campaign exploiting a vulnerability in the wild."):
    return ThreatChunk(
        chunk_id=chunk_id,
        doc_id="DOC-1",
        doc_title="Advisory",
        source_org="CISA",
        published_date=datetime(2023, 5, 25, tzinfo=timezone.utc),
        text=text,
        entities=entities,
    )


# ---------------------------------------------------------------------------
# CVE lookup via Qdrant payload
# ---------------------------------------------------------------------------


def test_cve_exact_lookup(db):
    qdrant, sqlite = db
    _store(db, _chunk("k1", CyberEntities(cves=["CVE-2017-0144"], severity="HIGH")))

    matches = exact_lookup(qdrant, sqlite, query="does CVE-2017-0144 appear?")
    assert len(matches) == 1
    assert matches[0].chunk_id == "k1"
    assert matches[0].matched_field == "cves"


def test_cve_lookup_via_explicit_identifiers(db):
    qdrant, sqlite = db
    _store(db, _chunk("k1", CyberEntities(cves=["CVE-2021-44228"])))

    matches = exact_lookup(qdrant, sqlite, identifiers={"cve": ["CVE-2021-44228"]})
    assert matches[0].chunk_id == "k1"


# ---------------------------------------------------------------------------
# IOC lookup via SQLite entities_json
# ---------------------------------------------------------------------------


def test_ipv4_exact_lookup(db):
    qdrant, sqlite = db
    ents = CyberEntities(iocs=IOCEntities(ipv4=["198.51.100.24"]))
    _store(db, _chunk("k2", ents))

    matches = exact_lookup(qdrant, sqlite, query="who owns 198.51.100.24 ?")
    assert len(matches) == 1
    assert matches[0].chunk_id == "k2"
    assert matches[0].matched_field == "iocs.ipv4"


def test_hash_exact_lookup(db):
    qdrant, sqlite = db
    h = "d" * 64
    ents = CyberEntities(iocs=IOCEntities(sha256=[h]))
    _store(db, _chunk("k3", ents))

    matches = exact_lookup(qdrant, sqlite, query=f"sample {h} seen")
    assert matches[0].chunk_id == "k3"


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def test_no_identifiers_returns_empty(db):
    qdrant, sqlite = db
    assert exact_lookup(qdrant, sqlite, query="generic ransomware writeup") == []


def test_metadata_hydrated(db):
    qdrant, sqlite = db
    _store(db, _chunk("k1", CyberEntities(cves=["CVE-2017-0144"])))
    matches = exact_lookup(qdrant, sqlite, query="CVE-2017-0144", hydrate=True)
    assert matches[0].metadata.get("doc_id") == "DOC-1"


def test_dedup_across_kinds(db):
    """A chunk matching on two identifiers appears once."""
    qdrant, sqlite = db
    ents = CyberEntities(cves=["CVE-2017-0144"], iocs=IOCEntities(ipv4=["10.0.0.9"]))
    _store(db, _chunk("k1", ents))
    matches = exact_lookup(qdrant, sqlite, query="CVE-2017-0144 from 10.0.0.9")
    assert len(matches) == 1
