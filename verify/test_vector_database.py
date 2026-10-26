from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import sqlite3
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from threat_retrieval_engine.search_engine.validator import (
    ThreatChunk,
    CyberEntities,
    IOCEntities,
)
from threat_retrieval_engine.search_engine.vectorizer import VectorResult
from threat_retrieval_engine.search_engine.vector_database import (
    setup_sqlite,
    store_chunks,
    fetch_text,
    fetch_chunk_metadata,
)


def test_sqlite_setup_and_store_chunks_with_entity_index():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "corpus_test.db"
        conn = setup_sqlite(str(db_path))

        try:
            # Check entity_index table exists
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            assert "corpus" in tables
            assert "entity_index" in tables

            # Create ThreatChunk and VectorResult
            tc = ThreatChunk(
                chunk_id="chunk_test_101",
                doc_id="CVE-2024-3400_NVD",
                doc_title="PAN-OS Advisory",
                source_org="NVD",
                published_date=datetime.now(timezone.utc),
                text="Primary text content of CVE-2024-3400",
                entities=CyberEntities(
                    cves=["CVE-2024-3400"],
                    iocs=IOCEntities(
                        ipv4=["192.0.2.1"],
                        sha256=["abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"],
                    ),
                    threat_actors=["UTA0218"],
                    malware_families=["Upstream"],
                    mitre_ttps=["T1059"],
                    severity="CRITICAL",
                ),
            )
            vr = VectorResult(
                chunk_id="chunk_test_101",
                dense_vector=[0.1] * 1024,
                sparse_vector={1: 1.0},
                enriched_text="Enriched CVE-2024-3400 content",
            )

            mock_qdrant = MagicMock()
            store_chunks([vr], [tc], mock_qdrant, conn)

            # Verify fetch_text
            text = fetch_text("chunk_test_101", conn)
            assert text == "Primary text content of CVE-2024-3400"

            # Verify fetch_chunk_metadata
            meta = fetch_chunk_metadata("chunk_test_101", conn)
            assert meta is not None
            assert meta["doc_id"] == "CVE-2024-3400_NVD"
            assert meta["source_org"] == "NVD"

            # Verify entity_index rows were populated
            entities = conn.execute(
                "SELECT entity_kind, entity_value FROM entity_index WHERE chunk_id = 'chunk_test_101'"
            ).fetchall()
            entity_pairs = [(e[0], e[1]) for e in entities]
            assert ("cve", "CVE-2024-3400") in entity_pairs
            assert ("actor", "uta0218") in entity_pairs
        finally:
            conn.close()
