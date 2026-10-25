from __future__ import annotations

import tempfile
import sqlite3
import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from threat_retrieval_engine.search_engine.exact_lookup import (
    ExactMatch,
    exact_lookup,
)
from threat_retrieval_engine.search_engine.vector_database import setup_sqlite


def test_exact_lookup_sqlite_and_source_filtering():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_corpus.db"
        conn = setup_sqlite(str(db_path))
        try:
            with conn:
                # Insert two chunks with matching IP: one from NVD, one from EPSS
                entities = json.dumps({
                    "cves": ["CVE-2024-3400"],
                    "iocs": {"ipv4": ["198.51.100.24"], "sha256": []},
                    "mitre_ttps": [],
                })
                conn.execute(
                    """
                    INSERT INTO corpus (chunk_id, doc_id, doc_title, source_org, published_date, text, enriched_text, entities_json)
                    VALUES ('chk_nvd', 'CVE-2024-3400_NVD', 'NVD Title', 'NVD', '2024-04-12T00:00:00Z', 'Text with 198.51.100.24', 'Text with 198.51.100.24', ?)
                    """,
                    (entities,),
                )
                conn.execute(
                    """
                    INSERT INTO corpus (chunk_id, doc_id, doc_title, source_org, published_date, text, enriched_text, entities_json)
                    VALUES ('chk_epss', 'CVE-2024-3400_EPSS', 'EPSS Title', 'EPSS', '2024-04-12T00:00:00Z', 'Text with 198.51.100.24', 'Text with 198.51.100.24', ?)
                    """,
                    (entities,),
                )
                # Add entity_index entries
                conn.execute(
                    "INSERT INTO entity_index VALUES ('198.51.100.24', 'chk_nvd', 'ipv4')"
                )
                conn.execute(
                    "INSERT INTO entity_index VALUES ('198.51.100.24', 'chk_epss', 'ipv4')"
                )

            mock_qdrant = MagicMock()
            mock_qdrant.scroll.return_value = ([], None)

            # 1. Lookup without source filtering -> returns both
            matches_all = exact_lookup(
                mock_qdrant,
                sqlite=conn,
                query="Incident on 198.51.100.24",
            )
            matched_chunks = [m.chunk_id for m in matches_all]
            assert "chk_nvd" in matched_chunks
            assert "chk_epss" in matched_chunks

            # 2. Lookup with allowed_sources=['NVD'] (R13)
            matches_nvd = exact_lookup(
                mock_qdrant,
                sqlite=conn,
                query="Incident on 198.51.100.24",
                allowed_sources=["NVD"],
            )
            matched_nvd_chunks = [m.chunk_id for m in matches_nvd]
            assert "chk_nvd" in matched_nvd_chunks
            assert "chk_epss" not in matched_nvd_chunks
        finally:
            conn.close()
