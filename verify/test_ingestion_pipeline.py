from __future__ import annotations

import json
import tempfile
from pathlib import Path
import pytest
from unittest.mock import MagicMock

from threat_retrieval_engine.search_engine.validator import (
    ThreatChunk,
    parse_normalized_directory,
)
from threat_retrieval_engine.search_engine.duplicate_checker import DuplicateChecker
from threat_retrieval_engine.search_engine.vector_database import setup_sqlite, store_chunks
from threat_retrieval_engine.search_engine.vectorizer import VectorResult


def test_ingestion_pipeline_end_to_end_components():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        norm_dir = tmp_path / "normalized_cves"
        norm_dir.mkdir()
        db_path = tmp_path / "corpus_test.db"
        conn = setup_sqlite(str(db_path))

        try:
            # Write sample normalized CVE JSON
            sample_cve = {
                "cve_id": "CVE-2024-3400",
                "title": "Palo Alto PAN-OS Command Injection",
                "description": "A command injection vulnerability in PAN-OS GlobalProtect.",
                "cvss_v3": {"base_score": 10.0, "severity": "CRITICAL"},
                "cisa_kev": {"listed": True},
                "epss": {"score": 0.95},
                "threat_actors": ["UTA0218"],
                "malware_families": [],
                "mitre_attack": ["T1059.004"],
                "sources": ["NVD", "CISA", "EPSS"],
            }
            (norm_dir / "CVE-2024-3400_normalized.json").write_text(
                json.dumps(sample_cve), encoding="utf-8"
            )

            # 1. Parse records
            chunks = list(parse_normalized_directory(norm_dir))
            assert len(chunks) >= 1
            assert "CVE-2024-3400" in chunks[0].entities.cves

            # 2. Dedup
            checker = DuplicateChecker()
            unique = list(checker.filter(chunks))
            assert len(unique) >= 1

            # 3. Vectorize (mocked vectors)
            v_results = [
                VectorResult(
                    chunk_id=c.chunk_id,
                    dense_vector=[0.05] * 1024,
                    sparse_vector={1: 1.0},
                    enriched_text=c.text,
                )
                for c in unique
            ]

            # 4. Store
            mock_qdrant = MagicMock()
            store_chunks(v_results, unique, mock_qdrant, conn)

            # Verify presence in SQLite
            count = conn.execute("SELECT COUNT(*) FROM corpus").fetchone()[0]
            assert count == len(unique)
        finally:
            conn.close()
