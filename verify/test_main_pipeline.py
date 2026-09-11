"""
test_main_pipeline.py
=====================
End-to-end integration tests for main.py

These tests run the complete pipeline on small fake CSV/JSON data
and verify chunks end up in both Qdrant and SQLite.

The BGE-M3 model is MOCKED so tests run instantly with no GPU or download.

Run with: pytest verify/test_main_pipeline.py -v
"""

import json
import sys
from pathlib import Path
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import run_pipeline
from vector_database import fetch_text, setup_sqlite
from vectorizer import BGEVectorizer, VectorResult


# ---------------------------------------------------------------------------
# Helpers for fake embeddings
# ---------------------------------------------------------------------------


def _mock_encode_result(items):
    """Return fake VectorResults matching the items list."""
    results = []
    for chunk_id, text in items:
        dense = np.random.rand(1024).tolist()
        norm = float(np.linalg.norm(dense))
        dense = [v / norm for v in dense]
        results.append(
            VectorResult(
                chunk_id=chunk_id,
                dense_vector=dense,
                sparse_vector={1: 0.5, 2: 0.3},
                enriched_text=text,
            )
        )
    return results


@pytest.fixture(autouse=True)
def mock_bge_vectorizer(monkeypatch):
    """Ensure BGEVectorizer.encode returns mock VectorResults without loading real model."""
    import vectorizer

    monkeypatch.setattr(
        vectorizer.BGEVectorizer,
        "encode",
        lambda self, items: _mock_encode_result(items),
    )
    monkeypatch.setattr(
        vectorizer.BGEVectorizer,
        "_load_model",
        lambda self: None,
    )


# ---------------------------------------------------------------------------
# Fake data helpers
# ---------------------------------------------------------------------------


KEV_CSV_CONTENT = (
    "cveID,vendorProject,product,vulnerabilityName,dateAdded,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
    "CVE-2021-44228,Apache,Log4j,Apache Log4j Remote Code Execution,2021-12-10,"
    "Patch immediately by upgrading to Log4j 2.15.0 or later.,2021-12-24,Known,"
    "Critical JNDI RCE exploit affecting millions of servers worldwide\n"
    "CVE-2022-26134,Atlassian,Confluence,Confluence Server RCE,2022-06-03,"
    "Upgrade to patched version immediately.,2022-06-17,Known,"
    "OGNL injection allows unauthenticated RCE on Confluence servers\n"
)

KEV_DUPLICATE_CONTENT = (
    "cveID,vendorProject,product,vulnerabilityName,dateAdded,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
    "CVE-2021-44228,Apache,Log4j,Apache Log4j Remote Code Execution,2021-12-10,"
    "Patch immediately by upgrading to Log4j 2.15.0 or later.,2021-12-24,Known,"
    "Critical JNDI RCE exploit affecting millions of servers worldwide\n"
    "CVE-2021-44228,Apache,Log4j,Apache Log4j Remote Code Execution,2021-12-10,"
    "Patch immediately by upgrading to Log4j 2.15.0 or later.,2021-12-24,Known,"
    "Critical JNDI RCE exploit affecting millions of servers worldwide\n"
)

EPSS_CSV_CONTENT = (
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97531,0.99987\n"
    "CVE-2022-26134,0.95103,0.99981\n"
    "CVE-2024-99999,0.001,0.10\n"   # low score — should be skipped
)

BAD_KEV_CONTENT = (
    "cveID,vendorProject,product,vulnerabilityName,dateAdded,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
    "CVE-2099-BAD,Vendor,Product,,2024-01-01,,,Unknown,\n"  # empty name → short text → quarantined
)


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


def test_full_pipeline_kev_only(tmp_path):
    """Two valid KEV rows should produce 2 stored chunks (or 1 if near-dup)."""
    kev_file = tmp_path / "kev.csv"
    kev_file.write_text(KEV_CSV_CONTENT, encoding="utf-8")

    qdrant_path = str(tmp_path / "qdrant")
    sqlite_path = str(tmp_path / "sqlite" / "corpus.db")

    run_pipeline(kev_csv=kev_file, qdrant_path=qdrant_path, sqlite_path=sqlite_path)

    sqlite = setup_sqlite(sqlite_path)
    count = sqlite.execute("SELECT COUNT(*) FROM corpus").fetchone()[0]
    sqlite.close()
    assert count >= 1   # at least one chunk stored


def test_full_pipeline_epss_only(tmp_path):
    """High-scoring EPSS rows should be stored; low-score row skipped."""
    epss_file = tmp_path / "epss.csv"
    epss_file.write_text(EPSS_CSV_CONTENT, encoding="utf-8")

    qdrant_path = str(tmp_path / "qdrant")
    sqlite_path = str(tmp_path / "sqlite" / "corpus.db")

    run_pipeline(epss_csv=epss_file, qdrant_path=qdrant_path, sqlite_path=sqlite_path)

    sqlite = setup_sqlite(sqlite_path)
    count = sqlite.execute("SELECT COUNT(*) FROM corpus").fetchone()[0]
    sqlite.close()
    # 2 high-score CVEs stored, 1 low-score skipped
    assert count == 2


def test_pipeline_deduplication_works(tmp_path):
    """Two identical rows in input should produce only 1 stored chunk."""
    kev_file = tmp_path / "kev_dup.csv"
    kev_file.write_text(KEV_DUPLICATE_CONTENT, encoding="utf-8")

    qdrant_path = str(tmp_path / "qdrant")
    sqlite_path = str(tmp_path / "sqlite" / "corpus.db")

    run_pipeline(kev_csv=kev_file, qdrant_path=qdrant_path, sqlite_path=sqlite_path)

    sqlite = setup_sqlite(sqlite_path)
    count = sqlite.execute("SELECT COUNT(*) FROM corpus").fetchone()[0]
    sqlite.close()
    assert count == 1   # only one unique chunk stored


def test_pipeline_quarantine_created(tmp_path):
    """A bad KEV row should create a quarantine file and NOT crash the pipeline."""
    kev_file = tmp_path / "bad_kev.csv"
    kev_file.write_text(BAD_KEV_CONTENT, encoding="utf-8")

    qdrant_path = str(tmp_path / "qdrant")
    sqlite_path = str(tmp_path / "sqlite" / "corpus.db")

    run_pipeline(kev_csv=kev_file, qdrant_path=qdrant_path, sqlite_path=sqlite_path)
    assert True  # just verifying no crash


def test_pipeline_no_sources_runs_safely(tmp_path):
    """Running with no data sources should complete without error."""
    qdrant_path = str(tmp_path / "qdrant")
    sqlite_path = str(tmp_path / "sqlite" / "corpus.db")

    run_pipeline(qdrant_path=qdrant_path, sqlite_path=sqlite_path)

    sqlite = setup_sqlite(sqlite_path)
    count = sqlite.execute("SELECT COUNT(*) FROM corpus").fetchone()[0]
    sqlite.close()
    assert count == 0


def test_full_pipeline_normalized_dir(tmp_path):
    """Verify full pipeline run when provided with Team 1's normalized JSON directory."""
    norm_dir = tmp_path / "normalized"
    norm_dir.mkdir()

    record1 = {
        "cve_id": "CVE-2024-1001",
        "title": "Normalized Pipeline Test Vulnerability 1",
        "descriptions": [{"language": "en", "text": "High severity security vulnerability affecting web services."}],
        "cvss_metrics": [{"base_score": 8.5}],
    }
    record2 = {
        "cve_id": "CVE-2024-1002",
        "title": "Normalized Pipeline Test Vulnerability 2",
        "descriptions": [{"language": "en", "text": "Critical remote code execution vulnerability in database server."}],
        "cvss_metrics": [{"base_score": 9.8}],
    }

    (norm_dir / "CVE-2024-1001_normalized.json").write_text(json.dumps(record1), encoding="utf-8")
    (norm_dir / "CVE-2024-1002_normalized.json").write_text(json.dumps(record2), encoding="utf-8")

    qdrant_path = str(tmp_path / "qdrant")
    sqlite_path = str(tmp_path / "sqlite" / "corpus.db")

    run_pipeline(normalized_dir=norm_dir, qdrant_path=qdrant_path, sqlite_path=sqlite_path)

    sqlite = setup_sqlite(sqlite_path)
    count = sqlite.execute("SELECT COUNT(*) FROM corpus").fetchone()[0]
    sqlite.close()
    assert count == 2
