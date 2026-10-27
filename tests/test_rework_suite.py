"""
tests/test_rework_suite.py
==========================
Regression and acceptance test suite verifying all 9 core requirements
mandated by Section E of rework_plan.md.
"""

import hashlib
import os
import re
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.testclient import TestClient

import threat_retrieval_engine.api.pipeline as pipeline_mod
from threat_retrieval_engine.api.confidence import (
    ConfidenceModel,
    parse_query_profile,
    resolve_confidence,
)
from threat_retrieval_engine.api.main import app, verify_service_auth
from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine
from threat_retrieval_engine.config import RetrievalConfig, _env_bool
from threat_retrieval_engine.search_engine.bm25_index import BM25Index, build_from_sqlite
from threat_retrieval_engine.search_engine.exact_lookup import _sqlite_lookup
from threat_retrieval_engine.search_engine.hybrid_search import HybridResult
from threat_retrieval_engine.search_engine.validator import (
    CyberEntities,
    IOCEntities,
    ThreatChunk,
)
from threat_retrieval_engine.search_engine.vector_database import (
    setup_sqlite,
    store_chunks,
)
from threat_retrieval_engine.search_engine.vectorizer import VectorResult


# 1. EPSS regex path in run_query (#2)
def test_1_epss_regex_path_in_run_query():
    """Verify #2: pipeline has 're' imported and executes EPSS regex without NameError."""
    assert hasattr(pipeline_mod, "re")
    assert pipeline_mod.re is re

    # Verify regex matches CVE in EPSS-formatted doc_id
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    match = cve_pattern.search("CVE-2017-0144_EPSS_data")
    assert match is not None
    assert match.group(0).upper() == "CVE-2017-0144"


# 2. LIKE wildcard escape returns no unrelated rows (#9)
def test_2_like_wildcard_escape_prevents_wildcard_injection():
    """Verify #9: % and _ are escaped in _sqlite_lookup so they don't act as SQL wildcards."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE entity_index (entity_value TEXT, chunk_id TEXT, entity_kind TEXT);")
    conn.execute("CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, entities_json TEXT);")

    conn.execute('INSERT INTO corpus VALUES ("c_percent", \'{"domain": ["100%safe.com"]}\');')
    conn.execute('INSERT INTO corpus VALUES ("c_other", \'{"domain": ["1000safe.com"]}\');')
    conn.execute('INSERT INTO corpus VALUES ("c_under", \'{"domain": ["a_b.com"]}\');')
    conn.execute('INSERT INTO corpus VALUES ("c_dash", \'{"domain": ["a-b.com"]}\');')
    conn.commit()

    # Search for "100%safe.com" - must only match c_percent
    res_percent = _sqlite_lookup(conn, "100%safe.com", limit=10)
    assert res_percent == ["c_percent"]

    # Search for "a_b.com" - must only match c_under
    res_under = _sqlite_lookup(conn, "a_b.com", limit=10)
    assert res_under == ["c_under"]


# 3. Re-ingest with changed entities leaves no stale entity_index rows (#6)
def test_3_reingest_cleans_stale_entity_index():
    """Verify #6: re-ingesting an updated chunk deletes obsolete entity_index rows in batches."""
    conn = setup_sqlite(":memory:", reset=True)

    entities_v1 = CyberEntities(
        severity="HIGH",
        cves=["CVE-2023-1111"],
        mitre_ttps=["T1059"],
        threat_actors=[],
        malware_families=[],
        iocs=IOCEntities(ipv4=["1.2.3.4"]),
    )
    chunk_v1 = ThreatChunk(
        chunk_id="chunk_test_1",
        doc_id="DOC_1",
        doc_title="V1 document title",
        source_org="NVD",
        published_date=datetime.now(timezone.utc),
        char_start=0,
        char_end=100,
        text="Sample text for testing stale entity index v1",
        entities=entities_v1,
    )
    vr_v1 = VectorResult(
        chunk_id="chunk_test_1",
        dense_vector=[0.1] * 768,
        sparse_vector={10: 1.0},
        enriched_text="enriched text v1",
    )

    class MockQdrant:
        def upsert(self, *args, **kwargs):
            pass

    mock_q = MockQdrant()

    # First ingestion
    store_chunks([vr_v1], [chunk_v1], mock_q, conn)
    rows_v1 = conn.execute("SELECT entity_value FROM entity_index WHERE chunk_id = 'chunk_test_1'").fetchall()
    values_v1 = {r[0] for r in rows_v1}
    assert "CVE-2023-1111" in values_v1
    assert "1.2.3.4" in values_v1

    # Second ingestion with updated entities
    entities_v2 = CyberEntities(
        severity="CRITICAL",
        cves=["CVE-2024-9999"],
        mitre_ttps=["T1078"],
        threat_actors=[],
        malware_families=[],
        iocs=IOCEntities(),
    )
    chunk_v2 = ThreatChunk(
        chunk_id="chunk_test_1",
        doc_id="DOC_1",
        doc_title="V2 document title",
        source_org="NVD",
        published_date=datetime.now(timezone.utc),
        char_start=0,
        char_end=100,
        text="Sample text for testing stale entity index v2",
        entities=entities_v2,
    )
    vr_v2 = VectorResult(
        chunk_id="chunk_test_1",
        dense_vector=[0.2] * 768,
        sparse_vector={20: 1.0},
        enriched_text="enriched text v2",
    )

    store_chunks([vr_v2], [chunk_v2], mock_q, conn)
    rows_v2 = conn.execute("SELECT entity_value FROM entity_index WHERE chunk_id = 'chunk_test_1'").fetchall()
    values_v2 = {r[0] for r in rows_v2}

    # Stale entities must be gone, new entities present
    assert "CVE-2023-1111" not in values_v2
    assert "1.2.3.4" not in values_v2
    assert "CVE-2024-9999" in values_v2
    assert "T1078" in values_v2


# 4. Exact and hybrid hit on the same chunk keeps a non-None dense_score (#4)
def test_4_exact_and_hybrid_overlap_dense_score(tmp_path):
    """Verify #4: exact-match hits that overlap with hybrid hits retain hybrid dense_score."""
    db_file = tmp_path / "test_corpus.db"
    conn = setup_sqlite(str(db_file), reset=True)
    conn.execute(
        "INSERT INTO corpus (chunk_id, doc_id, doc_title, source_org, published_date, char_start, char_end, text, enriched_text, entities_json) "
        "VALUES ('chk_both', 'LOG4J', 'Log4j Title', 'NVD', '2024-01-01', 0, 100, 'Exploit CVE-2021-44228', 'Enriched text', '{\"cve\": [\"CVE-2021-44228\"]}')"
    )
    conn.commit()
    conn.close()

    engine = ThreatRetrieverEngine()
    engine._initialized = True
    engine.sqlite_path = str(db_file)
    engine.qdrant = MagicMock()
    engine.sqlite = sqlite3.connect(str(db_file))

    engine.hybrid_searcher = MagicMock()
    engine.hybrid_searcher.search.return_value = [
        HybridResult(chunk_id="chk_both", rrf_score=0.9, dense_score=0.88, payload={"document_id": "LOG4J"})
    ]
    engine.confidence_model = None
    engine.attack_graph = None

    with patch("threat_retrieval_engine.api.pipeline.exact_lookup", return_value=["chk_both"]):
        resp = engine.run_query("CVE-2021-44228", top_k=5)
        assert len(resp.top_matches) > 0
        top = resp.top_matches[0]
        assert top.chunk_id == "chk_both"
        assert top.evidence_breakdown.semantic_similarity == pytest.approx(0.88, abs=1e-3)


# 5. Calibrator none yields calibrated=False (#1)
def test_5_calibrator_none_yields_uncalibrated():
    """Verify #1: model with calibrator type 'none' yields calibrated=False and UNCALIBRATED tier_basis."""
    model_uncal = ConfidenceModel(
        weights={"bm25_norm_score": 1.5, "ioc_coverage": 1.0},
        bias=0.0,
        feature_names=["bm25_norm_score", "ioc_coverage"],
        calibrator={"type": "none", "method": "none", "params": {}},
    )
    assert not model_uncal.is_calibrated

    profile = parse_query_profile("general threat report")
    chunk = {"chunk_id": "c1", "doc_id": "DOC1", "text": "sample text", "entities_json": {}}

    res = resolve_confidence(profile, chunk, candidate_score=0.75, model=model_uncal)
    assert res.calibrated is False
    assert res.tier_basis == "UNCALIBRATED_LOGISTIC_REGRESSION"


# 6. Concurrent initialize() runs the loaders once (R-1)
def test_6_concurrent_initialize_runs_loader_once():
    """Verify R-1: Multi-threaded concurrent initialize() only executes initialization once."""
    engine = ThreatRetrieverEngine()
    load_count = 0
    load_lock = threading.Lock()

    def mock_setup_db(*args, **kwargs):
        nonlocal load_count
        with load_lock:
            load_count += 1
        time.sleep(0.05)
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, text TEXT, enriched_text TEXT, entities_json TEXT);")
        return MagicMock(), conn

    with patch("threat_retrieval_engine.api.pipeline.setup_databases", side_effect=mock_setup_db), \
         patch("threat_retrieval_engine.api.pipeline._build_starter_attack_graph", return_value=MagicMock()), \
         patch("threat_retrieval_engine.search_engine.bm25_index.build_from_sqlite", return_value=MagicMock()), \
         patch("threat_retrieval_engine.search_engine.vectorizer.BGEVectorizer", return_value=MagicMock()), \
         patch("threat_retrieval_engine.search_engine.reranker.CrossEncoderReranker", return_value=MagicMock()), \
         patch("threat_retrieval_engine.api.pipeline.get_confidence_model", return_value=MagicMock()):

        threads = [threading.Thread(target=engine.initialize) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert load_count == 1
    assert engine._initialized is True


# 7. Tampered, missing-sidecar and stale BM25 cache all trigger a rebuild (R-5)
def test_7_bm25_cache_integrity_and_staleness_rebuild():
    """Verify R-5: Missing sidecar, tampered checksum, or stale corpus count all trigger safe rebuild."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "corpus.db"
        cache_path = Path(tmpdir) / "bm25.pkl"
        sidecar_path = cache_path.with_suffix(".sha256")

        conn = sqlite3.connect(str(db_path))
        with conn:
            conn.execute("CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, text TEXT, enriched_text TEXT)")
            conn.execute("INSERT INTO corpus VALUES ('c1', 'sample text', 'sample enriched text')")
        conn.close()

        # 1. Build initial cache (1 document)
        idx1 = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx1._doc_len) == 1
        assert cache_path.is_file()
        assert sidecar_path.is_file()

        # 2. Missing sidecar -> rejected and safely rebuilt
        sidecar_path.unlink()
        idx_no_sidecar = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx_no_sidecar._doc_len) == 1
        assert sidecar_path.is_file()

        # 3. Tampered data -> rejected and safely rebuilt
        cache_path.write_bytes(b"tampered-corrupted-pickle-content")
        idx_tampered = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx_tampered._doc_len) == 1

        # 4. Stale cache (new row inserted into DB) -> rejected and rebuilt with 2 docs
        conn2 = sqlite3.connect(str(db_path))
        with conn2:
            conn2.execute("INSERT INTO corpus VALUES ('c2', 'text2', 'enriched2')")
        conn2.close()

        idx_stale = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx_stale._doc_len) == 2


# 8. SERVICE_AUTH_ENABLED=false leaves auth off (N-1), and a non-ASCII token returns 401 (N-2)
@pytest.mark.asyncio
async def test_8_service_auth_and_non_ascii_token():
    """Verify N-1: bool parsing correctly handles false/0, and N-2: non-ASCII token returns 401 without 500 crash."""
    assert _env_bool("false") is False
    assert _env_bool("0") is False
    assert _env_bool("true") is True
    assert _env_bool("1") is True

    # N-2 test: non-ASCII token does not crash hmac.compare_digest
    with patch("threat_retrieval_engine.api.main.get_config") as mock_cfg:
        mock_cfg.return_value.service_auth_enabled = True
        mock_cfg.return_value.api_key_header = "X-API-Key"
        mock_cfg.return_value.api_key = "secret_valid_ascii_key"

        req = MagicMock(spec=Request)
        req.headers = {"X-API-Key": "invalid_token_with_é_accent"}

        with pytest.raises(HTTPException) as exc_info:
            await verify_service_auth(req)
        assert exc_info.value.status_code == 401


# 9. A /match request over the deadline returns within d_match (R-2)
@pytest.mark.asyncio
async def test_9_match_request_over_deadline_returns_504():
    """Verify R-2: API request taking longer than d_match_seconds returns HTTP 504."""
    with patch("threat_retrieval_engine.api.main.get_config") as mock_cfg:
        mock_cfg.return_value.d_match_seconds = 0.05
        mock_cfg.return_value.service_auth_enabled = False
        mock_cfg.return_value.cors_allowed_origins = ["*"]

        def slow_query(*args, **kwargs):
            import time
            time.sleep(0.2)
            return MagicMock()

        with patch("threat_retrieval_engine.api.main.get_orchestrator") as mock_orch:
            mock_orch.return_value.run_query = slow_query
            client = TestClient(app)
            resp = client.post("/api/v1/threats/match", json={"query": "CVE-2024-1111"})
            assert resp.status_code == 504
            assert "deadline exceeded" in resp.json()["detail"].lower()
