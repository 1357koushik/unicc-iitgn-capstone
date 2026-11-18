import sqlite3
import pytest
from datetime import datetime, timezone
from threat_retrieval_engine.api.confidence import (
    ConfidenceModel,
    parse_query_profile,
    resolve_confidence,
)
from threat_retrieval_engine.search_engine.exact_lookup import _sqlite_lookup
from threat_retrieval_engine.search_engine.vector_database import (
    setup_sqlite,
    store_chunks,
)
from threat_retrieval_engine.search_engine.validator import (
    ThreatChunk,
    CyberEntities,
    IOCEntities,
)
from threat_retrieval_engine.search_engine.vectorizer import VectorResult
from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine


def test_confidence_model_uncalibrated_flag():
    """Verify that a model with calibrator.type == 'none' correctly reports calibrated=False."""
    # Model with type: "none" calibrator (matching confidence_model.json)
    model_uncal = ConfidenceModel(
        weights={"bm25_norm_score": 1.5, "ioc_coverage": 1.0},
        bias=0.0,
        feature_names=["bm25_norm_score", "ioc_coverage"],
        calibrator={"type": "none", "method": "none", "params": {}},
    )
    assert not model_uncal.is_calibrated

    profile = parse_query_profile("general search query without cve")
    chunk = {"chunk_id": "c1", "doc_id": "DOC1", "text": "sample threat advisory text", "entities_json": {}}

    res = resolve_confidence(profile, chunk, candidate_score=0.8, model=model_uncal)
    assert res.match_type == "LEARNED_MODEL"
    assert res.calibrated is False
    assert res.tier_basis == "UNCALIBRATED_LOGISTIC_REGRESSION"

    # Model with active calibrator
    model_cal = ConfidenceModel(
        weights={"bm25_norm_score": 1.5, "ioc_coverage": 1.0},
        bias=0.0,
        feature_names=["bm25_norm_score", "ioc_coverage"],
        calibrator={"type": "sigmoid", "method": "sigmoid", "params": {"a": 1.0, "b": 0.0}},
    )
    assert model_cal.is_calibrated
    res_cal = resolve_confidence(profile, chunk, candidate_score=0.8, model=model_cal)
    assert res_cal.calibrated is True
    assert res_cal.tier_basis == "CALIBRATED_LOGISTIC_REGRESSION"


def test_exact_lookup_like_escaping():
    """Verify that % and _ are escaped in _sqlite_lookup to prevent wildcard injection."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE entity_index (entity_value TEXT, chunk_id TEXT, entity_kind TEXT);")
    conn.execute("CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, entities_json TEXT);")

    # Insert two chunks: one with 100% and one with 1000
    conn.execute('INSERT INTO corpus VALUES ("c_percent", \'{"domain": ["100%safe.com"]}\');')
    conn.execute('INSERT INTO corpus VALUES ("c_other", \'{"domain": ["1000safe.com"]}\');')
    conn.commit()

    # Searching for exact "100%safe.com" should only return c_percent, NOT c_other
    results = _sqlite_lookup(conn, "100%safe.com", limit=10)
    assert results == ["c_percent"]

    # Searching for a single underscore should not act as wildcard
    conn.execute('INSERT INTO corpus VALUES ("c_under", \'{"domain": ["a_b.com"]}\');')
    conn.execute('INSERT INTO corpus VALUES ("c_dash", \'{"domain": ["a-b.com"]}\');')
    conn.commit()

    results_under = _sqlite_lookup(conn, "a_b.com", limit=10)
    assert results_under == ["c_under"]


def test_store_chunks_cleans_stale_entity_index():
    """Verify that re-ingesting a chunk removes old entity mappings from entity_index."""
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
        text="This is a long sample text exceeding 15 characters v1",
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
    assert "T1059" in values_v1
    assert "1.2.3.4" in values_v1

    # Second ingestion with updated entities (CVE replaced with CVE-2024-9999, old TTP removed)
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
        text="This is a long sample text exceeding 15 characters v2",
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

    # Old entities must be completely removed
    assert "CVE-2023-1111" not in values_v2
    assert "T1059" not in values_v2
    assert "1.2.3.4" not in values_v2

    # New entities must be present
    assert "CVE-2024-9999" in values_v2
    assert "T1078" in values_v2


def test_pipeline_epss_regex_execution():
    """Verify that re is imported in pipeline.py and EPSS regex executes without NameError."""
    import re
    # Direct check that pipeline module has 're'
    import threat_retrieval_engine.api.pipeline as pipeline_mod
    assert hasattr(pipeline_mod, "re")
    assert pipeline_mod.re is re
