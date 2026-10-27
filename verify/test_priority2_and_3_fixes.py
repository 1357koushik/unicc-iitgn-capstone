import hashlib
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate
from threat_retrieval_engine.poc_intelligence.poc_validator import PoCValidator
from threat_retrieval_engine.search_engine.bm25_index import build_from_sqlite, BM25Index
from threat_retrieval_engine.search_engine.hybrid_search import HybridSearcher
from threat_retrieval_engine.poc_intelligence.sources.bluesky_scraper import _sanitize_text as bsky_sanitize
from threat_retrieval_engine.poc_intelligence.sources.mastodon_scraper import _sanitize_text as mastodon_sanitize


def test_archived_repo_penalty():
    """Verify that archived repos receive a -0.10 penalty and archived_repository warning."""
    validator = PoCValidator()

    active_cand = RawCandidate(
        url="https://github.com/org/repo-active",
        title="CVE-2024-3400 exploit",
        source="github",
        author="org",
        stars=10,
        language="Python",
        raw_metadata={"archived": False},
    )
    archived_cand = RawCandidate(
        url="https://github.com/org/repo-archived",
        title="CVE-2024-3400 exploit",
        source="github",
        author="org",
        stars=10,
        language="Python",
        raw_metadata={"archived": True},
    )

    res_active = validator.validate_candidate(active_cand, "CVE-2024-3400")
    res_archived = validator.validate_candidate(archived_cand, "CVE-2024-3400")

    assert res_archived.confidence_score < res_active.confidence_score
    assert "archived_repository" in res_archived.warning_flags
    assert "archived_repository" not in res_active.warning_flags


def test_social_media_sanitization():
    """Verify that null bytes, control characters, and excess length are stripped."""
    dirty_text = "Exploit \x00payload\x08 test\x1f for CVE-2024-1234 " + ("A" * 3000)
    cleaned_bsky = bsky_sanitize(dirty_text, max_chars=2000)
    assert "\x00" not in cleaned_bsky
    assert "\x08" not in cleaned_bsky
    assert len(cleaned_bsky) <= 2000

    cleaned_mastodon = mastodon_sanitize(dirty_text, max_chars=2000)
    assert "\x00" not in cleaned_mastodon
    assert len(cleaned_mastodon) <= 2000


def test_bm25_cache_sha256_tamper_detection():
    """Verify that BM25 index produces a .sha256 sidecar and rejects tampered caches."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "corpus.db"
        cache_path = Path(tmpdir) / "bm25.pkl"

        conn = sqlite3.connect(str(db_path))
        with conn:
            conn.execute("CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, text TEXT, enriched_text TEXT)")
            conn.execute("INSERT INTO corpus VALUES ('c1', 'sample text', 'sample enriched text')")
        conn.close()

        # Build and cache
        idx1 = build_from_sqlite(db_path, cache_path=cache_path)
        assert cache_path.is_file()
        sha_path = cache_path.with_suffix(".sha256")
        assert sha_path.is_file()

        expected_hash = hashlib.sha256(cache_path.read_bytes()).hexdigest()
        sidecar_lines = sha_path.read_text(encoding="utf-8").strip().splitlines()
        assert sidecar_lines[0] == expected_hash
        assert int(sidecar_lines[1]) == 1

        # Tamper with the pickle cache
        cache_path.write_bytes(b"tampered data")

        # Loading tampered cache should fail verification and safely rebuild
        idx2 = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx2._doc_len) == 1


def test_hnsw_ef_search_configured():
    """Verify HybridSearcher initializes with hnsw_ef_search."""
    searcher = HybridSearcher(
        qdrant=MagicMock(),
        sqlite=MagicMock(),
        bm25=MagicMock(),
        query_encoder=MagicMock(),
        hnsw_ef_search=128,
    )
    assert searcher.hnsw_ef_search == 128
