import os
import tempfile
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from fastapi import Request
from fastapi.exceptions import HTTPException

from threat_retrieval_engine.config import _env_bool, get_config
from threat_retrieval_engine.api.main import verify_service_auth
from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine
from threat_retrieval_engine.search_engine.bm25_index import build_from_sqlite, BM25Index


def test_env_bool_parsing():
    """Verify N-1: _env_bool correctly parses various truthy and falsy strings."""
    assert _env_bool("true") is True
    assert _env_bool("TRUE") is True
    assert _env_bool("1") is True
    assert _env_bool("yes") is True
    assert _env_bool("on") is True
    assert _env_bool(True) is True

    assert _env_bool("false") is False
    assert _env_bool("FALSE") is False
    assert _env_bool("0") is False
    assert _env_bool("no") is False
    assert _env_bool("off") is False
    assert _env_bool("") is False
    assert _env_bool(False) is False
    assert _env_bool(None, default=False) is False
    assert _env_bool(None, default=True) is True


@pytest.mark.asyncio
async def test_non_ascii_token_compare():
    """Verify N-2: hmac comparison with non-ASCII token doesn't crash with TypeError (returns 401)."""
    with patch("threat_retrieval_engine.api.main.get_config") as mock_cfg:
        mock_cfg.return_value.service_auth_enabled = True
        mock_cfg.return_value.api_key_header = "X-API-Key"
        mock_cfg.return_value.api_key = "secret_ascii_key"

        req = MagicMock(spec=Request)
        req.headers = {"X-API-Key": "vulnerable_token_with_é_accent"}

        with pytest.raises(HTTPException) as exc_info:
            await verify_service_auth(req)
        assert exc_info.value.status_code == 401


def test_concurrent_initialize_race():
    """Verify R-1: Multi-threaded concurrent initialize() only executes initialization once."""
    engine = ThreatRetrieverEngine()
    load_count = 0

    def mock_setup_db(*args, **kwargs):
        nonlocal load_count
        import time
        time.sleep(0.05)  # simulate slow DB/model loading
        load_count += 1
        return MagicMock(), MagicMock()

    with patch("threat_retrieval_engine.api.pipeline.setup_databases", side_effect=mock_setup_db), \
         patch("threat_retrieval_engine.api.pipeline._build_starter_attack_graph", return_value=MagicMock()), \
         patch("threat_retrieval_engine.search_engine.bm25_index.build_from_sqlite", return_value=MagicMock()):

        threads = []
        for _ in range(8):
            t = threading.Thread(target=engine.initialize)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    assert load_count == 1
    assert engine._initialized is True


def test_bm25_missing_sidecar_and_stale_cache():
    """Verify R-5: Missing sidecar triggers safe rebuild; stale doc count triggers rebuild."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "corpus.db"
        cache_path = Path(tmpdir) / "bm25.pkl"

        conn = sqlite3.connect(str(db_path))
        with conn:
            conn.execute("CREATE TABLE corpus (chunk_id TEXT PRIMARY KEY, text TEXT, enriched_text TEXT)")
            conn.execute("INSERT INTO corpus VALUES ('c1', 'sample text', 'sample enriched text')")
        conn.close()

        # Build initial cache (1 document)
        idx1 = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx1._doc_len) == 1
        assert cache_path.is_file()
        sha_path = cache_path.with_suffix(".sha256")
        assert sha_path.is_file()

        # Case 1: Missing sidecar file -> must reject and rebuild
        sha_path.unlink()
        assert not sha_path.is_file()
        idx_rebuilt = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx_rebuilt._doc_len) == 1
        assert sha_path.is_file()

        # Case 2: Stale cache (new documents inserted into corpus, cached doc count is 1, corpus now has 2)
        conn = sqlite3.connect(str(db_path))
        with conn:
            conn.execute("INSERT INTO corpus VALUES ('c2', 'second text', 'second enriched text')")
        conn.close()

        # Loading without force_rebuild should detect staleness (cached=1, corpus=2) and rebuild
        idx_stale_detected = build_from_sqlite(db_path, cache_path=cache_path)
        assert len(idx_stale_detected._doc_len) == 2
        sidecar_lines = sha_path.read_text(encoding="utf-8").strip().splitlines()
        assert int(sidecar_lines[1]) == 2
