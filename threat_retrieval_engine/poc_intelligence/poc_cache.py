from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

try:
    from threat_retrieval_engine.api.schemas import PoCFindResponse
except ImportError:
    from api.schemas import PoCFindResponse

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("./data/sqlite/corpus_store.db")
DEFAULT_NORMALIZED_CVES_DIR = Path("./knowledge_foundation/normalized_cves")


class PoCCache:
    """SQLite-backed cache for PoC search results with KEV-aware TTL management."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        normalized_cves_dir: str | Path | None = None,
        default_ttl_seconds: int = 21600,  # 6 hours
        kev_ttl_seconds: int = 3600,        # 1 hour
    ) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.normalized_cves_dir = Path(normalized_cves_dir) if normalized_cves_dir else DEFAULT_NORMALIZED_CVES_DIR
        self.default_ttl_seconds = default_ttl_seconds
        self.kev_ttl_seconds = kev_ttl_seconds
        self._ensure_table()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_table(self) -> None:
        conn = None
        try:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS poc_cache (
                        cve_id TEXT PRIMARY KEY,
                        response_json TEXT NOT NULL,
                        cached_at INTEGER NOT NULL,
                        ttl_seconds INTEGER NOT NULL
                    )
                    """
                )
        except Exception as exc:
            logger.warning("Could not initialize SQLite poc_cache table: %s", exc)
        finally:
            if conn:
                conn.close()

    def is_cisa_kev_listed(self, cve_id: str) -> bool:
        """Check if target CVE is listed in local normalized CISA KEV records."""
        cve_clean = cve_id.strip().upper()
        json_path = self.normalized_cves_dir / f"{cve_clean}_normalized.json"
        if json_path.is_file():
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data.get("known_exploited"):
                        return True
                    if data.get("cisa_kev", {}).get("listed"):
                        return True
            except Exception:
                pass
        return False

    def determine_ttl(self, cve_id: str) -> int:
        """Assign dynamic TTL: 1h for actively exploited CISA KEV vulnerabilities, 6h otherwise."""
        if self.is_cisa_kev_listed(cve_id):
            return self.kev_ttl_seconds
        return self.default_ttl_seconds

    def get(self, cve_id: str) -> PoCFindResponse | None:
        """Retrieve cached PoC response if present and unexpired."""
        cve_clean = cve_id.strip().upper()
        now = int(time.time())
        conn = None
        try:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT response_json, cached_at, ttl_seconds FROM poc_cache WHERE cve_id = ?",
                (cve_clean,),
            ).fetchone()

            if row is None:
                return None

            cached_at = row["cached_at"]
            ttl = row["ttl_seconds"]
            if now - cached_at > ttl:
                # Expired entry
                return None

            data = json.loads(row["response_json"])
            resp = PoCFindResponse(**data)
            resp.cached = True
            return resp
        except Exception as exc:
            logger.warning("Error reading from poc_cache for %s: %s", cve_clean, exc)
            return None
        finally:
            if conn:
                conn.close()

    def set(
        self,
        cve_id: str,
        response: PoCFindResponse,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store PoC response into SQLite cache."""
        cve_clean = cve_id.strip().upper()
        ttl = ttl_seconds if ttl_seconds is not None else self.determine_ttl(cve_clean)
        now = int(time.time())
        payload = response.model_dump()
        payload["cached"] = True

        conn = None
        try:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    INSERT INTO poc_cache (cve_id, response_json, cached_at, ttl_seconds)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        response_json = excluded.response_json,
                        cached_at = excluded.cached_at,
                        ttl_seconds = excluded.ttl_seconds
                    """,
                    (cve_clean, json.dumps(payload), now, ttl),
                )
        except Exception as exc:
            logger.warning("Error writing to poc_cache for %s: %s", cve_clean, exc)
        finally:
            if conn:
                conn.close()

