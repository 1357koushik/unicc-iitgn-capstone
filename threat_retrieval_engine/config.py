"""
threat_retrieval_engine/config.py
=================================
Central authoritative configuration loader (R43).
Loads `config/retrieval_config.yaml` with environment variable overrides and
anchors all filesystem paths to the repository root (R31, R38).
Enforces the V2 deadline contract invariant: T_client_match > D_match.
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any
import yaml

logger = logging.getLogger(__name__)

# Repository root (parent of threat_retrieval_engine)
REPO_ROOT = Path(__file__).resolve().parent.parent


def _data_dir_override() -> Path | None:
    """``TRE_DATA_DIR``: base directory that holds the data (outside the checkout)."""
    raw = os.environ.get("TRE_DATA_DIR", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


def _resolve_path(rel_or_abs: str | Path) -> Path:
    """Resolve a configured path.

    Absolute paths are kept. Relative paths are anchored to the repository root,
    unless ``TRE_DATA_DIR`` is set: then ``./data/<x>`` resolves to
    ``$TRE_DATA_DIR/<x>`` (the directory *is* the ``data`` folder, as in the
    existing server layout ``~/data/{sqlite,qdrant_storage}``) and any other
    relative path resolves under ``$TRE_DATA_DIR``.
    """
    p = Path(rel_or_abs)
    if p.is_absolute():
        return p
    data_dir = _data_dir_override()
    if data_dir is not None:
        parts = p.parts
        if parts and parts[0] == "data":
            parts = parts[1:]
        return data_dir.joinpath(*parts).resolve()
    return (REPO_ROOT / p).resolve()


def _env_bool(val: Any, default: bool = False) -> bool:
    """Robust boolean environment variable parser handling true/false/0/1."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if s in {"0", "false", "no", "off", "disable", "disabled", ""}:
        return False
    return default


class RetrievalConfig:
    REPO_ROOT = REPO_ROOT

    def __init__(self, config_dict: dict[str, Any] | None = None) -> None:
        cfg = config_dict or {}
        self.repo_root = REPO_ROOT
        self.REPO_ROOT = REPO_ROOT
        self.config_path: Path | None = None  # set by load_config()
        self.data_dir: Path = _data_dir_override() or (REPO_ROOT / "data")

        # Storage paths
        self.qdrant_storage_path = _resolve_path(cfg.get("qdrant_storage_path", "./data/qdrant_storage"))
        self.sqlite_db_path = _resolve_path(cfg.get("sqlite_db_path", "./data/sqlite/corpus_store.db"))
        self.bm25_cache_file = _resolve_path(cfg.get("bm25_cache_file", self.sqlite_db_path.parent / "bm25_index.pkl"))
        self.quarantine_path = _resolve_path(cfg.get("quarantine_path", "./data/quarantined"))

        # Qdrant HNSW
        self.hnsw_m = int(cfg.get("hnsw_m", 32))
        self.hnsw_ef_construct = int(cfg.get("hnsw_ef_construct", 200))
        self.hnsw_ef_search = int(cfg.get("hnsw_ef_search", 64))

        # Quantization
        self.quantization_type = str(cfg.get("quantization_type", "Int8"))
        self.quantization_quantile = float(cfg.get("quantization_quantile", 0.99))
        self.quantization_always_ram = bool(cfg.get("quantization_always_ram", True))

        # Deduplication
        self.minhash_num_permutations = int(cfg.get("minhash_num_permutations", 128))
        self.minhash_similarity_threshold = float(cfg.get("minhash_similarity_threshold", 0.90))
        self.minhash_shingle_size = int(cfg.get("minhash_shingle_size", 3))

        # Hybrid retrieval
        self.bm25_k1 = float(cfg.get("bm25_k1", 1.5))
        self.bm25_b = float(cfg.get("bm25_b", 0.75))
        self.bm25_text_column = str(cfg.get("bm25_text_column", "enriched_text"))
        self.rrf_k = int(cfg.get("rrf_k", 60))
        self.retrieval_candidate_k = int(cfg.get("retrieval_candidate_k", 50))
        self.retrieval_top_k = int(cfg.get("retrieval_top_k", 10))
        self.default_alpha = float(cfg.get("default_alpha", 0.5))

        # Reranker
        self.reranker_model = str(cfg.get("reranker_model", "BAAI/bge-reranker-v2-m3"))
        self.reranker_use_fp16 = bool(cfg.get("reranker_use_fp16", True))
        self.reranker_top_k = int(cfg.get("reranker_top_k", 5))

        # ATT&CK graph and entity names: C9 build root (holds LATEST); $TRE_ATTACK_DIR overrides at runtime
        self.attack_build_dir = _resolve_path(cfg.get("attack_build_dir", "./data/attack"))

        # Deadlines (V2)
        deadlines = cfg.get("deadlines", {})
        self.d_match_seconds = float(os.getenv("D_MATCH_SECONDS", deadlines.get("d_match_seconds", 15.0)))
        self.t_client_match_seconds = float(os.getenv("T_CLIENT_MATCH_SECONDS", deadlines.get("t_client_match_seconds", 20.0)))
        self.d_poc_seconds = float(os.getenv("D_POC_SECONDS", deadlines.get("d_poc_seconds", 20.0)))
        self.client_margin_seconds = float(deadlines.get("client_margin_seconds", 5.0))

        # Enforce V2 Invariant: T_client_match > D_match
        if self.t_client_match_seconds <= self.d_match_seconds:
            self.t_client_match_seconds = self.d_match_seconds + self.client_margin_seconds

        # Concurrency: dedicated bounded pool for /match (V-4)
        self.match_max_workers = int(cfg.get("match_max_workers", 4))

        # Confidence model auditing (V-1). ``warn`` keeps serving an unverified
        # artifact but reports calibrated=False; ``enforce`` refuses to serve it.
        self.confidence_model_audit_enforce = _env_bool(
            os.getenv("CONFIDENCE_MODEL_AUDIT_ENFORCE"),
            default=bool(cfg.get("confidence_model_audit_enforce", False)),
        )

        # BM25 cache integrity (V-5): HMAC key is never stored beside the cache.
        self.bm25_cache_hmac_key = os.getenv("BM25_CACHE_HMAC_KEY", "")
        self.bm25_cache_key_file = _resolve_path(
            cfg.get("bm25_cache_key_file", str(Path.home() / ".config" / "unicc-team2" / "bm25_cache.key"))
        )

        # Security
        sec = cfg.get("security", {})
        self.cors_allowed_origins = list(sec.get("cors_allowed_origins", [
            "http://localhost:3000", "http://127.0.0.1:3000",
            "http://localhost:8000", "http://127.0.0.1:8000",
            "http://localhost:8080", "http://127.0.0.1:8080"
        ]))
        self.service_auth_enabled = _env_bool(
            os.getenv("SERVICE_AUTH_ENABLED"),
            default=bool(sec.get("service_auth_enabled", False)),
        )
        self.api_key = os.getenv("RETRIEVAL_API_KEY", "")
        self.api_key_header = str(sec.get("api_key_header", "X-API-Key"))

        # PoC Intelligence
        poc = cfg.get("poc_intelligence", {})
        self.poc_enabled = bool(poc.get("enabled", True))
        self.poc_cache_ttl_seconds = int(poc.get("cache_ttl_seconds", 21600))
        self.poc_kev_cache_ttl_seconds = int(poc.get("kev_cache_ttl_seconds", 3600))
        self.poc_max_results_per_source = int(poc.get("max_results_per_source", 10))
        self.poc_max_total_results = int(poc.get("max_total_results", 30))
        self.poc_min_confidence_threshold = float(poc.get("min_confidence_threshold", 0.0))
        self.poc_request_timeout_seconds = float(poc.get("request_timeout_seconds", 10.0))
        self.x_allow_paid_requests = _env_bool(
            os.getenv("X_ALLOW_PAID_REQUESTS"),
            default=bool(poc.get("x_allow_paid_requests", False)),
        )
        self.poc_mastodon_instances = list(poc.get("mastodon_instances", [
            "infosec.exchange", "defcon.social", "chaos.social", "ioc.exchange", "hachyderm.io"
        ]))
        self.poc_sources = poc.get("sources", {})


_CONFIG_CACHE: RetrievalConfig | None = None


def load_config(config_path: str | Path | None = None) -> RetrievalConfig:
    """Load configuration from YAML file or return cached singleton."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None and config_path is None:
        return _CONFIG_CACHE

    if config_path:
        target_path = _resolve_path(config_path)
    elif os.environ.get("TRE_CONFIG_PATH", "").strip():
        target_path = Path(os.environ["TRE_CONFIG_PATH"]).expanduser().resolve()
    else:
        target_path = REPO_ROOT / "config" / "retrieval_config.yaml"
    cfg_data: dict[str, Any] = {}
    if target_path.is_file():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                cfg_data = yaml.safe_load(f) or {}
            logger.info("Loaded configuration from %s", target_path)
        except Exception as exc:
            logger.warning("Failed to parse config file %s: %s; using defaults.", target_path, exc)
    else:
        logger.info("Config file %s not found; using defaults.", target_path)

    loaded = RetrievalConfig(cfg_data)
    loaded.config_path = target_path
    if config_path is None:
        _CONFIG_CACHE = loaded
    return loaded


def get_config() -> RetrievalConfig:
    return load_config()
