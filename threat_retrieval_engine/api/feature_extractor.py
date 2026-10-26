"""
threat_retrieval_engine/api/feature_extractor.py
================================================
Single source of truth for feature extraction shared by training and serving
(guarantees train-serve parity across Phase 2-4, R1).

CRITICAL ANTI-LEAKAGE CONSTRAINT:
Layer 2 features MUST NOT inspect or use `doc_id` or check exact string
equality on `doc_id`. Feature schema version: v1.0.0.
"""

from __future__ import annotations

import json
import math
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threat_retrieval_engine.api.confidence import QueryProfile

try:
    from threat_retrieval_engine.indicators import (
        COMMON_ACTORS as _COMMON_ACTORS,
        COMMON_MALWARE as _COMMON_MALWARE,
        CVE_PATTERN as _CVE_PATTERN,
        IPV4_PATTERN as _IPV4_PATTERN,
        MD5_PATTERN as _MD5_PATTERN,
        MITRE_PATTERN as _MITRE_PATTERN,
        SHA256_PATTERN as _SHA256_PATTERN,
        TOOL_TO_TECH as _TOOL_TO_TECH,
    )
except ImportError:
    from indicators import (
        COMMON_ACTORS as _COMMON_ACTORS,
        COMMON_MALWARE as _COMMON_MALWARE,
        CVE_PATTERN as _CVE_PATTERN,
        IPV4_PATTERN as _IPV4_PATTERN,
        MD5_PATTERN as _MD5_PATTERN,
        MITRE_PATTERN as _MITRE_PATTERN,
        SHA256_PATTERN as _SHA256_PATTERN,
        TOOL_TO_TECH as _TOOL_TO_TECH,
    )

FEATURE_SCHEMA_VERSION = "v1.0.0"

FEATURE_NAMES: list[str] = [
    "has_cve",
    "has_ioc",
    "has_ttp",
    "cve_coverage",
    "ioc_coverage",
    "ttp_coverage",
    "reranker_score",
    "bm25_norm_score",
    "inter_cve_cov",
    "inter_ioc_cov",
    "inter_ttp_cov",
    "inter_reranker",
]


def _extract_chunk_entities(candidate_chunk: dict[str, Any]) -> dict[str, Any]:
    """Safely extracts parsed entities dict from candidate chunk without touching doc_id."""
    meta = candidate_chunk.get("metadata")
    if not isinstance(meta, dict):
        meta = {}

    ent = candidate_chunk.get("entities") or candidate_chunk.get("entities_json")
    if not ent:
        ent = meta.get("entities") or meta.get("entities_json")

    if isinstance(ent, str):
        try:
            return json.loads(ent)
        except Exception:
            return {}
    elif isinstance(ent, dict):
        return ent
    return {}


def _extract_chunk_cves(ent: dict[str, Any], text: str) -> set[str]:
    cves: set[str] = set()
    raw = ent.get("cves")
    if isinstance(raw, (list, tuple, set)):
        cves.update(str(c).upper() for c in raw if c)
    if text:
        cves.update(m.upper() for m in _CVE_PATTERN.findall(text))
    return cves


def _extract_chunk_iocs(ent: dict[str, Any], text: str) -> set[str]:
    iocs: set[str] = set()
    iocs_data = ent.get("iocs")
    if isinstance(iocs_data, dict):
        for k in ("ipv4", "sha256", "md5", "ipv6", "domains", "urls"):
            vals = iocs_data.get(k)
            if isinstance(vals, (list, tuple, set)):
                iocs.update(str(v).lower() for v in vals if v)
    if text:
        iocs.update(m.lower() for m in _IPV4_PATTERN.findall(text))
        iocs.update(m.lower() for m in _MD5_PATTERN.findall(text))
        iocs.update(m.lower() for m in _SHA256_PATTERN.findall(text))
    return iocs


def _extract_chunk_ttps(ent: dict[str, Any], text: str) -> set[str]:
    ttps: set[str] = set()
    raw_ttps = ent.get("mitre_ttps")
    if isinstance(raw_ttps, (list, tuple, set)):
        ttps.update(str(t).upper() for t in raw_ttps if t)
    if text:
        ttps.update(m.upper() for m in _MITRE_PATTERN.findall(text))

    t_lower = text.lower() if text else ""
    chunk_mal: set[str] = set()
    raw_mal = ent.get("malware_families")
    if isinstance(raw_mal, (list, tuple, set)):
        chunk_mal.update(str(m).lower() for m in raw_mal if m)
    for m in _COMMON_MALWARE:
        if m in t_lower:
            chunk_mal.add(m)

    for tool_name, techs in _TOOL_TO_TECH.items():
        if tool_name in t_lower or any(m == tool_name for m in chunk_mal):
            ttps.update(techs)

    raw_actors = ent.get("threat_actors")
    if isinstance(raw_actors, (list, tuple, set)):
        ttps.update(str(a).lower() for a in raw_actors if a)
    for a in _COMMON_ACTORS:
        if a in t_lower:
            ttps.add(a)

    ttps.update(chunk_mal)
    return ttps


def _extract_reranker_score(candidate_chunk: dict[str, Any]) -> float:
    """
    Extract continuous cross-encoder semantic score (R1, N1).
    Explicitly decoupled from dense_score to prevent train-serve divergence.
    """
    # 1. Explicit logit key
    for logit_key in ("reranker_logit", "rerank_logit", "cross_encoder_logit"):
        if logit_key in candidate_chunk and candidate_chunk[logit_key] is not None:
            try:
                s = float(candidate_chunk[logit_key])
                s = max(-50.0, min(50.0, s))
                return 1.0 / (1.0 + math.exp(-s))
            except (ValueError, TypeError):
                pass

    # 2. Continuous reranker score or probability (dense_score is NOT a fallback here)
    for score_key in ("reranker_score", "rerank_score", "cross_encoder_score", "rerank_prob"):
        if score_key in candidate_chunk and candidate_chunk[score_key] is not None:
            try:
                val = float(candidate_chunk[score_key])
                if candidate_chunk.get("is_logit", False) or val < 0.0 or val > 1.0:
                    val = max(-50.0, min(50.0, val))
                    return 1.0 / (1.0 + math.exp(-val))
                return max(0.0, min(1.0, val))
            except (ValueError, TypeError):
                pass

    return 0.0


def _extract_bm25_norm_score(candidate_chunk: dict[str, Any]) -> float:
    """
    Extract normalized BM25 lexical alignment score in [0.0, 1.0].
    CRITICAL (R1): Does NOT fall back to rrf_score to prevent Layer 2 probability collapse.
    """
    for key in ("bm25_norm_score", "bm25_norm", "lexical_norm_score"):
        if key in candidate_chunk and candidate_chunk[key] is not None:
            try:
                val = float(candidate_chunk[key])
                return max(0.0, min(1.0, val))
            except (ValueError, TypeError):
                pass
    return 0.0


def extract_features(query_profile: Any, candidate_chunk: dict[str, Any]) -> dict[str, float]:
    """
    Extracts the official 12-feature schema (v1.0.0) for a (query, candidate) pair.
    Single source of truth shared across training and runtime inference.

    CRITICAL: Never inspects doc_id.
    """
    meta = candidate_chunk.get("metadata")
    if not isinstance(meta, dict):
        meta = {}

    text = candidate_chunk.get("text") or meta.get("text") or meta.get("enriched_text") or ""
    ent = _extract_chunk_entities(candidate_chunk)

    # 1. Query Sets & Presence Flags
    q_cves = {str(c).upper() for c in getattr(query_profile, "cves", ())}
    has_cve = 1.0 if len(q_cves) > 0 else 0.0

    q_ips = {str(ip).lower() for ip in getattr(query_profile, "ips", ())}
    q_hashes = {str(h).lower() for h in getattr(query_profile, "hashes", ())}
    q_iocs = q_ips | q_hashes
    has_ioc = 1.0 if len(q_iocs) > 0 else 0.0

    q_ttps_techniques = {str(t).upper() for t in getattr(query_profile, "mitre_techniques", ())}
    q_ttps_actors = {str(a).lower() for a in getattr(query_profile, "threat_actors", ())}
    q_ttps_malware = {str(m).lower() for m in getattr(query_profile, "malware", ())}
    q_ttps = q_ttps_techniques | q_ttps_actors | q_ttps_malware
    has_ttp = 1.0 if len(q_ttps) > 0 else 0.0

    # 2. Document Sets
    d_cves = _extract_chunk_cves(ent, text)
    d_iocs = _extract_chunk_iocs(ent, text)
    d_ttps = _extract_chunk_ttps(ent, text)

    # If candidate chunk has precomputed attribution, fold it in safely
    attr = candidate_chunk.get("attribution")
    if isinstance(attr, dict):
        for c in attr.get("matching_cves") or []:
            d_cves.add(str(c).upper())
        for i in attr.get("matching_iocs") or []:
            d_iocs.add(str(i).lower())
        for t in attr.get("matching_mitre_techniques") or []:
            d_ttps.add(str(t).upper())
        for m in attr.get("shared_malware") or []:
            d_ttps.add(str(m).lower())

    # 3. Continuous Channel Coverages
    cve_coverage = (len(q_cves & d_cves) / len(q_cves)) if has_cve > 0.0 else 0.0
    ioc_coverage = (len(q_iocs & d_iocs) / len(q_iocs)) if has_ioc > 0.0 else 0.0
    ttp_coverage = (len(q_ttps & d_ttps) / len(q_ttps)) if has_ttp > 0.0 else 0.0

    # 4. Continuous Similarity Scores
    reranker_score = _extract_reranker_score(candidate_chunk)
    bm25_norm_score = _extract_bm25_norm_score(candidate_chunk)

    # Parity fallback matching training dataset token containment formula: |Q ∩ D| / |Q| (R1)
    if bm25_norm_score == 0.0 and text:
        raw_q = getattr(query_profile, "raw_query", "")
        if not raw_q:
            tokens_list = (
                list(getattr(query_profile, "cves", ()))
                + list(getattr(query_profile, "ips", ()))
                + list(getattr(query_profile, "hashes", ()))
                + list(getattr(query_profile, "mitre_techniques", ()))
                + list(getattr(query_profile, "threat_actors", ()))
                + list(getattr(query_profile, "malware", ()))
            )
            raw_q = " ".join(tokens_list)
        if raw_q:
            q_toks = {t.lower() for t in re.findall(r"\b\w{2,}\b", raw_q)}
            d_toks = {t.lower() for t in re.findall(r"\b\w{2,}\b", text)}
            if q_toks:
                bm25_norm_score = len(q_toks & d_toks) / len(q_toks)

    # 5. Interaction Terms
    inter_cve_cov = has_cve * cve_coverage
    inter_ioc_cov = has_ioc * ioc_coverage
    inter_ttp_cov = has_ttp * ttp_coverage
    inter_reranker = has_cve * reranker_score

    return {
        "has_cve": has_cve,
        "has_ioc": has_ioc,
        "has_ttp": has_ttp,
        "cve_coverage": round(cve_coverage, 4),
        "ioc_coverage": round(ioc_coverage, 4),
        "ttp_coverage": round(ttp_coverage, 4),
        "reranker_score": round(reranker_score, 4),
        "bm25_norm_score": round(bm25_norm_score, 4),
        "inter_cve_cov": round(inter_cve_cov, 4),
        "inter_ioc_cov": round(inter_ioc_cov, 4),
        "inter_ttp_cov": round(inter_ttp_cov, 4),
        "inter_reranker": round(inter_reranker, 4),
    }


class FeatureExtractor:
    """
    Centralized feature extractor for train-serve parity.
    Provides static and instance access to extract_features.
    """
    SCHEMA_VERSION = FEATURE_SCHEMA_VERSION
    FEATURE_NAMES = FEATURE_NAMES

    @staticmethod
    def extract_features(query_profile: Any, candidate_chunk: dict[str, Any]) -> dict[str, float]:
        return extract_features(query_profile, candidate_chunk)
