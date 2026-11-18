"""
threat_retrieval_engine/api/confidence.py
=========================================
Runtime confidence resolution module for Phase 2 of the UNICC x IITGN Capstone.

Implements the Two-Layer Confidence Architecture:
  - Layer 1: Deterministic Identifier Match (Exact Primary CVE ID / Hash Match) -> EXACT
  - Layer 2: Learned Calibrated Logistic Regression Model (with Platt/Isotonic scaling)
             or Option B Presence-Renormalized Behavioral Heuristic (M1).
  - Safe Degraded Mode: Capped at STRONG, uncalibrated M1 fallback (R20).
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threat_retrieval_engine.api.feature_extractor import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract_features,
)

from threat_retrieval_engine.attack.runtime import entity_names
from threat_retrieval_engine.indicators import (
    CVE_PATTERN as _CVE_PATTERN,
    IPV4_PATTERN as _IPV4_PATTERN,
    MD5_PATTERN as _MD5_PATTERN,
    MITRE_PATTERN as _MITRE_PATTERN,
    SHA256_PATTERN as _SHA256_PATTERN,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class QueryProfile:
    """
    Immutable structured query representation parsed via standard regex.
    CVEs are normalized uppercase de-duplicated.
    IPs and hashes are normalized lowercase.
    MITRE techniques are normalized uppercase.
    """
    cves: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    threat_actors: tuple[str, ...] = ()
    malware: tuple[str, ...] = ()
    raw_query: str = ""

    @property
    def has_cve(self) -> bool:
        return len(self.cves) > 0

    @property
    def has_ioc(self) -> bool:
        return len(self.ips) > 0 or len(self.hashes) > 0

    @property
    def has_ttp(self) -> bool:
        return len(self.mitre_techniques) > 0 or len(self.threat_actors) > 0 or len(self.malware) > 0

    @classmethod
    def from_text(cls, query: str) -> QueryProfile:
        return parse_query_profile(query)


def parse_query_profile(query: str) -> QueryProfile:
    """Parse query text into a frozen QueryProfile with normalized indicators."""
    cves = tuple(sorted({m.upper() for m in _CVE_PATTERN.findall(query)}))
    ips = tuple(sorted(set(_IPV4_PATTERN.findall(query))))
    sha256 = set(_SHA256_PATTERN.findall(query))
    md5 = set(_MD5_PATTERN.findall(query)) - sha256
    hashes = tuple(sorted(h.lower() for h in (sha256 | md5)))
    # Entity names and ATT&CK IDs from the C9 gazetteer, lower-cased ATT&CK titles (empty when the ATT&CK
    # component is unavailable).
    names = entity_names(query, query=True)
    mitre = tuple(sorted({m.upper() for m in _MITRE_PATTERN.findall(query)} | set(names["technique_ids"])))
    actors = tuple(sorted({a.lower() for a in names["threat_actors"]}))
    malware = tuple(sorted({m.lower() for m in names["malware"]}))

    return QueryProfile(
        cves=cves,
        ips=ips,
        hashes=hashes,
        mitre_techniques=mitre,
        threat_actors=actors,
        malware=malware,
        raw_query=query,
    )


# ---------------------------------------------------------------------------
# Layer 1: Deterministic Identifier Matcher & Record Class (R6a)
# ---------------------------------------------------------------------------

def classify_evidence_record_class(candidate_chunk: dict[str, Any]) -> str:
    """Classify chunk as DESCRIPTION vs METADATA_STUB (R6a)."""
    meta = candidate_chunk.get("metadata") or {}
    doc_id = str(candidate_chunk.get("doc_id") or meta.get("doc_id") or candidate_chunk.get("chunk_id", ""))
    source_org = str(candidate_chunk.get("source_org") or meta.get("source_org", "")).upper()
    if doc_id.endswith("_EPSS") or source_org == "EPSS" or doc_id.endswith("_KEV"):
        return "METADATA_STUB"
    return "DESCRIPTION"


def match_layer1(
    query_profile: QueryProfile,
    candidate_chunk: dict[str, Any],
) -> tuple[bool, str | None]:
    """
    Layer 1 Deterministic Identifier Match (No Model).
    Returns (True, 'EXACT_ID' | 'EXACT_HASH') if certitude conditions are met.
    Incidental mentions inside body text do NOT trigger Layer 1.
    """
    meta = candidate_chunk.get("metadata")
    if not isinstance(meta, dict):
        meta = {}

    # 1. EXACT_ID:
    # Triggered if query_profile.cves is non-empty and EVERY queried CVE equals
    # the chunk's primary CVE extracted via re.match(r"^(CVE-\d{4}-\d{4,7})", doc_id)
    if query_profile.cves:
        doc_id = candidate_chunk.get("doc_id") or meta.get("doc_id") or candidate_chunk.get("chunk_id", "")
        if doc_id:
            m = re.match(r"^(CVE-\d{4}-\d{4,7})", str(doc_id), re.IGNORECASE)
            if m:
                primary_cve = m.group(1).upper()
                if all(c.upper() == primary_cve for c in query_profile.cves):
                    return (True, "EXACT_ID")

    # 2. EXACT_HASH:
    # Triggered if query_profile.hashes is non-empty and any queried hash matches
    # entities_json['iocs']['sha256'] or ['md5']
    if query_profile.hashes:
        ent = candidate_chunk.get("entities") or candidate_chunk.get("entities_json")
        if not ent:
            ent = meta.get("entities") or meta.get("entities_json")
        if isinstance(ent, str):
            try:
                ent = json.loads(ent)
            except Exception:
                ent = {}
        if isinstance(ent, dict):
            iocs = ent.get("iocs") or {}
            chunk_hashes = set()
            for h in (iocs.get("sha256") or []):
                chunk_hashes.add(str(h).lower())
            for h in (iocs.get("md5") or []):
                chunk_hashes.add(str(h).lower())
            if any(h.lower() in chunk_hashes for h in query_profile.hashes):
                return (True, "EXACT_HASH")

    return (False, None)


# ---------------------------------------------------------------------------
# Tier Classification Mapping
# ---------------------------------------------------------------------------

def classify_confidence_tier(probability: float) -> str:
    """
    Pure mapping from calibrated probability to pre-registered bands:
      >= 0.65 -> STRONG
      >= 0.45 -> PARTIAL
      >= 0.10 -> WEAK
      < 0.10  -> UNSUPPORTED
    """
    if probability >= 0.65:
        return "STRONG"
    elif probability >= 0.45:
        return "PARTIAL"
    elif probability >= 0.10:
        return "WEAK"
    return "UNSUPPORTED"


# ---------------------------------------------------------------------------
# Learned Confidence Model & Loader
# ---------------------------------------------------------------------------

class ConfidenceModel:
    """Lightweight, vectorized CPU inference for L2 Logistic Regression & Calibrator with support guards.

    NOTE ON FEATURE WEIGHTS (v1.0.0):
    In the default shipped model artifact (models/confidence_model.json), non-zero weights
    are present only for `ioc_coverage`, `bm25_norm_score`, and `inter_ioc_cov`. Features
    such as `cve_coverage`, `ttp_coverage`, and `reranker_score` have 0.0 weights pending
    Phase 2 retraining on expanded behavioral datasets. Layer 1 (EXACT_ID) handles primary
    CVE matching deterministically.
    """

    def __init__(
        self,
        weights: dict[str, float] | list[float],
        bias: float = 0.0,
        feature_names: list[str] | None = None,
        model_version: str = "v1.0.0",
        scaler: dict[str, Any] | None = None,
        calibrator: dict[str, Any] | None = None,
        feature_support: dict[str, list[float]] | None = None,
    ) -> None:
        self.feature_names = feature_names or FEATURE_NAMES
        self.bias = float(bias)
        self.model_version = model_version
        self.scaler = scaler
        self.calibrator = calibrator
        self.feature_support = feature_support or {
            name: [0.0, 1.0] for name in self.feature_names
        }

        if isinstance(weights, dict):
            self.weights = {k: float(v) for k, v in weights.items()}
        elif isinstance(weights, (list, tuple)):
            self.weights = {
                name: float(w) for name, w in zip(self.feature_names, weights)
            }
        else:
            self.weights = {}

    @property
    def is_calibrated(self) -> bool:
        """Return True only if an active calibrator (sigmoid/platt/isotonic) is configured."""
        if not self.calibrator or not isinstance(self.calibrator, dict):
            return False
        method = (self.calibrator.get("method") or self.calibrator.get("type") or "").lower()
        return method in ("sigmoid", "platt", "isotonic")

    def is_in_support(self, features: dict[str, float]) -> bool:
        """Check if feature vector is within valid training support bounds (R1)."""
        for name, bounds in self.feature_support.items():
            if name in features and len(bounds) == 2:
                val = float(features[name])
                # allow 0.5 epsilon margin
                if val < bounds[0] - 0.5 or val > bounds[1] + 0.5:
                    return False
        return True

    def get_contributions(self, features: dict[str, float]) -> dict[str, float]:
        """Compute individual feature contributions to the logit."""
        contributions: dict[str, float] = {}
        for name, w in self.weights.items():
            val = float(features.get(name, 0.0))
            if self.scaler and "mean" in self.scaler and "scale" in self.scaler:
                try:
                    if isinstance(self.scaler["mean"], dict):
                        mean = float(self.scaler["mean"].get(name, 0.0))
                        scale = float(self.scaler["scale"].get(name, 1.0))
                    else:
                        idx = self.feature_names.index(name)
                        mean = float(self.scaler["mean"][idx])
                        scale = float(self.scaler["scale"][idx])
                    if scale != 0.0:
                        val = (val - mean) / scale
                except (ValueError, IndexError, KeyError, TypeError):
                    pass
            contributions[name] = round(w * val, 4)
        return contributions

    def predict_proba(self, features: dict[str, float]) -> float:
        """Evaluate logistic regression logit + optional calibrator."""
        z = self.bias
        for name, w in self.weights.items():
            val = float(features.get(name, 0.0))
            if self.scaler and "mean" in self.scaler and "scale" in self.scaler:
                try:
                    if isinstance(self.scaler["mean"], dict):
                        mean = float(self.scaler["mean"].get(name, 0.0))
                        scale = float(self.scaler["scale"].get(name, 1.0))
                    else:
                        idx = self.feature_names.index(name)
                        mean = float(self.scaler["mean"][idx])
                        scale = float(self.scaler["scale"][idx])
                    if scale != 0.0:
                        val = (val - mean) / scale
                except (ValueError, IndexError, KeyError, TypeError):
                    pass
            z += w * val

        z_clipped = max(-50.0, min(50.0, z))
        prob = 1.0 / (1.0 + math.exp(-z_clipped))

        if self.calibrator and isinstance(self.calibrator, dict):
            method = self.calibrator.get("method") or self.calibrator.get("type")
            params = self.calibrator.get("params") if isinstance(self.calibrator.get("params"), dict) else self.calibrator
            if method in ("sigmoid", "platt"):
                a = float(params.get("a", 1.0))
                b = float(params.get("b", 0.0))
                cal_z = max(-50.0, min(50.0, a * z + b))
                prob = 1.0 / (1.0 + math.exp(-cal_z))
            elif method == "isotonic":
                x_thresh = params.get("x_thresholds", [])
                y_thresh = params.get("y_thresholds", [])
                if len(x_thresh) >= 2 and len(x_thresh) == len(y_thresh):
                    if prob <= x_thresh[0]:
                        prob = float(y_thresh[0])
                    elif prob >= x_thresh[-1]:
                        prob = float(y_thresh[-1])
                    else:
                        for i in range(len(x_thresh) - 1):
                            if x_thresh[i] <= prob <= x_thresh[i + 1]:
                                span = x_thresh[i + 1] - x_thresh[i]
                                if span > 0:
                                    t = (prob - x_thresh[i]) / span
                                    prob = y_thresh[i] + t * (y_thresh[i + 1] - y_thresh[i])
                                else:
                                    prob = float(y_thresh[i])
                                break

        return max(0.0, min(1.0, prob))


_MODEL_CACHE: ConfidenceModel | None = None
_MODEL_LOAD_ATTEMPTED: bool = False


def load_confidence_model(model_path: str | Path | None = None) -> ConfidenceModel | None:
    """Load model artifact from models/confidence_model.json. Triggers safe degraded mode if absent."""
    if model_path:
        path = Path(model_path)
    else:
        path = Path(__file__).resolve().parent.parent / "models" / "confidence_model.json"

    if not path.is_file():
        logger.warning("Confidence model not found at %s. Operating in safe degraded mode.", path)
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            logger.warning("Invalid confidence model JSON structure at %s. Operating in safe degraded mode.", path)
            return None

        weights = data.get("weights")
        if weights is None:
            logger.warning("Confidence model missing weights at %s. Operating in safe degraded mode.", path)
            return None

        return ConfidenceModel(
            weights=weights,
            bias=float(data.get("bias", data.get("intercept", 0.0))),
            feature_names=data.get("feature_names", FEATURE_NAMES),
            model_version=str(data.get("model_version", data.get("version", "v1.0.0"))),
            scaler=data.get("scaler"),
            calibrator=data.get("calibrator"),
            feature_support=data.get("feature_support"),
        )
    except Exception as exc:
        logger.warning("Failed to load confidence model from %s: %s. Operating in safe degraded mode.", path, exc)
        return None


def get_confidence_model() -> ConfidenceModel | None:
    """Singleton getter for the loaded confidence model."""
    global _MODEL_CACHE, _MODEL_LOAD_ATTEMPTED
    if not _MODEL_LOAD_ATTEMPTED:
        _MODEL_CACHE = load_confidence_model()
        _MODEL_LOAD_ATTEMPTED = True
    return _MODEL_CACHE


# ---------------------------------------------------------------------------
# Resolution Data Structure
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConfidenceResolution:
    """
    Strongly typed confidence resolution schema matching Contract Section 8.1.
    """
    match_type: str            # EXACT_ID | EXACT_HASH | LEARNED_MODEL | HEURISTIC_PRESENCE
    probability: float         # Calibrated probability in [0.0, 1.0]
    tier: str                  # EXACT | STRONG | PARTIAL | WEAK | UNSUPPORTED
    tier_basis: str            # DETERMINISTIC_L1 | CALIBRATED_LOGISTIC_REGRESSION | UNCALIBRATED_BEHAVIORAL_HEURISTIC
    features: dict[str, float]
    feature_contributions: dict[str, float] = field(default_factory=dict)
    model_version: str = "v1.0.0"
    calibrated: bool = True
    degraded: bool = False
    evidence_record_class: str = "DESCRIPTION"  # DESCRIPTION vs METADATA_STUB (R6a)


# ---------------------------------------------------------------------------
# Runtime Resolution Entrypoint
# ---------------------------------------------------------------------------

def resolve_confidence(
    query_profile: QueryProfile,
    candidate_chunk: dict[str, Any],
    candidate_score: float,
    model: Any = None,
    force_degraded: bool = False,
) -> ConfidenceResolution:
    """
    Resolves confidence score and tier for a query and candidate chunk.

    1. Checks Layer 1 deterministic match (EXACT_ID / EXACT_HASH) -> EXACT tier, prob 1.0.
    2. If not Layer 1:
       - If behavioral query (no CVE, only IOC/TTP): Option B presence-renormalized heuristic.
       - If CVE / general query: Learned Logistic Regression model.
       - If model missing / invalid or reranker failed: Safe degraded mode (capped at STRONG, never EXACT, M1 fallback).
    """
    record_class = classify_evidence_record_class(candidate_chunk)

    # 1. Deterministic Layer 1 Matcher
    is_l1, match_type = match_layer1(query_profile, candidate_chunk)
    if is_l1 and match_type is not None:
        features = extract_features(query_profile, candidate_chunk)
        return ConfidenceResolution(
            match_type=match_type,
            probability=1.0,
            tier="EXACT",
            tier_basis="DETERMINISTIC_L1",
            features=features,
            feature_contributions={},
            model_version=getattr(model, "model_version", "v1.0.0") if model else "v1.0.0",
            calibrated=True,
            degraded=False,
            evidence_record_class=record_class,
        )

    # 2. Extract Layer 2 features (train-serve parity, anti-leakage)
    features = extract_features(query_profile, candidate_chunk)

    # Check query type: Behavioral (Option B) vs CVE/Model
    has_cve = bool(query_profile.cves)
    has_behavioral = bool(
        query_profile.ips or query_profile.hashes or
        query_profile.mitre_techniques or query_profile.threat_actors or query_profile.malware
    )

    # Option B: Behavioral query (no CVE, only IOC/TTP) - Renormalized Presence Weights (R17)
    # Rationale:
    # When a query contains behavioral observables (IOCs, TTPs) but no explicit CVE,
    # the learned model's CVE-centric features cannot fire. Instead of penalizing absent
    # CVE observables, Option B activates only the present observable modalities:
    #   - Semantic base weight: 0.20 (always active via reranker / dense / BM25)
    #   - IOC weight: 0.40 (active only if query has IOCs)
    #   - TTP weight: 0.20 (active only if query has TTPs)
    # The composite probability is normalized by dividing by total active weight:
    #   prob = sum(w_i * sim_i) / sum(w_i)
    # Results are uncalibrated (calibrated=False, tier_basis="UNCALIBRATED_BEHAVIORAL_HEURISTIC")
    # and strictly capped at tier "STRONG" (never "EXACT").
    if not has_cve and has_behavioral and not force_degraded:
        ioc_sim = features["ioc_coverage"]
        ttp_sim = features["ttp_coverage"]
        semantic_sim = (
            features["reranker_score"]
            if features["reranker_score"] > 0
            else (candidate_score if candidate_score > 0 else features["bm25_norm_score"])
        )

        weights = []
        sims = []
        weights.append(0.20)
        sims.append(semantic_sim)
        if features["has_ioc"] > 0:
            weights.append(0.40)
            sims.append(ioc_sim)
        if features["has_ttp"] > 0:
            weights.append(0.20)
            sims.append(ttp_sim)

        total_w = sum(weights)
        prob = sum(w * s for w, s in zip(weights, sims)) / total_w if total_w > 0 else 0.0
        prob = max(0.0, min(1.0, prob))
        tier = classify_confidence_tier(prob)
        if tier == "EXACT":
            tier = "STRONG"  # Layer 2 cannot assign EXACT

        contributions = {
            "semantic": round((0.20 / total_w) * semantic_sim, 4),
        }
        if features["has_ioc"] > 0:
            contributions["ioc"] = round((0.40 / total_w) * ioc_sim, 4)
        if features["has_ttp"] > 0:
            contributions["ttp"] = round((0.20 / total_w) * ttp_sim, 4)

        return ConfidenceResolution(
            match_type="HEURISTIC_PRESENCE",
            probability=round(prob, 4),
            tier=tier,
            tier_basis="UNCALIBRATED_BEHAVIORAL_HEURISTIC",
            features=features,
            feature_contributions=contributions,
            model_version="m1.0.0-heuristic",
            calibrated=False,
            degraded=False,
            evidence_record_class=record_class,
        )

    # 3. Learned Model or Safe Degraded Mode
    active_model = model if model is not None else get_confidence_model()
    if active_model is not None and not getattr(active_model, "is_degraded", False) and not force_degraded:
        prob = active_model.predict_proba(features)
        prob = max(0.0, min(1.0, prob))
        tier = classify_confidence_tier(prob)
        if tier == "EXACT":
            tier = "STRONG"
        contributions = active_model.get_contributions(features)
        is_cal = getattr(active_model, "is_calibrated", False)
        return ConfidenceResolution(
            match_type="LEARNED_MODEL",
            probability=round(prob, 4),
            tier=tier,
            tier_basis="CALIBRATED_LOGISTIC_REGRESSION" if is_cal else "UNCALIBRATED_LOGISTIC_REGRESSION",
            features=features,
            feature_contributions=contributions,
            model_version=active_model.model_version,
            calibrated=is_cal,
            degraded=False,
            evidence_record_class=record_class,
        )

    # 4. Safe Degraded Mode (model artifact missing, unreadable, or reranker failed, R20)
    logger.warning("Confidence resolution operating in safe degraded mode (model missing or degraded).")
    semantic_sim = (
        features["reranker_score"]
        if features["reranker_score"] > 0
        else (candidate_score if candidate_score > 0 else features["bm25_norm_score"])
    )
    active_weight = (
        (0.40 * features["has_ioc"]) +
        (0.20 * features["has_ttp"]) +
        (0.20 * features["has_cve"]) +
        0.20
    )
    w_ioc = (0.40 * features["has_ioc"]) / active_weight
    w_ttp = (0.20 * features["has_ttp"]) / active_weight
    w_cve = (0.20 * features["has_cve"]) / active_weight
    w_sem = 0.20 / active_weight

    composite = (
        (w_ioc * features["ioc_coverage"]) +
        (w_ttp * features["ttp_coverage"]) +
        (w_cve * features["cve_coverage"]) +
        (w_sem * semantic_sim)
    )
    prob = max(0.0, min(1.0, composite))
    tier = classify_confidence_tier(prob)
    if tier == "EXACT":
        tier = "STRONG"  # Contract rule: Cap tier at STRONG, never EXACT in degraded mode

    contributions = {
        "ioc": round(w_ioc * features["ioc_coverage"], 4),
        "ttp": round(w_ttp * features["ttp_coverage"], 4),
        "cve": round(w_cve * features["cve_coverage"], 4),
        "semantic": round(w_sem * semantic_sim, 4),
    }
    return ConfidenceResolution(
        match_type="HEURISTIC_PRESENCE",
        probability=round(prob, 4),
        tier=tier,
        tier_basis="UNCALIBRATED_BEHAVIORAL_HEURISTIC",
        features=features,
        feature_contributions=contributions,
        model_version="degraded-m1",
        calibrated=False,
        degraded=True,
        evidence_record_class=record_class,
    )
