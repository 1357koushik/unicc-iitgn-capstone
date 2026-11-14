from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from threat_retrieval_engine.api.confidence import classify_confidence_tier
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


@dataclass
class ParsedEntities:
    cves: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)


def parse_query_entities(query: str) -> ParsedEntities:
    """Extract structured indicators and entities from threat query text."""
    cves = sorted({m.upper() for m in _CVE_PATTERN.findall(query)})
    ips = sorted(set(_IPV4_PATTERN.findall(query)))
    
    sha256 = set(_SHA256_PATTERN.findall(query))
    md5 = set(_MD5_PATTERN.findall(query)) - sha256
    hashes = sorted(h.lower() for h in sha256 | md5)

    mitre = sorted({m.upper() for m in _MITRE_PATTERN.findall(query)})

    q_lower = query.lower()
    actors = [a for a in _COMMON_ACTORS if a.lower() in q_lower]
    malware = [m for m in _COMMON_MALWARE if m.lower() in q_lower]

    return ParsedEntities(
        cves=cves,
        ips=ips,
        hashes=hashes,
        mitre_techniques=mitre,
        threat_actors=actors,
        malware=malware,
    )


def jaccard_similarity(a: set[str] | list[str], b: set[str] | list[str]) -> float:
    """Calculate Jaccard similarity between two sets."""
    set_a = {x.lower() for x in a if x}
    set_b = {x.lower() for x in b if x}
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


CALIBRATED_SCORING_WEIGHTS: tuple[float, float, float, float] = (0.40, 0.20, 0.20, 0.20)


def calculate_composite_score(
    ioc_score: float,
    ttp_score: float,
    semantic_score: float,
    cve_score: float,
    weights: tuple[float, float, float, float] | list[float] | None = None,
) -> float:
    """Legacy helper maintained for backward compatibility."""
    w = weights if weights is not None else CALIBRATED_SCORING_WEIGHTS
    composite = (
        (ioc_score * w[0])
        + (ttp_score * w[1])
        + (semantic_score * w[2])
        + (cve_score * w[3])
    )
    return round(float(composite), 4)


def extract_attribution(
    query_ent: ParsedEntities,
    chunk_meta: dict[str, Any],
    chunk_text: str = "",
) -> dict[str, list[str]]:
    """Compare query entities with chunk metadata/text to extract attributions."""
    entities_data = chunk_meta.get("entities") or {}
    if isinstance(entities_data, str):
        import json
        try:
            entities_data = json.loads(entities_data)
        except Exception:
            entities_data = {}

    # Extract chunk CVEs
    chunk_cves = set(entities_data.get("cves") or [])
    chunk_cves.update(_CVE_PATTERN.findall(chunk_text))
    chunk_cves_norm = {c.upper() for c in chunk_cves}
    matching_cves = sorted({c.upper() for c in query_ent.cves} & chunk_cves_norm)

    # Extract chunk IOCs
    iocs_data = entities_data.get("iocs") or {}
    chunk_iocs = set(iocs_data.get("ipv4") or [])
    chunk_iocs.update(iocs_data.get("sha256") or [])
    chunk_iocs.update(iocs_data.get("md5") or [])
    chunk_iocs.update(_IPV4_PATTERN.findall(chunk_text))
    chunk_iocs.update(_MD5_PATTERN.findall(chunk_text))
    chunk_iocs.update(_SHA256_PATTERN.findall(chunk_text))
    chunk_iocs_norm = {i.lower() for i in chunk_iocs}
    query_iocs_norm = {i.lower() for i in (query_ent.ips + query_ent.hashes)}
    matching_iocs = sorted(query_iocs_norm & chunk_iocs_norm)

    # Extract chunk malware
    chunk_mal = set(entities_data.get("malware_families") or [])
    for m in _COMMON_MALWARE:
        if m.lower() in chunk_text.lower():
            chunk_mal.add(m)
    matching_mal = sorted({m.lower(): m for m in query_ent.malware if m.lower() in {x.lower() for x in chunk_mal}}.values())

    # Extract chunk MITRE TTPs (direct mentions + tool-implemented techniques)
    chunk_ttps = set(entities_data.get("mitre_ttps") or [])
    chunk_ttps.update(_MITRE_PATTERN.findall(chunk_text))
    for t_name, techs in _TOOL_TO_TECH.items():
        if t_name in chunk_text.lower() or any(m.lower() == t_name for m in chunk_mal):
            chunk_ttps.update(techs)

    chunk_ttps_norm = {t.upper() for t in chunk_ttps}
    query_ttps_norm = {t.upper() for t in query_ent.mitre_techniques}
    matching_ttps = sorted(query_ttps_norm & chunk_ttps_norm)

    return {
        "matching_iocs": matching_iocs,
        "matching_cves": matching_cves,
        "shared_malware": matching_mal,
        "matching_mitre_techniques": matching_ttps,
    }


def build_citation(chunk_id: str, chunk_meta: dict[str, Any], chunk_text: str) -> dict[str, Any]:
    """Construct structured citation from chunk metadata and provenance without fabricating dates (R9)."""
    doc_id = chunk_meta.get("doc_id") or chunk_id
    doc_title = chunk_meta.get("doc_title") or "UNKNOWN"
    source_org = chunk_meta.get("source_org") or "UNKNOWN"
    pub_date = chunk_meta.get("published_date")
    
    if isinstance(pub_date, datetime):
        published_date_str = pub_date.isoformat() + "Z"
    elif pub_date:
        published_date_str = str(pub_date)
    else:
        published_date_str = None
    
    page_no = chunk_meta.get("page_number")
    snippet = chunk_text.strip() if chunk_text else "No passage text available."
    if len(snippet) > 400:
        snippet = snippet[:400] + "..."

    provenance_status = "VERIFIED" if published_date_str and doc_title != "UNKNOWN" else "MISSING"

    return {
        "doc_id": str(doc_id),
        "doc_title": str(doc_title),
        "source_org": str(source_org),
        "published_date": published_date_str,
        "page_number": page_no,
        "text_snippet": snippet,
        "provenance_status": provenance_status,
    }
