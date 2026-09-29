"""
tests/test_helpers.py
=====================
Unit tests for API helper functions: entity extraction, Jaccard similarity,
4-factor scoring, confidence tier classification, and citation generation.
"""

from __future__ import annotations

import pytest
from threat_retrieval_engine.api.helpers import (
    build_citation,
    calculate_composite_score,
    classify_confidence_tier,
    extract_attribution,
    jaccard_similarity,
    parse_query_entities,
)


def test_parse_query_entities_cve_and_ioc() -> None:
    query = "Attacker exploited CVE-2017-0144 from 198.51.100.24 using technique T1021.002 with PsExec"
    parsed = parse_query_entities(query)

    assert "CVE-2017-0144" in parsed.cves
    assert "198.51.100.24" in parsed.ips
    assert "T1021.002" in parsed.mitre_techniques
    assert "PsExec" in parsed.malware


def test_parse_query_entities_hashes() -> None:
    query = (
        "Detected malicious payload with MD5 5d41402abc4b2a76b9719d911017c592 and "
        "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    parsed = parse_query_entities(query)

    assert "5d41402abc4b2a76b9719d911017c592" in parsed.hashes
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in parsed.hashes


def test_jaccard_similarity() -> None:
    assert jaccard_similarity([], []) == 0.0
    assert jaccard_similarity(["a", "b"], ["a", "b"]) == 1.0
    assert jaccard_similarity(["a"], ["b"]) == 0.0
    assert jaccard_similarity(["a", "b"], ["a", "c"]) == pytest.approx(1.0 / 3.0)


def test_calculate_composite_score_formula() -> None:
    # Formula: 0.35 * IOC + 0.25 * TTP + 0.25 * Semantic + 0.15 * CVE
    score = calculate_composite_score(
        ioc_score=1.0,
        ttp_score=1.0,
        semantic_score=1.0,
        cve_score=1.0,
    )
    assert score == pytest.approx(1.0, abs=1e-4)

    partial_score = calculate_composite_score(
        ioc_score=0.0,
        ttp_score=1.0,
        semantic_score=0.8,
        cve_score=1.0,
    )
    # 0.35*0 + 0.25*1.0 + 0.25*0.8 + 0.15*1.0 = 0 + 0.25 + 0.20 + 0.15 = 0.60
    assert partial_score == pytest.approx(0.60, abs=1e-4)


def test_classify_confidence_tier_thresholds() -> None:
    assert classify_confidence_tier(0.96) == "EXACT"
    assert classify_confidence_tier(0.95) == "EXACT"
    assert classify_confidence_tier(0.85) == "STRONG"
    assert classify_confidence_tier(0.80) == "STRONG"
    assert classify_confidence_tier(0.79) == "PARTIAL"
    assert classify_confidence_tier(0.55) == "PARTIAL"
    assert classify_confidence_tier(0.54) == "WEAK"
    assert classify_confidence_tier(0.30) == "WEAK"
    assert classify_confidence_tier(0.29) == "UNSUPPORTED"
    assert classify_confidence_tier(0.0) == "UNSUPPORTED"


def test_extract_attribution() -> None:
    query = "Attacker exploited CVE-2017-0144 using T1021.002"
    parsed = parse_query_entities(query)
    metadata = {
        "entities": {
            "cves": ["CVE-2017-0144"],
            "mitre_ttps": ["T1021.002"],
            "threat_actors": ["APT29"],
            "malware_families": ["PsExec"],
            "iocs": {"ipv4": ["198.51.100.24"]},
        }
    }
    text = "Attacker executed T1021.002 over SMB."

    attribution = extract_attribution(parsed, metadata, text)
    assert "CVE-2017-0144" in attribution["matching_cves"]
    assert "T1021.002" in attribution["matching_mitre_techniques"]


def test_build_citation() -> None:
    metadata = {
        "doc_id": "CVE-2021-44228",
        "doc_title": "Apache Log4j Vulnerability",
        "source_org": "NVD",
        "published_date": "2021-12-10",
        "char_start": 0,
        "char_end": 150,
    }
    text = "JNDI lookup vulnerability in Log4j enables remote arbitrary code execution."

    citation = build_citation("chunk_123", metadata, text)
    assert citation["doc_id"] == "CVE-2021-44228"
    assert citation["source_org"] == "NVD"
    assert "JNDI lookup" in citation["text_snippet"]
