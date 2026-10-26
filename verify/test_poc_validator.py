from __future__ import annotations

import pytest
from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate
from threat_retrieval_engine.poc_intelligence.poc_validator import PoCValidator


def test_validator_verified_code_high_stars():
    validator = PoCValidator()
    cand = RawCandidate(
        url="https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/cve-2024-3400",
        title="PAN-OS GlobalProtect RCE CVE-2024-3400 Exploit Module",
        source="github",
        author="rapid7",
        description="Working Ruby exploit module for CVE-2024-3400 remote code execution",
        stars=32000,
        language="Ruby",
    )
    res = validator.validate_candidate(cand, cve_id="CVE-2024-3400")
    assert res.confidence_score >= 0.75
    assert res.confidence_label in ("HIGH_RELEVANCE_POC_CANDIDATE", "VERIFIED_CODE")
    assert len(res.warning_flags) == 0


def test_validator_likely_poc():
    validator = PoCValidator()
    cand = RawCandidate(
        url="https://github.com/threatsec/CVE-2021-44228-poc",
        title="CVE-2021-44228 Proof of Concept",
        source="github",
        author="threatsec",
        description="Simple script testing vulnerability in Log4j",
        stars=4,
        language="Python",
    )
    res = validator.validate_candidate(cand, cve_id="CVE-2021-44228")
    assert 0.50 <= res.confidence_score <= 0.85
    assert res.confidence_label in ("HIGH_RELEVANCE_POC_CANDIDATE", "POSSIBLE_POC", "LIKELY_POC", "VERIFIED_CODE")


def test_validator_suspicious_malware_trap():
    validator = PoCValidator()
    cand = RawCandidate(
        url="https://github.com/fake-sec/cve-2024-3400-poc",
        title="100% working CVE-2024-3400 0day download",
        source="github",
        author="fake-sec",
        description="Download exploit.exe with password 1234. PowerShell -enc AABBAA... invoke-expression",
        stars=0,
    )
    res = validator.validate_candidate(cand, cve_id="CVE-2024-3400")
    assert res.confidence_score < 0.25
    assert res.confidence_label == "SUSPICIOUS"
    assert "binary_only" in res.warning_flags
    assert "obfuscated_code" in res.warning_flags


def test_precision_metric_meets_target_benchmark():
    validator = PoCValidator()
    cands = [
        RawCandidate(
            url="https://github.com/sec1/CVE-2024-3400-exploit",
            title="CVE-2024-3400 Python Exploit",
            source="github",
            author="sec1",
            stars=45,
            language="Python",
        ),
        RawCandidate(
            url="https://github.com/sec2/CVE-2024-3400-poc",
            title="Nuclei template for CVE-2024-3400",
            source="github",
            author="sec2",
            stars=12,
            language="YAML",
        ),
        RawCandidate(
            url="https://infosec.exchange/@analyst/11223344",
            title="Mastodon thread discussing CVE-2024-3400 technical details",
            source="mastodon",
            author="@analyst@infosec.exchange",
            description="Discussing mitigations and workarounds for the new PAN-OS flaw.",
        ),
        RawCandidate(
            url="https://github.com/malicious/fake-cve-2024-3400",
            title="Buy full 0day telegram contact t.me/hacker",
            source="github",
            author="scammer",
            description="Download run.exe password protected archive",
        ),
    ]

    validated = [validator.validate_candidate(c, "CVE-2024-3400") for c in cands]
    # First 2 are verified/likely, 3rd is discussion, 4th is suspicious
    assert validated[0].confidence_label in ("HIGH_RELEVANCE_POC_CANDIDATE", "VERIFIED_CODE")
    assert validated[1].confidence_label in ("HIGH_RELEVANCE_POC_CANDIDATE", "POSSIBLE_POC", "LIKELY_POC", "VERIFIED_CODE")
    assert validated[2].confidence_label in ("RELATED_DISCUSSION", "DISCUSSION", "ADVISORY_OR_PATCH")
    assert validated[3].confidence_label in ("SUSPICIOUS", "LOW_CONFIDENCE")

    # Precision for the top 3 items
    top_3_precision = validator.calculate_precision(validated[:3])
    # 2 out of 3 = 66.7%
    assert top_3_precision >= 0.66

    # Precision for verified/likely subset is 1.0 (100% precision)
    high_conf = [r for r in validated if r.confidence_score >= 0.50]
    assert validator.calculate_precision(high_conf) == 1.0
