from __future__ import annotations

import pytest
from threat_retrieval_engine.search_engine.tokenizer import (
    tokenize,
    extract_identifiers,
    _valid_ipv4,
)


def test_tokenizer_atomic_tokens():
    text = "Observed CVE-2021-44228 from IP 198.51.100.24 using technique T1059.001 with sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    tokens = tokenize(text)

    # Identifiers must be preserved atomically in lowercase
    assert "cve-2021-44228" in tokens
    assert "198.51.100.24" in tokens
    assert "t1059.001" in tokens
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in tokens

    # Normal words should also be present
    assert "observed" in tokens
    assert "technique" in tokens


def test_tokenizer_ipv4_validation():
    assert _valid_ipv4("192.168.1.1") is True
    assert _valid_ipv4("10.0.0.1/24") is True
    assert _valid_ipv4("999.1.1.1") is False
    assert _valid_ipv4("1.2.3.4.5") is False
    assert _valid_ipv4("not.an.ip") is False


def test_extract_identifiers():
    text = "Vulnerability CVE-2024-3400 exploited via 203.0.113.5 and hash 5d41402abc4b2a76b9719d911017c592"
    idents = extract_identifiers(text)

    assert "cve-2024-3400" in idents["cve"]
    assert "203.0.113.5" in idents["ipv4"]
    assert "5d41402abc4b2a76b9719d911017c592" in idents["hash"]
