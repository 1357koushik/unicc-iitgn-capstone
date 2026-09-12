"""
test_tokenizer.py
=================
Tests for tokenizer.py — the cyber-aware tokenizer.

Run with: pytest verify/test_tokenizer.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tokenizer import extract_identifiers, tokenize


# ---------------------------------------------------------------------------
# Atomic-token preservation
# ---------------------------------------------------------------------------


def test_cve_preserved_as_single_token():
    toks = tokenize("Exploitation of CVE-2017-0144 was observed")
    assert "cve-2017-0144" in toks
    # It must NOT be split into cve / 2017 / 0144
    assert "2017" not in toks
    assert "0144" not in toks


def test_ipv4_preserved():
    toks = tokenize("beacon to 198.51.100.24 every 60 seconds")
    assert "198.51.100.24" in toks
    assert "198" not in toks


def test_sha256_preserved():
    h = "a" * 64
    toks = tokenize(f"dropped file with hash {h}")
    assert h in toks


def test_md5_preserved():
    h = "b" * 32
    toks = tokenize(f"md5 {h} flagged")
    assert h in toks


def test_mitre_technique_preserved():
    toks = tokenize("used T1021.002 for lateral movement")
    assert "t1021.002" in toks


def test_domain_preserved():
    toks = tokenize("c2 at evil-domain.example.com resolved")
    assert "evil-domain.example.com" in toks


def test_url_preserved():
    toks = tokenize("payload from https://bad.example.com/x?a=1 downloaded")
    assert any(t.startswith("https://bad.example.com") for t in toks)


# ---------------------------------------------------------------------------
# Ordinary words + ordering
# ---------------------------------------------------------------------------


def test_ordinary_words_lowercased():
    toks = tokenize("Lateral Movement Detected")
    assert toks == ["lateral", "movement", "detected"]


def test_reading_order_preserved():
    toks = tokenize("exploit CVE-2017-0144 from 198.51.100.24")
    assert toks == ["exploit", "cve-2017-0144", "from", "198.51.100.24"]


def test_empty_string():
    assert tokenize("") == []


def test_version_string_not_mistaken_for_ip():
    # 1.2.3.4567 has a >255 octet — must not be captured as an IPv4 token
    toks = tokenize("software version 1.2.3.4567 released")
    assert "1.2.3.4567" not in toks


# ---------------------------------------------------------------------------
# extract_identifiers
# ---------------------------------------------------------------------------


def test_extract_identifiers_groups_by_kind():
    text = "CVE-2017-0144 seen from 10.0.0.5 using T1021.002"
    ids = extract_identifiers(text)
    assert ids["cve"] == ["cve-2017-0144"]
    assert ids["ipv4"] == ["10.0.0.5"]
    assert ids["mitre"] == ["t1021.002"]


def test_extract_identifiers_dedupes():
    ids = extract_identifiers("CVE-2017-0144 and again CVE-2017-0144")
    assert ids["cve"] == ["cve-2017-0144"]
