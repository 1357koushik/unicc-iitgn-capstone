from __future__ import annotations

import pytest
from datetime import datetime, timezone
from threat_retrieval_engine.search_engine.duplicate_checker import (
    DuplicateChecker,
    _make_shingles,
    _tokenize,
)
from threat_retrieval_engine.search_engine.validator import ThreatChunk


def test_make_shingles():
    tokens = "one two three four five"
    shingles = _make_shingles(tokens, size=3)
    assert len(shingles) == 3
    assert b"one two three" in shingles
    assert b"two three four" in shingles
    assert b"three four five" in shingles


def test_duplicate_checker_detection():
    checker = DuplicateChecker(threshold=0.75)

    base_text = "Apache Log4j2 JNDI remote code execution vulnerability flaw in LDAP request parsing logic allowing arbitrary payload execution."
    near_dup = "Apache Log4j2 JNDI remote code execution vulnerability flaw in LDAP request parsing logic allowing arbitrary payload execution on remote systems."
    different = "Palo Alto Networks PAN-OS command injection vulnerability in GlobalProtect gateway portal."
    now = datetime.now(timezone.utc)

    c1 = ThreatChunk(
        chunk_id="c1",
        doc_id="CVE-2021-44228_NVD",
        doc_title="Log4j",
        source_org="NVD",
        published_date=now,
        text=base_text,
    )
    c2 = ThreatChunk(
        chunk_id="c2",
        doc_id="CVE-2021-44228_ALIAS",
        doc_title="Log4j Alias",
        source_org="CVE_LIST_V5",
        published_date=now,
        text=near_dup,
    )
    c3 = ThreatChunk(
        chunk_id="c3",
        doc_id="CVE-2024-3400_NVD",
        doc_title="PAN-OS",
        source_org="NVD",
        published_date=now,
        text=different,
    )

    chunks = [c1, c2, c3]
    unique = list(checker.filter(chunks))

    # c1 is added, c2 should be rejected as near-duplicate, c3 is distinct
    unique_ids = [c.chunk_id for c in unique]
    assert "c1" in unique_ids
    assert "c3" in unique_ids
    assert "c2" not in unique_ids
