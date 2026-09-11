"""
test_duplicate_checker.py
=========================
Tests for src/duplicate_checker.py (MinHash LSH deduplication)

Run with: pytest verify/test_duplicate_checker.py -v
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from validator import CyberEntities, ThreatChunk
from duplicate_checker import DuplicateChecker, _make_shingles, _tokenize


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_chunk(chunk_id: str, text: str) -> ThreatChunk:
    return ThreatChunk(
        chunk_id=chunk_id,
        doc_id=chunk_id,
        doc_title=f"Advisory {chunk_id}",
        source_org="NVD",
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        text=text,
    )


LONG_TEXT_A = (
    "Apache Log4j2 contains a remote code execution vulnerability via the JNDI lookup mechanism. "
    "An attacker can exploit this by sending a crafted HTTP request to a vulnerable server. "
    "This affects all versions from 2.0 to 2.14.1. Administrators should patch immediately. "
    "CVE-2021-44228 is tracked by NIST and CISA as a critical severity vulnerability."
)

LONG_TEXT_B = (
    "Apache Log4j2 contains a remote code execution vulnerability via the JNDI lookup mechanism. "
    "An attacker can exploit this by sending a crafted HTTP request to a vulnerable server. "
    "This affects all versions from 2.0 to 2.14.1. Administrators should patch immediately. "
    "CVE-2021-44228 is tracked by NIST and CISA as a critical severity issue."
    # Only last few words changed — near-duplicate
)

LONG_TEXT_C = (
    "Microsoft Windows contains a privilege escalation vulnerability in the kernel driver. "
    "A local attacker can gain SYSTEM privileges by exploiting a race condition in win32k.sys. "
    "This affects Windows 10, 11, and Windows Server 2019 and 2022. "
    "Users should apply the latest security updates from Microsoft Patch Tuesday."
)


# ---------------------------------------------------------------------------
# Internal helper tests
# ---------------------------------------------------------------------------


def test_tokenize_lowercases():
    tokens = _tokenize("Hello WORLD foo123")
    assert tokens == ["hello", "world", "foo123"]


def test_tokenize_strips_punctuation():
    tokens = _tokenize("CVE-2024-1234: an (example) test!")
    assert "cve" in tokens
    assert "2024" in tokens


def test_make_shingles_count():
    text = "the quick brown fox jumps over the lazy dog"
    shingles = _make_shingles(text, size=3)
    words = text.split()
    expected_count = len(words) - 3 + 1
    assert len(shingles) == expected_count


def test_make_shingles_short_text():
    """Text shorter than shingle size should return one shingle (the full text)."""
    shingles = _make_shingles("hello world", size=3)
    assert len(shingles) == 1


# ---------------------------------------------------------------------------
# DuplicateChecker behavior
# ---------------------------------------------------------------------------


def test_unique_document_passes():
    """A brand-new document should not be flagged as a duplicate."""
    checker = DuplicateChecker()
    chunk = _make_chunk("chunk_001", LONG_TEXT_A)
    assert checker.is_duplicate(chunk) is False


def test_exact_duplicate_caught():
    """The exact same text submitted twice — the second should be a duplicate."""
    checker = DuplicateChecker()
    chunk_a = _make_chunk("chunk_001", LONG_TEXT_A)
    chunk_b = _make_chunk("chunk_002", LONG_TEXT_A)   # same text, different ID
    checker.is_duplicate(chunk_a)
    assert checker.is_duplicate(chunk_b) is True


def test_near_duplicate_caught():
    """Text that differs only slightly (same 90%+ content) should be caught."""
    checker = DuplicateChecker()
    chunk_a = _make_chunk("chunk_001", LONG_TEXT_A)
    chunk_b = _make_chunk("chunk_002", LONG_TEXT_B)   # last few words changed
    checker.is_duplicate(chunk_a)
    assert checker.is_duplicate(chunk_b) is True


def test_different_documents_pass():
    """Two completely different reports should both pass through."""
    checker = DuplicateChecker()
    chunk_a = _make_chunk("chunk_001", LONG_TEXT_A)
    chunk_c = _make_chunk("chunk_003", LONG_TEXT_C)
    assert checker.is_duplicate(chunk_a) is False
    assert checker.is_duplicate(chunk_c) is False


# ---------------------------------------------------------------------------
# filter() method
# ---------------------------------------------------------------------------


def test_filter_returns_correct_count():
    """3 unique + 1 near-duplicate = 3 chunks after filtering."""
    checker = DuplicateChecker()
    chunks = [
        _make_chunk("c1", LONG_TEXT_A),
        _make_chunk("c2", LONG_TEXT_B),   # near-duplicate of c1
        _make_chunk("c3", LONG_TEXT_C),
    ]
    unique = list(checker.filter(chunks))
    # c2 should be dropped as a near-dup of c1
    assert len(unique) == 2


def test_filter_preserves_order():
    """First-seen document should be kept, later duplicate dropped."""
    checker = DuplicateChecker()
    chunks = [
        _make_chunk("first", LONG_TEXT_A),
        _make_chunk("second", LONG_TEXT_A),  # duplicate
    ]
    unique = list(checker.filter(chunks))
    assert unique[0].chunk_id == "first"


def test_filter_empty_input():
    """Empty input should produce empty output."""
    checker = DuplicateChecker()
    assert list(checker.filter([])) == []


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------


def test_reset_clears_index():
    """After reset, a previously-seen document should be accepted again."""
    checker = DuplicateChecker()
    chunk = _make_chunk("chunk_001", LONG_TEXT_A)

    checker.is_duplicate(chunk)           # registers it
    assert checker.is_duplicate(_make_chunk("chunk_002", LONG_TEXT_A)) is True  # duplicate

    checker.reset()

    # After reset, the same text is fresh again
    assert checker.is_duplicate(_make_chunk("chunk_001", LONG_TEXT_A)) is False
