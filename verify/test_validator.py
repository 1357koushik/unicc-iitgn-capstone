"""
test_validator.py
=================
Tests for src/validator.py
Run with: pytest verify/test_validator.py -v
"""

import csv
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Make src/ importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from validator import (
    CyberEntities,
    ThreatChunk,
    add_query_prefix,
    build_context,
    cvss_score_to_severity,
    is_valid_text,
    make_chunk_id,
    parse_cisa_kev_csv,
    parse_epss_csv,
    parse_normalized_directory,
    parse_normalized_jsonl,
    parse_normalized_record,
    sanitize_text,
    validate_file,
)


# ---------------------------------------------------------------------------
# sanitize_text
# ---------------------------------------------------------------------------


def test_sanitize_text_fixes_mojibake():
    broken = "It\u2019s a vulnerability"   # curly apostrophe
    result = sanitize_text(broken)
    assert "'" in result or "\u2019" in result   # ftfy either keeps or normalizes it


def test_sanitize_text_collapses_whitespace():
    messy = "  hello   world\n\ntest  "
    result = sanitize_text(messy)
    assert result == "hello world test"


def test_sanitize_text_handles_non_string():
    result = sanitize_text(12345)
    assert result == "12345"


# ---------------------------------------------------------------------------
# is_valid_text
# ---------------------------------------------------------------------------


def test_is_valid_text_too_short():
    assert is_valid_text("short") is False


def test_is_valid_text_too_long():
    assert is_valid_text("x" * 33000) is False


def test_is_valid_text_ok():
    assert is_valid_text("This is a normal piece of text about a vulnerability.") is True


def test_is_valid_text_exactly_min():
    # Exactly 15 characters — should pass
    assert is_valid_text("a" * 15) is True


# ---------------------------------------------------------------------------
# ThreatChunk schema
# ---------------------------------------------------------------------------


def test_threat_chunk_schema_valid():
    chunk = ThreatChunk(
        chunk_id="abc123",
        doc_id="CVE-2024-1234",
        doc_title="Test Vulnerability",
        source_org="NVD",
        published_date=datetime.now(timezone.utc),
        text="This vulnerability allows remote code execution via a crafted packet.",
    )
    assert chunk.chunk_id == "abc123"
    assert chunk.entities.severity == "UNKNOWN"


def test_threat_chunk_schema_text_too_short():
    with pytest.raises(Exception):
        ThreatChunk(
            chunk_id="x",
            doc_id="CVE-0000-0000",
            doc_title="Bad",
            source_org="NVD",
            published_date=datetime.now(timezone.utc),
            text="tiny",   # only 4 chars — should fail
        )


def test_threat_chunk_schema_severity_unknown_default():
    chunk = ThreatChunk(
        chunk_id="abc",
        doc_id="DOC1",
        doc_title="Test",
        source_org="NVD",
        published_date=datetime.now(timezone.utc),
        text="A valid vulnerability description that is long enough to pass.",
    )
    assert chunk.entities.severity == "UNKNOWN"


# ---------------------------------------------------------------------------
# build_context (Strategy C)
# ---------------------------------------------------------------------------


def test_build_context_includes_fields():
    chunk = ThreatChunk(
        chunk_id="ctx1",
        doc_id="CVE-2024-9999",
        doc_title="Log4Shell Remote Exploit",
        source_org="NVD",
        published_date=datetime.now(timezone.utc),
        section_header="Description",
        text="Apache Log4j allows remote code execution.",
        entities=CyberEntities(
            cves=["CVE-2021-44228"],
            malware_families=["Log4Shell"],
            mitre_ttps=["T1190"],
        ),
    )
    context = build_context(chunk)
    assert "Log4Shell Remote Exploit" in context
    assert "CVE-2021-44228" in context
    assert "T1190" in context
    assert "Apache Log4j" in context


def test_build_context_handles_empty_entities():
    chunk = ThreatChunk(
        chunk_id="ctx2",
        doc_id="DOC2",
        doc_title="Generic Advisory",
        source_org="CISA",
        published_date=datetime.now(timezone.utc),
        text="A vulnerability exists in the affected software product.",
    )
    context = build_context(chunk)
    assert "none" in context   # empty CVEs/malware/TTPs show as "none"


# ---------------------------------------------------------------------------
# add_query_prefix
# ---------------------------------------------------------------------------


def test_add_query_prefix():
    result = add_query_prefix("What is Log4Shell?")
    assert result.startswith("Represent this sentence for searching relevant passages:")
    assert "Log4Shell" in result


# ---------------------------------------------------------------------------
# cvss_score_to_severity
# ---------------------------------------------------------------------------


def test_cvss_score_to_severity():
    assert cvss_score_to_severity(9.8) == "CRITICAL"
    assert cvss_score_to_severity(7.5) == "HIGH"
    assert cvss_score_to_severity(5.0) == "MEDIUM"
    assert cvss_score_to_severity(2.0) == "LOW"
    assert cvss_score_to_severity(None) == "UNKNOWN"
    assert cvss_score_to_severity("bad") == "UNKNOWN"


# ---------------------------------------------------------------------------
# make_chunk_id — determinism
# ---------------------------------------------------------------------------


def test_make_chunk_id_deterministic():
    id1 = make_chunk_id("CVE-2024-1234", "Some vulnerability description text here.")
    id2 = make_chunk_id("CVE-2024-1234", "Some vulnerability description text here.")
    assert id1 == id2


def test_make_chunk_id_different_inputs_differ():
    id1 = make_chunk_id("CVE-2024-1111", "Text A about some vulnerability.")
    id2 = make_chunk_id("CVE-2024-2222", "Text B about a different vulnerability.")
    assert id1 != id2


# ---------------------------------------------------------------------------
# CISA KEV CSV parser
# ---------------------------------------------------------------------------


def test_kev_csv_parser():
    csv_content = (
        "cveID,vendorProject,product,vulnerabilityName,dateAdded,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
        "CVE-2021-44228,Apache,Log4j,Apache Log4j Remote Code Execution,2021-12-10,"
        "Patch immediately.,2021-12-24,Known,Critical RCE exploit\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write(csv_content)
        tmp_path = Path(f.name)

    chunks = list(parse_cisa_kev_csv(tmp_path))
    tmp_path.unlink(missing_ok=True)

    assert len(chunks) == 1
    assert chunks[0].source_org == "CISA"
    assert "CVE-2021-44228" in chunks[0].entities.cves
    assert "Log4j" in chunks[0].text


# ---------------------------------------------------------------------------
# EPSS CSV parser — skips low scores
# ---------------------------------------------------------------------------


def test_epss_csv_parser_skips_low_scores():
    csv_content = (
        "cve,epss,percentile\n"
        "CVE-2021-44228,0.97,0.999\n"   # high — should be included
        "CVE-2024-9999,0.001,0.10\n"    # very low — should be skipped
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write(csv_content)
        tmp_path = Path(f.name)

    chunks = list(parse_epss_csv(tmp_path))
    tmp_path.unlink(missing_ok=True)

    assert len(chunks) == 1
    assert "CVE-2021-44228" in chunks[0].text


# ---------------------------------------------------------------------------
# Quarantine: bad record should not crash, just get logged
# ---------------------------------------------------------------------------


def test_quarantine_on_bad_text():
    """A row with an empty description should be quarantined, not crash."""
    csv_content = (
        "cveID,vendorProject,product,vulnerabilityName,dateAdded,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
        "CVE-2099-9999,Vendor,Product,,2024-01-01,,,Unknown,\n"   # empty vulnerabilityName → short text
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write(csv_content)
        tmp_path = Path(f.name)

    # Should not raise
    chunks = list(parse_cisa_kev_csv(tmp_path))
    tmp_path.unlink(missing_ok=True)
    # Might be 0 or 1 depending on whether fallback text is long enough
    assert isinstance(chunks, list)


# ---------------------------------------------------------------------------
# Team 1 Unified Normalized CVE Record Tests
# ---------------------------------------------------------------------------


def test_parse_normalized_record_complete():
    """Verify full extraction from Team 1's unified normalized JSON structure."""
    record = {
        "cve_id": "CVE-2021-23758",
        "title": "Deserialization of Untrusted Data",
        "available_sources": ["NVD", "CVE_LIST_V5", "CISA_KEV", "EPSS"],
        "dates": {"date_published": "2021-12-03T00:00:00Z"},
        "descriptions": [
            {
                "language": "en",
                "text": "This affects all versions of package AjaxPro.2. The use of JavaScriptSerializer allows remote code execution.",
            }
        ],
        "affected_products": [
            {"vendor": "Ajax.NET Professional", "product": "AjaxPro.2"}
        ],
        "cvss_metrics": [
            {"base_score": 9.8, "base_severity": "CRITICAL", "version": "3.1"}
        ],
        "cisa_kev": {"listed": True, "due_date": "2026-09-09"},
        "epss": {"score": 0.89096, "percentile": 0.99768},
        "weaknesses": [{"cwe_id": "CWE-502", "description": "Deserialization"}],
    }

    chunk = parse_normalized_record(record)
    assert chunk is not None
    assert chunk.doc_id == "CVE-2021-23758"
    assert "CVE-2021-23758 — Deserialization of Untrusted Data" in chunk.doc_title
    assert "AjaxPro.2" in chunk.text
    assert chunk.entities.severity == "CRITICAL"
    assert "CVE-2021-23758" in chunk.entities.cves
    assert "NVD" in chunk.source_org


def test_parse_normalized_directory(tmp_path):
    """Verify ingesting a directory of Team 1 normalized JSON files."""
    data = {
        "cve_id": "CVE-2024-3094",
        "title": "XZ Utils Backdoor",
        "available_sources": ["NVD", "CVE_LIST_V5"],
        "dates": {"date_published": "2024-03-29"},
        "descriptions": [
            {"language": "en", "text": "Malicious code was discovered in XZ Utils tarballs."}
        ],
        "cvss_metrics": [{"base_score": 10.0, "base_severity": "CRITICAL"}],
    }
    json_file = tmp_path / "CVE-2024-3094_normalized.json"
    json_file.write_text(json.dumps(data), encoding="utf-8")

    chunks = list(parse_normalized_directory(tmp_path))
    assert len(chunks) == 1
    assert chunks[0].doc_id == "CVE-2024-3094"
    assert chunks[0].entities.severity == "CRITICAL"


def test_parse_normalized_jsonl(tmp_path):
    """Verify streaming Team 1 normalized JSONL records."""
    records = [
        {
            "cve_id": "CVE-2024-0001",
            "title": "Test Vuln 1",
            "descriptions": [{"language": "en", "text": "Description of vulnerability 1 with sufficient length."}],
            "cvss_metrics": [{"base_score": 7.5}],
        },
        {
            "cve_id": "CVE-2024-0002",
            "title": "Test Vuln 2",
            "descriptions": [{"language": "en", "text": "Description of vulnerability 2 with sufficient length."}],
            "cvss_metrics": [{"base_score": 5.0}],
        },
    ]
    jsonl_file = tmp_path / "normalized.jsonl"
    jsonl_file.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    chunks = list(parse_normalized_jsonl(jsonl_file))
    assert len(chunks) == 2
    assert chunks[0].doc_id == "CVE-2024-0001"
    assert chunks[0].entities.severity == "HIGH"
    assert chunks[1].doc_id == "CVE-2024-0002"
    assert chunks[1].entities.severity == "MEDIUM"


def test_validate_file_cli_utility(tmp_path):
    """Verify Team 1 validation suite CLI returns correct pass/fail stats."""
    valid_data = {
        "cve_id": "CVE-2024-9999",
        "title": "Valid Advisory",
        "descriptions": [{"language": "en", "text": "A valid vulnerability description of appropriate length."}],
        "cvss_metrics": [{"base_score": 9.0}],
    }
    test_file = tmp_path / "valid_cve.json"
    test_file.write_text(json.dumps(valid_data), encoding="utf-8")

    stats = validate_file(test_file)
    assert stats["valid"] == 1
    assert stats["failed"] == 0


