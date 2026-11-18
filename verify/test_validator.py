from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
import pytest
from threat_retrieval_engine.search_engine.validator import (
    ThreatChunk,
    CyberEntities,
    build_context,
    sanitize_text,
    parse_cisa_kev_csv,
    parse_epss_csv,
)


def test_sanitize_text():
    raw = "Test   string with\x00 null and   extra   spaces\r\nand bad characters \u200b."
    clean = sanitize_text(raw)
    assert "\x00" not in clean
    assert "  " not in clean
    assert "Test string with null and extra spaces" in clean


def test_threat_chunk_build_context():
    chunk = ThreatChunk(
        chunk_id="chk1",
        doc_id="CVE-2021-44228_NVD",
        doc_title="Log4Shell",
        source_org="NVD",
        published_date=datetime.now(timezone.utc),
        text="Log4j vulnerability allowing remote code execution.",
        entities=CyberEntities(
            cves=["CVE-2021-44228"],
            threat_actors=["APT41"],
            malware_families=["Mirai"],
            mitre_ttps=["T1059.001"],
            severity="CRITICAL",
        ),
    )
    ctx = build_context(chunk)
    assert "CVE-2021-44228" in ctx
    assert "Mirai" in ctx
    assert "T1059.001" in ctx
    assert "Log4j" in ctx


def test_kev_and_epss_parsers_severity_unknown():
    # R11: KEV and EPSS have no CVSS vectors, so severity must be UNKNOWN
    with tempfile.TemporaryDirectory() as tmpdir:
        kev_file = Path(tmpdir) / "kev.csv"
        kev_file.write_text(
            "cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
            "CVE-2024-3400,Palo Alto,PAN-OS,Command Injection,2024-04-12,Test KEV desc,Apply updates,2024-04-19,Known,\n",
            encoding="utf-8",
        )
        kev_chunks = list(parse_cisa_kev_csv(kev_file))
        assert len(kev_chunks) == 1
        assert kev_chunks[0].entities.severity == "UNKNOWN"

        epss_file = Path(tmpdir) / "epss.csv"
        epss_file.write_text(
            "#model_date:2024-04-15\ncve,epss,percentile\nCVE-2024-3400,0.85000,0.98000\n",
            encoding="utf-8",
        )
        epss_chunks = list(parse_epss_csv(epss_file))
        assert len(epss_chunks) == 1
        assert epss_chunks[0].entities.severity == "UNKNOWN"
